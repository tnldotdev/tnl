package state

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func assertDNSChallengeSubjectBinding(t *testing.T, database *Database, expected CertificateSubject, challenge DNSChallengeContext) {
	t.Helper()
	if challenge.Subject != expected {
		t.Fatalf("DNS challenge subject = %#v, want %#v", challenge.Subject, expected)
	}
	typed, err := database.GetDNSChallengeContextForSubject(t.Context(), expected, challenge.AuthorizationID)
	if err != nil || !reflect.DeepEqual(typed, challenge) {
		t.Fatalf("typed DNS challenge lookup lost its stored subject: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*CertificateSubject)
	}{
		{"kind", func(s *CertificateSubject) { s.Kind = "invalid" }},
		{"owner", func(s *CertificateSubject) { s.ID += "-other" }},
		{"run", func(s *CertificateSubject) { s.RunID += "-other" }},
		{"run number", func(s *CertificateSubject) { s.RunNumber++ }},
	} {
		crossed := expected
		tc.change(&crossed)
		if _, err := database.GetDNSChallengeContextForSubject(t.Context(), crossed, challenge.AuthorizationID); !errors.Is(err, ErrDNSChallengeNotFound) {
			t.Fatalf("crossed DNS challenge %s accepted: %v", tc.name, err)
		}
	}
}

func TestIntegrationRunAliasDNSChallengesUseCapturedCertificateNames(t *testing.T) {
	f, parent, declaration := newRunAliasServiceFixture(t)
	f.run = f.publish(t, f.service)
	var plan CertificatePlan
	if err := f.database.pool.QueryRow(t.Context(), `SELECT certificate_cache_key,certificate_scope,certificate_identifiers
	    FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&plan.CacheKey, &plan.Scope, &plan.Identifiers); err != nil {
		t.Fatal(err)
	}
	plan.ChallengeMethod = "dns-01"
	if len(plan.Identifiers) != 2 || !slices.Contains(plan.Identifiers, f.run.RunHostname) ||
		!slices.Contains(plan.Identifiers, f.service.Endpoint.Hostname) {
		t.Fatal("fixture did not capture the two exact certificate names", plan)
	}
	work := createPlanIssuanceWork(t, f.database, f.now, f.run, plan, false, nil)
	for _, authorization := range work.Authorizations {
		challenge, err := f.database.GetDNSChallengeContextForSubject(t.Context(), work.Subject, authorization.ID)
		if err != nil || challenge.Identifier != authorization.Identifier {
			t.Fatal("approved certificate name lost DNS challenge authority", authorization.Identifier, err)
		}
		assertDNSChallengeSubjectBinding(t, f.database, work.Subject, challenge)
	}
	// cleanup uses the order's captured names even after the endpoint setting
	// changes. current configuration must not strand an approved TXT record.
	declaration.RunAliasParent = ""
	if _, err := f.database.ConfigureService(t.Context(), f.service.ID, f.project.ActorID, f.service.ServiceMetadata,
		&declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	for _, authorization := range work.Authorizations {
		if _, err := f.database.GetDNSChallengeContextForSubject(t.Context(), work.Subject, authorization.ID); err != nil {
			t.Fatal("withdrawal stranded captured DNS cleanup authority", err)
		}
	}
	authorization := work.Authorizations[0]
	for _, identifier := range []string{parent, "*." + parent, "unapproved." + parent, "*." + f.service.Endpoint.Hostname} {
		if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.acme_authorizations SET identifier=$2 WHERE id=$1`,
			authorization.ID, identifier); err != nil {
			t.Fatal(err)
		}
		if _, err := f.database.GetDNSChallengeContextForSubject(t.Context(), work.Subject, authorization.ID); err == nil {
			t.Fatal("DNS challenge escaped its captured certificate names", identifier)
		}
	}
}

func TestIntegrationDNSDedicatedWaitExcludedFromPoolActivity(t *testing.T) {
	database, databaseURL, _ := newControlStateIntegrationDatabaseWithURL(t, "dns_activity")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	observer, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	clock, err := observer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, clock)
	if _, err := clock.Exec(ctx, `SELECT allowed FROM control.maintenance_controls WHERE operation = 'certificate_issuance' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	entered, release := make(chan struct{}), make(chan struct{})
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	var callbacks atomic.Int32
	const recordName = "_acme-challenge.activity.example.test"
	workers.Go(func() {
		firstDone <- database.WithDNSRecordLock(ctx, recordName, func() error {
			callbacks.Add(1)
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var holderPID int32
	if err := observer.QueryRow(ctx, `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&holderPID); err != nil {
		t.Fatal(err)
	}
	workers.Go(func() {
		secondDone <- database.WithDNSRecordLock(ctx, recordName, func() error {
			callbacks.Add(1)
			return database.Health(ctx)
		})
	})
	waitForPostgresBlock(t, ctx, database, holderPID, secondDone)
	poolDone := make(chan error, 1)
	workers.Go(func() {
		_, err := controlstatedb.New(database.pool).LockCertificateIssuanceControl(ctx)
		poolDone <- err
	})
	waitForPostgresBlock(t, ctx, database, int32(observer.PgConn().PID()), poolDone)
	active, truncated := database.activity.snapshot(time.Now())
	if truncated || len(active) != 1 || active[0].Operation != "LockCertificateIssuanceControl" {
		t.Fatalf("request-pool activity includes dedicated DNS wait: %+v, truncated=%t", active, truncated)
	}
	if callbacks.Load() != 1 {
		t.Fatal("DNS waiter bypassed advisory lock")
	}
	if err := clock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, poolDone); err != nil {
		t.Fatal(err)
	}
	if active, _ := database.activity.snapshot(time.Now()); len(active) != 0 {
		t.Fatalf("dedicated wait remains in pool activity: %+v", active)
	}
	close(release)
	for _, done := range []chan error{firstDone, secondDone} {
		if err := awaitIntegrationResult(t, ctx, done); err != nil {
			t.Fatal(err)
		}
	}
	if callbacks.Load() != 2 {
		t.Fatal("DNS callback did not resume")
	}
	var remaining int
	if err := observer.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("leaked DNS locks = %d, %v", remaining, err)
	}
}
