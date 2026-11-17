package state

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationUnusedCertificateWorkRetiresWithLastConsumer(t *testing.T) {
	f := newServicePublicationFixture(t)
	work := createPlanIssuanceWork(t, f.database, f.now, f.run, f.prepared.CertificatePlan, false, nil)
	claimed, found, err := f.database.ClaimACMEOrderWork(t.Context(), "in-flight", f.now, time.Minute)
	if err != nil || !found || claimed.ID != work.ID {
		t.Fatal("could not claim original issuance", found, err)
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	var state, authorization string
	var owner string
	var expires time.Time
	var revision int64
	if err := f.database.pool.QueryRow(t.Context(), `SELECT issuance.state,authz.state,
		issuance.work_owner,issuance.work_expires_at,issuance.order_revision
		FROM control.acme_orders issuance JOIN control.acme_authorizations authz ON authz.order_id=issuance.id
		WHERE issuance.id=$1`, work.ID).Scan(&state, &authorization, &owner, &expires, &revision); err != nil {
		t.Fatal(err)
	}
	if state != "canceled" || authorization != "cleaning" {
		t.Fatal("last consumer left unused issuance or challenge presentation active", state, authorization)
	}
	if owner != claimed.WorkerID || !expires.Equal(claimed.WorkExpiresAt) || uint64(revision) <= claimed.OrderRevision {
		t.Fatal("retirement replaced the original work fence or failed to invalidate its revision", owner, expires, revision)
	}
	if _, err := f.database.SaveACMEOrderWork(t.Context(), claimed, f.now); !errors.Is(err, ErrACMEWorkStale) {
		t.Fatal("retired worker could resume issuance", err)
	}
	if _, found, err := f.database.ClaimACMEOrderWork(t.Context(), "too-early-cleanup", f.now, time.Minute); err != nil || found {
		t.Fatal("cleanup overtook the original in-flight worker deadline", found, err)
	}
	at := f.now.Add(time.Minute)
	cleanup, found, err := f.database.ClaimACMEOrderWork(t.Context(), "cleanup", at, time.Minute)
	if err != nil || !found || cleanup.ID != work.ID || cleanup.State != "canceled" ||
		len(cleanup.Authorizations) != 1 || cleanup.Authorizations[0].State != "cleaning" {
		t.Fatal("retirement lost durable DNS cleanup", found, err)
	}
	challenge, err := f.database.GetDNSChallengeContextForSubject(t.Context(), cleanup.Subject, cleanup.Authorizations[0].ID)
	if err != nil || len(challenge.Presentations) != 1 || challenge.Presentations[0].Active {
		t.Fatal("retired challenge remained desired", err)
	}
	cleanup.Authorizations[0].State = "complete"
	cleanup.Authorizations[0].CleanupCompletedAt = &at
	cleanup.Authorizations[0].AvailableAt, cleanup.AvailableAt = at, at
	if _, err := f.database.SaveACMEOrderWork(t.Context(), cleanup, at); err != nil {
		t.Fatal(err)
	}
	if _, found, err := f.database.ClaimACMEOrderWork(t.Context(), "after-cleanup", at.Add(time.Second), time.Minute); err != nil || found {
		t.Fatal("retired issuance performed more work after cleanup", found, err)
	}
}

func TestIntegrationCertificateWorkRetainsAuthorizedSiblingAndRestart(t *testing.T) {
	e := newRestoredCertificateEnvironment(t, DomainKindManaged, naming.ManagedURLModeGenerated, false)
	_, replica := e.deployment(t, "certificate-consumers", true, map[string]ProjectServiceConfiguration{
		"first":  {Protocol: "http", Target: "localhost:3000", Public: new(true)},
		"second": {Protocol: "http", Target: "localhost:3001", Public: new(true)},
	})
	first := e.startAssigned(t, replica, "first")
	second := e.startAssigned(t, replica, "second")
	work := createPlanIssuanceWork(t, e.database, e.now, first.run, first.prepared.CertificatePlan, false, nil)
	if err := e.database.CloseServiceRun(t.Context(), first.service.ID, first.run.RunID, first.run.Token, e.now); err != nil {
		t.Fatal(err)
	}
	retained, err := e.database.GetServiceCertificateIssuance(t.Context(), second.service.ID, second.run.RunID, second.run.Token, work.ID, e.now)
	if err != nil || retained.State != "authorizing" {
		t.Fatal("closing the original run canceled a still-authorized sibling's work", retained.State, err)
	}
	original := first.run
	first.start(t, "authorized-restart", e.now)
	reused, err := e.database.CreateServiceCertificateIssuance(t.Context(), first.service.ID, first.run.RunID, first.run.Token,
		work.Account.DirectoryURL, "restart", first.run.RunNumber, work.CSRDER, e.now)
	if err != nil || reused.ID != work.ID || reused.NewOrder || reused.ServiceRunID != original.RunID {
		t.Fatal("authorized restart lost the shared unfinished issuance", reused.ID, err)
	}
	if err := e.database.CloseServiceRun(t.Context(), second.service.ID, second.run.RunID, second.run.Token, e.now); err != nil {
		t.Fatal(err)
	}
	if retained, err = e.database.GetServiceCertificateIssuance(t.Context(), first.service.ID, first.run.RunID, first.run.Token, work.ID, e.now); err != nil || retained.State != "authorizing" {
		t.Fatal("closing a sibling canceled the authorized replacement", retained.State, err)
	}
	if err := e.database.CloseServiceRun(t.Context(), first.service.ID, first.run.RunID, first.run.Token, e.now); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := e.database.pool.QueryRow(t.Context(), `SELECT state FROM control.acme_orders WHERE id=$1`, work.ID).Scan(&state); err != nil || state != "canceled" {
		t.Fatal("last shared consumer did not retire issuance", state, err)
	}
}

func TestIntegrationCertificateWorkUsesServingAuthorityNotPublisherLiveness(t *testing.T) {
	f := newServicePublicationFixture(t)
	until := f.now.Add(10 * time.Second)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs
		SET publisher_expires_at=$2,serving_until=$3 WHERE id=$1`, f.run.RunID, f.now.Add(time.Second), until); err != nil {
		t.Fatal(err)
	}
	work := createPlanIssuanceWork(t, f.database, f.now, f.run, f.prepared.CertificatePlan, false, nil)
	at := f.now.Add(2 * time.Second)
	current, found, err := f.database.ClaimACMEOrderWork(t.Context(), "after-liveness", at, time.Second)
	if err != nil || !found || current.ID != work.ID || current.State != "authorizing" {
		t.Fatal("short publisher liveness revoked current certificate work", current.State, found, err)
	}
	if _, err := f.database.SaveACMEOrderWork(t.Context(), current, at); err != nil {
		t.Fatal(err)
	}
	expired, found, err := f.database.ClaimACMEOrderWork(t.Context(), "at-authority-expiry", until, time.Second)
	if err != nil || !found || expired.State != "canceled" || expired.Authorizations[0].State != "cleaning" {
		t.Fatal("work claim advanced issuance after actual consumer expiry", expired.State, found, err)
	}
	var closed bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT closed_at IS NOT NULL FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&closed); err != nil || closed {
		t.Fatal("proof depended on prior run maintenance rather than current authority", closed, err)
	}
}

func TestIntegrationCertificateRetirementSharesRunClosureTransaction(t *testing.T) {
	f := newServicePublicationFixture(t)
	work := createPlanIssuanceWork(t, f.database, f.now, f.run, f.prepared.CertificatePlan, false, nil)
	before := certificateCreationSnapshot(t, f)
	beforeAuthorizations, err := controlstatedb.New(f.database.pool).ListACMEOrderAuthorizations(t.Context(), work.ID)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if err := lockServiceAdmission(t.Context(), tx, f.service.ID); err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(tx)
	run, err := q.LockServiceRun(t.Context(), controlstatedb.LockServiceRunParams{ID: f.run.RunID, ServiceID: f.service.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := closeServiceRun(t.Context(), q, run, f.now); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := tx.QueryRow(t.Context(), `SELECT state FROM control.acme_orders WHERE id=$1`, work.ID).Scan(&state); err != nil || state != "canceled" {
		t.Fatal("transaction did not actually stage certificate retirement", state, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if certificateCreationSnapshot(t, f) != before {
		t.Fatal("rolled-back run closure retained certificate or audit changes")
	}
	afterAuthorizations, err := controlstatedb.New(f.database.pool).ListACMEOrderAuthorizations(t.Context(), work.ID)
	if err != nil || !reflect.DeepEqual(beforeAuthorizations, afterAuthorizations) {
		t.Fatal("rolled-back retirement retained challenge cleanup changes", err)
	}
	current, err := f.database.GetServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, f.run.Token, work.ID, f.now)
	if err != nil || current.State != "authorizing" {
		t.Fatal("rollback lost the current consumer's usable issuance", current.State, err)
	}
}

func TestIntegrationCertificateWorkRetainsAtomicAuthorizedRestart(t *testing.T) {
	f := newServicePublicationFixture(t)
	work := createPlanIssuanceWork(t, f.database, f.now, f.run, f.prepared.CertificatePlan, false, nil)
	// a replacement can start after publisher liveness ends while the old run
	// still has serving authority. the transaction never publishes a consumer gap.
	at := f.now.Add(time.Second)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs
		SET publisher_expires_at=$2 WHERE id=$1`, f.run.RunID, at); err != nil {
		t.Fatal(err)
	}
	f.start(t, "atomic-authorized-restart", at)
	reused, err := f.database.CreateServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, f.run.Token,
		work.Account.DirectoryURL, "atomic-restart", f.run.RunNumber, work.CSRDER, at)
	if err != nil || reused.ID != work.ID || reused.NewOrder || reused.State != ACMEOrderAuthorizing {
		t.Fatal("atomic authorized restart retired the same captured plan", reused.State, reused.ID, err)
	}
}

func TestIntegrationCertificateWorkClaimRechecksConsumerPermission(t *testing.T) {
	for _, boundary := range []string{"revoked-grant", "expired-grant", "revoked-publisher", "disabled-service", "released-domain"} {
		t.Run(boundary, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			work := createPlanIssuanceWork(t, f.database, f.now, f.run, f.prepared.CertificatePlan, false, nil)
			at := f.now.Add(time.Second)
			// bypass the mutation's normal run closure deliberately: claim must
			// check current authority even before maintenance settles this row.
			var err error
			switch boundary {
			case "revoked-grant":
				_, err = f.database.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, f.publisher.GrantID, at)
			case "expired-grant":
				_, err = f.database.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, f.publisher.GrantID, at)
			case "revoked-publisher":
				_, err = f.database.pool.Exec(t.Context(), `UPDATE control.publisher_identities SET revoked_at=$2 WHERE id=$1`, f.publisher.ID, at)
			case "disabled-service":
				_, err = f.database.pool.Exec(t.Context(), `UPDATE control.services SET enabled=false WHERE id=$1`, f.service.ID)
			case "released-domain":
				_, err = f.database.pool.Exec(t.Context(), `UPDATE control.domains SET state='released',released_at=$2
					WHERE id=(SELECT domain_id FROM control.services WHERE id=$1)`, f.service.ID, at)
			}
			if err != nil {
				t.Fatal(err)
			}
			current, found, err := f.database.ClaimACMEOrderWork(t.Context(), "current-permission", at, time.Minute)
			if err != nil || !found || current.ID != work.ID || current.State != ACMEOrderCanceled ||
				len(current.Authorizations) != 1 || current.Authorizations[0].State != ACMEAuthorizationCleaning {
				t.Fatal("stale consumer permission advanced issuance or lost cleanup", current.State, found, err)
			}
		})
	}
}

func TestIntegrationCertificateConcurrentFinalConsumersRetire(t *testing.T) {
	e := newRestoredCertificateEnvironment(t, DomainKindManaged, naming.ManagedURLModeGenerated, false)
	_, replica := e.deployment(t, "concurrent-certificate-consumers", true, map[string]ProjectServiceConfiguration{
		"first":  {Protocol: "http", Target: "localhost:3000", Public: new(true)},
		"second": {Protocol: "http", Target: "localhost:3001", Public: new(true)},
	})
	first := e.startAssigned(t, replica, "first")
	second := e.startAssigned(t, replica, "second")
	work := createPlanIssuanceWork(t, e.database, e.now, first.run, first.prepared.CertificatePlan, false, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	closing, err := e.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, closing)
	if err := lockServiceAdmission(ctx, closing, first.service.ID); err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(closing)
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: first.run.RunID, ServiceID: first.service.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := closeServiceRun(ctx, q, run, e.now); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	closed := make(chan error, 1)
	workers.Go(func() {
		closed <- e.database.CloseServiceRun(ctx, second.service.ID, second.run.RunID, second.run.Token, e.now)
	})
	pid := waitForPostgresBlock(t, ctx, e.database, int32(closing.Conn().PgConn().PID()), closed)
	var query string
	if err := e.database.pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&query); err != nil {
		t.Fatal(err)
	}
	// the current team audit lock serializes these public closures before
	// certificate retirement. an order-row wait is also safe if that changes.
	if !strings.Contains(query, "CloseServiceRun") && !strings.Contains(query, "LockServiceCertificateOrdersForConsumer") {
		t.Fatal("closure blocked at an unexpected dependency", query)
	}
	t.Log("second closure waits before its fresh consumer snapshot:", strings.Join(strings.Fields(query), " "))
	if err := closing.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, closed); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := e.database.pool.QueryRow(ctx, `SELECT state FROM control.acme_orders WHERE id=$1`, work.ID).Scan(&state); err != nil || state != "canceled" {
		t.Fatal("concurrent final closes both retained the unused order", state, err)
	}
}

func TestIntegrationCertificateRetirementRetainsFailedPresentationCleanup(t *testing.T) {
	f := newServicePublicationFixture(t)
	work := createPlanIssuanceWork(t, f.database, f.now, f.run, f.prepared.CertificatePlan, false, func(work *ACMEOrderWork) {
		work.Authorizations[0].State = ACMEAuthorizationFailed
		work.Authorizations[0].PresentedAt = &f.now
	})
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	cleanup, found, err := f.database.ClaimACMEOrderWork(t.Context(), "failed-presentation-cleanup", f.now.Add(time.Second), time.Minute)
	if err != nil || !found || cleanup.ID != work.ID || cleanup.State != ACMEOrderCanceled ||
		len(cleanup.Authorizations) != 1 || cleanup.Authorizations[0].State != ACMEAuthorizationCleaning ||
		cleanup.Authorizations[0].CleanupCompletedAt != nil {
		t.Fatal("failed challenge status discarded an actual DNS presentation", cleanup.State, found, err)
	}
}
