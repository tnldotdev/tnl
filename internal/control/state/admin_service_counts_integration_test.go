package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func adminPreparedRun(t *testing.T, d *Database, service ServiceRecord, actor string, now time.Time) (PublisherIdentity, ServiceRunPreparation) {
	t.Helper()
	enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: service.TeamID, ActingIdentityID: actor},
		PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, "admin-counts", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	return publisher, prepared
}

func assertAdminServiceCounts(t *testing.T, d *Database, at time.Time, enabled, suspended, starting, ready int64) {
	t.Helper()
	counts, err := d.AdminRuntimeCounts(t.Context(), at)
	if err != nil {
		t.Fatal(err)
	}
	if counts.EnabledServices != enabled || counts.SuspendedServices != suspended ||
		counts.StartingServiceRuns != starting || counts.ReadyServiceRuns != ready {
		t.Fatalf("canonical admin counts = %+v; want %d enabled, %d suspended, %d starting, %d ready", counts, enabled, suspended, starting, ready)
	}
}

func TestIntegrationAdminRuntimeCountsUseCanonicalServicesAndRuns(t *testing.T) {
	native := newConnectorPairFixture(t)
	d, now := native.d, native.now
	f := serviceHTTPFixture{database: d, now: now, project: appliedProjectRequest(t, d, now), leases: native.leases}
	create := func(name string, public bool) ServiceRecord {
		t.Helper()
		service, err := d.CreateServiceAt(t.Context(), f.project.TeamID, f.project.ActorID, name, name, ServicePlacement{}, now,
			ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000", Public: &public})
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	http := create("http", true)
	httpRun := f.publish(t, http)
	starting := create("starting", false)
	publisher, prepared := adminPreparedRun(t, d, starting, f.project.ActorID, now)
	startingRun, err := d.StartServiceRun(t.Context(), starting.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	pending := create("prepared", false)
	adminPreparedRun(t, d, pending, f.project.ActorID, now)
	suspended := create("suspended", false)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.services SET enabled=false WHERE id=$1`, suspended.ID); err != nil {
		t.Fatal(err)
	}
	deleted := create("deleted", false)
	if err := d.DeleteService(t.Context(), deleted.ID, f.project.ActorID, now); err != nil {
		t.Fatal(err)
	}
	expired := create("expired", false)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.services SET expires_at=$2 WHERE id=$1`, expired.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	at := now.Add(2 * time.Second)
	// the fixture also contains the retained public URL and publish run. neither
	// is a canonical service, and a prepared run is not a starting publication.
	assertAdminServiceCounts(t, d, now, 5, 1, 1, 2)
	assertAdminServiceCounts(t, d, at, 4, 1, 1, 2)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.service_runs SET healthy=false WHERE id=$1`, native.run.RunID); err != nil {
		t.Fatal(err)
	}
	assertAdminServiceCounts(t, d, at, 4, 1, 1, 1)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.service_runs SET healthy=true WHERE id=$1`, native.run.RunID); err != nil {
		t.Fatal(err)
	}
	// exact-service grants retain their existing retired-key recovery rule.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.publisher_identity_keys SET retired_at=$2
	    WHERE id=(SELECT publisher_key_id FROM control.service_runs WHERE id=$1)`, native.run.RunID, now); err != nil {
		t.Fatal(err)
	}
	assertAdminServiceCounts(t, d, at, 4, 1, 1, 2)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET revoked_at=$2
	    WHERE id=(SELECT publisher_grant_id FROM control.service_runs WHERE id=$1)`, native.run.RunID, now); err != nil {
		t.Fatal(err)
	}
	assertAdminServiceCounts(t, d, at, 4, 1, 1, 1)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.service_runs SET certificate_expires_at=$2 WHERE id=$1`, httpRun.RunID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	assertAdminServiceCounts(t, d, at, 4, 1, 1, 0)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`, startingRun.RunID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	assertAdminServiceCounts(t, d, at, 4, 1, 0, 0)
}

func TestIntegrationAdminRuntimeCountsRequireCurrentNamespaceSigningKey(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	actor := oidcRouteRequest(t, d, now)
	service, publisher := managementAllocation(t, d, actor.TeamID, actor.ActingIdentityID, now)
	prepared, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, "namespace-count", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, now); err != nil {
		t.Fatal(err)
	}
	assertAdminServiceCounts(t, d, now, 1, 0, 1, 0)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`, publisher.KeyID, now); err != nil {
		t.Fatal(err)
	}
	assertAdminServiceCounts(t, d, now, 1, 0, 0, 0)
}

func TestIntegrationAdminRuntimeCountsIncludeGuestServingDeadline(t *testing.T) {
	f, guest := guestAuthorityFixture(t, true)
	assertAdminServiceCounts(t, f.database, f.now, 1, 0, 0, 1)
	trial := f.stored(t)
	if !trial.ReadyDeadline.Valid {
		t.Fatal("guest fixture has no serving deadline")
	}
	// retain a later publisher lease to isolate the fixed guest deadline rather
	// than letting ordinary heartbeat expiry explain the count.
	if _, err := f.database.pool.Exec(f.ctx, `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`,
		f.run.RunID, trial.ReadyDeadline.Time.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	assertAdminServiceCounts(t, f.database, trial.ReadyDeadline.Time, 1, 0, 0, 0)
	assertAdminServiceCounts(t, f.database, guest.ExpiresAt, 0, 0, 0, 0)
}

func TestIntegrationAdminRuntimeCountsDoNotLockServices(t *testing.T) {
	f := newConnectorPairFixture(t)
	tx, err := f.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if _, err := controlstatedb.New(tx).LockService(t.Context(), f.run.ServiceID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	counts, err := f.d.AdminRuntimeCounts(ctx, f.now)
	if err != nil || counts.EnabledServices != 1 || counts.ReadyServiceRuns != 1 {
		t.Fatal("admin observations waited for a service mutation lock", err)
	}
}
