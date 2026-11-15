package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type poolRunFixture struct {
	publisher PublisherIdentity
	prepared  ServiceRunPreparation
	run       ServiceRunState
}

func readyPoolServiceRun(t *testing.T, d *Database, run ServiceRunState, leases map[string]RelayLease, now time.Time) {
	t.Helper()
	for _, slot := range run.Connections {
		lease := leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
}

func poolReviewFixtures(t *testing.T) (servicePublicationFixture, [2]poolRunFixture) {
	t.Helper()
	f := newServicePublicationFixture(t)
	d, now := f.database, f.now
	meta := f.service.ServiceMetadata
	meta.PublisherPool = true
	updated, err := d.ConfigureService(t.Context(), f.service.ID, f.publisher.CreatorID, meta, nil, ServiceUpdateConditions{}, now)
	if err != nil || !updated.PublisherPool {
		t.Fatal("explicit authorized pool configuration failed", err)
	}
	f.service = updated
	installPrivateTestCertificate(t, d, f.prepared, f.run, now)
	readyPoolServiceRun(t, d, f.run, f.leases, now)

	runs := [2]poolRunFixture{{publisher: f.publisher, prepared: f.prepared, run: f.run}}
	for index := 1; index < 2; index++ {
		e := publisherEnrollment(t, d, serviceTestAuthority{TeamID: f.service.TeamID, ActingIdentityID: f.publisher.CreatorID}, PublisherScope{TeamID: f.service.TeamID, Kind: "service", ServiceID: f.service.ID}, now)
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := d.PrepareServiceRun(t.Context(), f.service.ID, publisher, "pool-review-"+string(rune('0'+index)), now, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(t.Context(), f.service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
		if err != nil {
			t.Fatal(err)
		}
		installPrivateTestCertificate(t, d, prepared, run, now)
		readyPoolServiceRun(t, d, run, f.leases, now)
		runs[index] = poolRunFixture{publisher: publisher, prepared: prepared, run: run}
	}
	return f, runs
}

func TestIntegrationSharedPublisherStorageAndPoolAuthorizationReview(t *testing.T) {
	f, runs := poolReviewFixtures(t)
	d, now := f.database, f.now
	for _, relation := range []struct{ name, kind string }{{"service_connection_slots", "r"}, {"service_runs", "r"}} {
		var kind string
		if err := d.pool.QueryRow(t.Context(), `SELECT relkind::text FROM pg_class WHERE oid=to_regclass('control.'||$1)`, relation.name).Scan(&kind); err != nil || kind != relation.kind {
			t.Fatalf("%s is not the canonical storage relation: %q %v", relation.name, kind, err)
		}
	}
	var retired int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_class WHERE oid=ANY(ARRAY[
		to_regclass('control.publisher_service_connection_slots'),
		to_regclass('control.publish_run_connection_slots'),
		to_regclass('control.publisher_service_runs')])`).Scan(&retired); err != nil || retired != 0 {
		t.Fatalf("retired slot or run relations remain: count=%d error=%v", retired, err)
	}
	var mirrors int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_proc WHERE proname IN('project_publisher_service_run','bind_public_publisher_runtime')`).Scan(&mirrors); err != nil || mirrors != 0 {
		t.Fatal("runtime mirror triggers remain", err)
	}
	// a pooled service must not let the same publisher start a second concurrent run.
	duplicate, err := d.PrepareServiceRun(t.Context(), f.service.ID, runs[0].publisher, "duplicate", now, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if !errors.Is(err, ErrServiceConflict) {
		if err == nil {
			_, err = d.StartServiceRun(t.Context(), f.service.ID, duplicate.RunID, duplicate.RunNumber, runs[0].publisher, now)
		}
		if !errors.Is(err, ErrServiceConflict) {
			t.Fatalf("same publisher joined a pool twice: %v", err)
		}
	}
	_, err = d.pool.Exec(t.Context(), `UPDATE control.service_runs SET publisher_identity_id=$2,publisher_grant_id=$3 WHERE id=$1`, runs[1].run.RunID, runs[0].publisher.ID, runs[0].publisher.GrantID)
	var violation *pgconn.PgError
	if !errors.As(err, &violation) {
		t.Fatalf("one-active-run invariant is not enforced: %v", err)
	}

	_ = registerTestIngress(t, d, now)
	if err = d.CloseServiceRun(t.Context(), f.service.ID, runs[0].run.RunID, runs[0].run.Token, now); err != nil {
		t.Fatal(err)
	}
	var closedOpen, siblingOpen int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_connection_slots WHERE service_run_id=$1 AND session_open`, runs[0].run.RunID).Scan(&closedOpen); err != nil || closedOpen != 0 {
		t.Fatalf("closed run retained open slots: %d %v", closedOpen, err)
	}
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_connection_slots WHERE service_run_id=$1 AND session_open`, runs[1].run.RunID).Scan(&siblingOpen); err != nil || siblingOpen != 2 {
		t.Fatalf("run eviction tombstoned a sibling: open=%d %v", siblingOpen, err)
	}
	var live int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_connection_slots WHERE service_id=$1 AND session_open`, f.service.ID).Scan(&live); err != nil || live != 2 {
		t.Fatalf("shared slot parent cascade did not preserve sibling: %d %v", live, err)
	}

	private, err := d.CreateServiceAt(t.Context(), f.service.TeamID, f.publisher.CreatorID, "private", "private", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	meta := private.ServiceMetadata
	meta.PublisherPool = true
	updated, err := d.ConfigureService(t.Context(), private.ID, f.publisher.CreatorID, meta, nil, ServiceUpdateConditions{}, now)
	if err != nil || !updated.PublisherPool || updated.TrustRevision != private.TrustRevision || updated.EndpointRevision != private.EndpointRevision {
		t.Fatal("operator pool edit changed trust or endpoint revision", err)
	}
	meta = updated.ServiceMetadata
	meta.Protocol = "postgres"
	trusted, err := d.ConfigureService(t.Context(), private.ID, f.publisher.CreatorID, meta, nil, ServiceUpdateConditions{}, now)
	if err != nil || trusted.TrustRevision != updated.TrustRevision+1 {
		t.Fatal("protocol update did not advance target trust", err)
	}
	if _, err = d.ConfigureService(t.Context(), private.ID, f.publisher.CreatorID, private.ServiceMetadata, nil, ServiceUpdateConditions{}, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("stale trust revision silently reverted approved protocol and pool: %v", err)
	}
	if saved, err := d.GetService(t.Context(), private.ID, f.publisher.CreatorID); err != nil || !saved.PublisherPool || saved.Protocol != "postgres" || saved.TrustRevision != trusted.TrustRevision {
		t.Fatal("stale configuration changed the saved service", err)
	}
}

func TestIntegrationPublisherCertificateCacheAndDNSRetryWindow(t *testing.T) {
	f, runs := poolReviewFixtures(t)
	d, now := f.database, f.now

	// pooled publishers must not share certificate issuance/CSR identity.
	var issuanceA, issuanceB string
	if err := d.pool.QueryRow(t.Context(), `SELECT certificate_issuance_id FROM control.service_runs WHERE id=$1`, runs[0].run.RunID).Scan(&issuanceA); err != nil {
		t.Fatal(err)
	}
	if err := d.pool.QueryRow(t.Context(), `SELECT certificate_issuance_id FROM control.service_runs WHERE id=$1`, runs[1].run.RunID).Scan(&issuanceB); err != nil {
		t.Fatal(err)
	}
	if issuanceA == "" || issuanceA == issuanceB {
		t.Fatal("pooled publishers shared or lost certificate issuance", issuanceA, issuanceB)
	}

	// restart the same publisher: its new run receives its own certificate installation.
	if err := d.CloseServiceRun(t.Context(), f.service.ID, runs[0].run.RunID, runs[0].run.Token, now); err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(t.Context(), f.service.ID, runs[0].publisher, "restart", now, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := d.StartServiceRun(t.Context(), f.service.ID, prepared.RunID, prepared.RunNumber, runs[0].publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prepared, restarted, now)
	var restartedIssuance string
	if err := d.pool.QueryRow(t.Context(), `SELECT certificate_issuance_id FROM control.service_runs WHERE id=$1`, restarted.RunID).Scan(&restartedIssuance); err != nil || restartedIssuance == "" {
		t.Fatal("restarted publisher lost installed certificate", err)
	}

	// a newer issuance wins; an older issuance id must not replace it.
	newer := createPlanIssuanceWork(t, d, now.Add(time.Second), restarted, prepared.CertificatePlan, true, nil)
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.service_runs SET certificate_issuance_id=$2 WHERE id=$1`, restarted.RunID, newer.ID); err != nil {
		t.Fatal(err)
	}
	// simulate an older/late installation attempt writing the previous issuance id.
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.service_runs SET certificate_issuance_id=$2 WHERE id=$1 AND certificate_issuance_id=$3`, restarted.RunID, restartedIssuance, restartedIssuance); err != nil {
		t.Fatal(err)
	}
	var actualIssuance string
	if err := d.pool.QueryRow(t.Context(), `SELECT certificate_issuance_id FROM control.service_runs WHERE id=$1`, restarted.RunID).Scan(&actualIssuance); err != nil || actualIssuance != newer.ID {
		t.Fatal("old retry changed installed certificate", actualIssuance, err)
	}

	// CA/DNS retry window: authorizing work is not claimable before retry_not_before.
	readyPoolServiceRun(t, d, restarted, f.leases, now)
	work := createPlanIssuanceWork(t, d, now.Add(2*time.Second), restarted, prepared.CertificatePlan, false, nil)
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.acme_orders SET state='authorizing',attempts=3,retry_not_before=$2,available_at=$2,last_error='CA retry window' WHERE id=$1`, work.ID, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if claimed, found, err := d.ClaimACMEOrderWork(t.Context(), "rate-window-review", now.Add(4*time.Second), time.Minute); err != nil || found {
		if err == nil {
			t.Fatalf("CA work was claimed before retry window: %s", claimed.ID)
		}
		t.Fatal(err)
	}
	var attempts int
	var availableAt time.Time
	if err := d.pool.QueryRow(t.Context(), `SELECT attempts, available_at FROM control.acme_orders WHERE id=$1`, work.ID).Scan(&attempts, &availableAt); err != nil || attempts != 3 || !availableAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("acknowledgment bypassed CA retry window: attempts=%d available=%v err=%v", attempts, availableAt, err)
	}
}
