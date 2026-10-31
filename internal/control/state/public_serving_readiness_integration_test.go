package state

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
)

func prepareServingPublisher(t *testing.T, f publishRunFixture) {
	t.Helper()
	work := createPlanIssuanceWork(t, f.database, f.now, f.authentication(), f.certificatePlan(), true, nil)
	if _, err := f.database.MarkPublicURLCertificateInstalled(t.Context(), f.authentication(), work.ID, *work.NotAfter, f.now); err != nil {
		t.Fatal(err)
	}
	for slot := range f.setup.PublisherConnections {
		claimTestConnection(t, f, slot, f.now)
	}
}

func servingPreparationPending(t *testing.T, f publishRunFixture, now time.Time) {
	t.Helper()
	if _, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), now); !errors.Is(err, ErrPublishRunNotReady) {
		t.Fatalf("preparation pending: %v", err)
	}
	var ready bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT ready_at IS NOT NULL FROM control.publish_runs WHERE id=$1`, f.setup.PublishRunID).Scan(&ready); err != nil || ready {
		t.Fatal("preparation committed ready state", ready, err)
	}
}

func registerServingIngress(t *testing.T, f publishRunFixture, name string, now time.Time) IngressLeaseIdentity {
	t.Helper()
	var pool string
	if err := f.database.pool.QueryRow(t.Context(), `SELECT ingress_pool_id FROM control.public_urls WHERE id=$1`, f.setup.PublicURLID).Scan(&pool); err != nil {
		t.Fatal(err)
	}
	lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: name, IngressRunID: name + "-process", ProtocolVersion: 1, ConnectionCapacity: 8, IngressPoolID: pool,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return lease.IngressLeaseIdentity
}

func servingObservation(t *testing.T, f publishRunFixture, owner IngressLeaseIdentity, now time.Time) (IngressPublicRunObservation, uint64) {
	t.Helper()
	snapshot, err := f.database.ReadIngressRoutingTableSnapshot(t.Context(), owner, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range snapshot.Entries {
		if event.Projection.PublishRunID == f.setup.PublishRunID {
			return IngressPublicRunObservation{f.setup.PublishRunID, int64(f.setup.PublishRunNumber), int64(event.EntryRevision), event.Projection.PublicUrlExpiresAt}, snapshot.RoutingTableRevision
		}
	}
	t.Fatal("missing preparation projection")
	return IngressPublicRunObservation{}, 0
}

func observeServingIngress(t *testing.T, f publishRunFixture, owner IngressLeaseIdentity, now time.Time) {
	t.Helper()
	observation, revision := servingObservation(t, f, owner, now)
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: owner,
		RoutingTableRevision: revision, PreparedPublicRuns: []IngressPublicRunObservation{observation}}, now, time.Minute); err != nil {
		t.Fatal(err)
	}
}

// state fixtures simulate installation explicitly. real runtime tests use the
// ingress controller and its installed table rather than this helper.
func readyTestServingRun(t *testing.T, f publishRunFixture, now time.Time) PublishRunLifecycle {
	t.Helper()
	if ready, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), now); err == nil {
		return ready
	} else if !errors.Is(err, ErrPublishRunNotReady) {
		t.Fatal(err)
	}
	registerServingIngress(t, f, fmt.Sprintf("fixture-serving-%d", now.UnixNano()), now)
	rows, err := f.database.pool.Query(t.Context(), `SELECT ingress_id,ingress_run_id,ingress_lease_revision FROM control.ingress_leases
		WHERE ingress_pool_id=(SELECT ingress_pool_id FROM control.public_urls WHERE id=$1) AND lease_expires_at>$2 AND NOT draining`, f.setup.PublicURLID, now)
	if err != nil {
		t.Fatal(err)
	}
	var owners []IngressLeaseIdentity
	for rows.Next() {
		var owner IngressLeaseIdentity
		if err := rows.Scan(&owner.IngressID, &owner.IngressRunID, &owner.IngressLeaseRevision); err != nil {
			t.Fatal(err)
		}
		owners = append(owners, owner)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, owner := range owners {
		observeServingIngress(t, f, owner, now)
	}
	ready, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range owners {
		observeServingIngress(t, f, owner, now)
	}
	return ready
}

func TestIntegrationPublicServingReadinessRequiresEveryCurrentReceiver(t *testing.T) {
	f := newPublishRunFixture(t)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, f.now)
	servingPreparationPending(t, f, f.now) // no receiver is not ready.
	a := registerServingIngress(t, f, "receiver-a", f.now)
	b := registerServingIngress(t, f, "receiver-b", f.now)
	observation, revision := servingObservation(t, f, a, f.now)
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: a, RoutingTableRevision: revision}, f.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	servingPreparationPending(t, f, f.now) // cursor alone proves no policy installation.
	observeServingIngress(t, f, a, f.now)
	servingPreparationPending(t, f, f.now)
	// process renewal must not extend an installed deadline.
	observation.ValidUntil = f.now.Add(time.Second)
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: b, RoutingTableRevision: revision, PreparedPublicRuns: []IngressPublicRunObservation{observation}}, f.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	later := f.now.Add(time.Second)
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: b}, later, time.Minute); err != nil {
		t.Fatal(err)
	}
	servingPreparationPending(t, f, later)
	observeServingIngress(t, f, b, later)
	ready, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), later)
	if err != nil || ready.ReadyAt == nil || !ready.ReadyAt.Equal(later) || !ready.Routable {
		t.Fatal("installed run did not become ready", ready, err)
	}
	// install the final projection with a short deadline from the outset;
	// a later retry of this revision cannot shorten already-observed evidence.
	observation, revision = servingObservation(t, f, a, later)
	observation.ValidUntil = later.Add(time.Second)
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: a, RoutingTableRevision: revision,
		PreparedPublicRuns: []IngressPublicRunObservation{observation}}, later, time.Minute); err != nil {
		t.Fatal(err)
	}
	observeServingIngress(t, f, b, later)
	joining := registerServingIngress(t, f, "late-receiver", later)
	if _, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), later); !errors.Is(err, ErrPublishRunNotReady) {
		t.Fatal("ready replay ignored an unprepared joining receiver", err)
	}
	if _, err := f.database.BeginIngressDrain(t.Context(), joining, later, later.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), later); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), observation.ValidUntil); !errors.Is(err, ErrPublishRunNotReady) {
		t.Fatal("first-ready history revived expired serving evidence", err)
	}
}

func TestIntegrationPublicServingReadinessExactBindingAndDrain(t *testing.T) {
	f := newPublishRunFixture(t)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, f.now)
	owner := registerServingIngress(t, f, "receiver", f.now)
	observation, revision := servingObservation(t, f, owner, f.now)
	for _, test := range []struct {
		name   string
		change func(*IngressRenewal)
		stale  bool
	}{
		{"run", func(r *IngressRenewal) { r.PreparedPublicRuns[0].PublishRunID = "another-run" }, false},
		{"number", func(r *IngressRenewal) { r.PreparedPublicRuns[0].PublishRunNumber++ }, false},
		{"entry", func(r *IngressRenewal) { r.PreparedPublicRuns[0].EntryRevision++ }, false},
		{"not-applied", func(r *IngressRenewal) { r.RoutingTableRevision = 0 }, false},
		{"expired", func(r *IngressRenewal) { r.PreparedPublicRuns[0].ValidUntil = f.now }, false},
		{"process", func(r *IngressRenewal) { r.IngressRunID = "other-process" }, true},
		{"lease", func(r *IngressRenewal) { r.IngressLeaseRevision++ }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := IngressRenewal{IngressLeaseIdentity: owner, RoutingTableRevision: revision, PreparedPublicRuns: []IngressPublicRunObservation{observation}}
			test.change(&r)
			_, err := f.database.RenewIngress(t.Context(), r, f.now, time.Minute)
			if test.stale && !errors.Is(err, ErrIngressLeaseStale) || !test.stale && err != nil {
				t.Fatal(err)
			}
			servingPreparationPending(t, f, f.now)
		})
	}
	observeServingIngress(t, f, owner, f.now)
	joining := registerServingIngress(t, f, "joining", f.now)
	servingPreparationPending(t, f, f.now)
	if _, err := f.database.BeginIngressDrain(t.Context(), joining, f.now, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), f.now); err != nil {
		t.Fatal("draining receiver blocked serving receivers", err)
	}
}

func TestIntegrationPublicReadinessSerializesRegistrationWithFinalVisibility(t *testing.T) {
	f := newPublishRunFixture(t)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, f.now)
	owner := registerServingIngress(t, f, "receiver", f.now)
	observeServingIngress(t, f, owner, f.now)
	d, now := f.database, f.now
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockIngressRoutingTableClock(ctx); err != nil {
		t.Fatal(err)
	}
	final := make(chan error, 1)
	workers.Go(func() { _, err := d.MarkPublishRunReady(ctx, f.authentication(), now); final <- err })
	finalPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), final)
	joined := make(chan error, 1)
	var snapshot IngressRoutingTableSnapshot
	workers.Go(func() {
		lease, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "joining-during-final", IngressRunID: "new-process", IngressPoolID: PrimaryIngressPoolID, ProtocolVersion: 1, ConnectionCapacity: 8}, now, time.Minute)
		if err == nil {
			snapshot, err = d.ReadIngressRoutingTableSnapshot(ctx, lease.IngressLeaseIdentity, now)
		}
		joined <- err
	})
	waitForPostgresBlock(t, ctx, d, finalPID, joined)
	if _, err := d.RenewIngress(ctx, IngressRenewal{IngressLeaseIdentity: owner}, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, final); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, joined); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 1 || snapshot.Entries[0].Projection.PublishRunReadyAt == nil || !snapshot.Entries[0].Projection.PublishRunReadyAt.Equal(now) {
		t.Fatal("joining receiver saw starting state after final receiver selection")
	}
}

func TestIntegrationPublicServingReadinessIsolationAndStartingClosure(t *testing.T) {
	a := newPublishRunFixture(t)
	prepareServingPublisher(t, a)
	servingPreparationPending(t, a, a.now)
	seedControlPublicURL(t, a.database, a.now, "independent")
	r := a.request
	r.PublicURLID, r.TeamID, r.MembershipID, r.ActingIdentityID = "public_url_independent", "team_independent", "membership_independent", "identity_independent"
	r.CertificateIdentifiers = []string{"route-independent.example.test"}
	r.CertificateCacheKey = "certificate_independent"
	setup, err := a.database.CreatePublishRun(t.Context(), r, a.now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	b := publishRunFixture{a.database, a.now, r, setup, a.leases}
	prepareServingPublisher(t, b)
	readyTestServingRun(t, b, b.now)
	servingPreparationPending(t, a, a.now)
	if err := a.database.ClosePublishRun(t.Context(), a.setup.PublishRunID, a.setup.PublishRunToken, a.now); err != nil {
		t.Fatal(err)
	}
	owner := registerServingIngress(t, b, "snapshot", b.now)
	snapshot, err := a.database.ReadIngressRoutingTableSnapshot(t.Context(), owner, a.now)
	if err != nil || len(snapshot.Entries) != 1 || snapshot.Entries[0].Projection.PublishRunID != b.setup.PublishRunID {
		t.Fatal("closing starting run left preparation routing or removed sibling", snapshot, err)
	}
}

func TestIntegrationPublicReadinessReplacementCannotReuseObservation(t *testing.T) {
	f := newPublishRunFixture(t)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, f.now)
	r := IngressRegistration{IngressID: "replacement", IngressRunID: "first", ProtocolVersion: 1, ConnectionCapacity: 8, IngressPoolID: PrimaryIngressPoolID}
	lease, err := f.database.RegisterIngress(t.Context(), r, f.now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	observation, revision := servingObservation(t, f, lease.IngressLeaseIdentity, f.now)
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: lease.IngressLeaseIdentity, RoutingTableRevision: revision, PreparedPublicRuns: []IngressPublicRunObservation{observation}}, f.now, time.Second); err != nil {
		t.Fatal(err)
	}
	r.IngressRunID = "second"
	later := f.now.Add(time.Second)
	replacement, err := f.database.RegisterIngress(t.Context(), r, later, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	servingPreparationPending(t, f, later)
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: lease.IngressLeaseIdentity, RoutingTableRevision: revision, PreparedPublicRuns: []IngressPublicRunObservation{observation}}, later, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("old process installed on replacement", err)
	}
	observeServingIngress(t, f, replacement.IngressLeaseIdentity, later)
	if _, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), later); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationPublicReadinessObservationDoesNotLockRunUnderIngress(t *testing.T) {
	f := newPublishRunFixture(t)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, f.now)
	owner := registerServingIngress(t, f, "independent-renewal", f.now)
	observation, revision := servingObservation(t, f, owner, f.now)
	gate, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockPublishRun(t.Context(), f.setup.PublishRunID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for range 2 { // both insertion and the conflict-update path must avoid run locks.
		if _, err := f.database.RenewIngress(ctx, IngressRenewal{IngressLeaseIdentity: owner, RoutingTableRevision: revision,
			PreparedPublicRuns: []IngressPublicRunObservation{observation}}, f.now, time.Minute); err != nil {
			t.Fatal("observation inverted run -> pool -> ingress order", err)
		}
	}
}

func TestIntegrationPublicServingReadinessStartsGuestClockAndMetricTogether(t *testing.T) {
	d, now, request, leases := newPublishRunPrerequisites(t)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateGuestTrial(t.Context(), guest, "tunnels.example.test", now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `INSERT INTO control.guest_public_urls(public_url_id,guest_id,created_at) VALUES($1,$2,$3)`, request.PublicURLID, guest.ID, now); err != nil {
		t.Fatal(err)
	}
	setup, err := d.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f := publishRunFixture{d, now, request, setup, leases}
	metrics := observability.New("control")
	t.Cleanup(func() { _ = metrics.Shutdown(t.Context()) })
	d.Instrument(metrics)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, now)
	servingPreparationPending(t, f, now.Add(2*time.Second))
	var premature bool
	if err := d.pool.QueryRow(t.Context(), `SELECT run.ready_at IS NOT NULL OR guest.active_ready_at IS NOT NULL OR guest.first_ready_at IS NOT NULL OR guest.used_ready_ns<>0 FROM control.publish_runs run CROSS JOIN control.guest_trials guest WHERE run.id=$1 AND guest.id=$2`, setup.PublishRunID, guest.ID).Scan(&premature); err != nil || premature {
		t.Fatal("preparation consumed guest ready time", premature, err)
	}
	metricText := func() string {
		w := httptest.NewRecorder()
		metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		return w.Body.String()
	}
	if strings.Contains(metricText(), "tnl_control_publish_runs_ready_total{") {
		t.Fatal("preparation emitted ready metric")
	}
	owner := registerServingIngress(t, f, "guest-receiver", now)
	observeServingIngress(t, f, owner, now)
	final := now.Add(3 * time.Second)
	if _, err := d.MarkPublishRunReady(t.Context(), f.authentication(), final); err != nil {
		t.Fatal(err)
	}
	var together bool
	if err := d.pool.QueryRow(t.Context(), `SELECT run.ready_at=$3 AND guest.active_ready_at=$3 AND guest.first_ready_at=$3 AND guest.used_ready_ns=0 FROM control.publish_runs run CROSS JOIN control.guest_trials guest WHERE run.id=$1 AND guest.id=$2`, setup.PublishRunID, guest.ID, final).Scan(&together); err != nil || !together {
		t.Fatal("ready clocks differ", together, err)
	}
	observeServingIngress(t, f, owner, final)
	if _, err := d.MarkPublishRunReady(t.Context(), f.authentication(), final); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(metricText(), "tnl_control_publish_runs_ready_total{tnl_public_url_purpose=\"app\"} 1") {
		t.Fatal("ready metric counted more than first transition")
	}
}

func TestIntegrationPublicReadinessIngressObservationRetainsInstalledDeadline(t *testing.T) {
	f := newPublishRunFixture(t)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, f.now)
	owner := registerServingIngress(t, f, "bounded-installation", f.now)
	old, revision := servingObservation(t, f, owner, f.now)
	old.ValidUntil = f.now.Add(time.Second)
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: owner, RoutingTableRevision: revision,
		PreparedPublicRuns: []IngressPublicRunObservation{old}}, f.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	later := f.now.Add(time.Second)
	if _, err := f.database.HeartbeatPublishRun(t.Context(), f.authentication(), later, time.Minute, time.Minute); err != nil {
		t.Fatal(err)
	}
	current, currentRevision := servingObservation(t, f, owner, later)
	if current.EntryRevision <= old.EntryRevision || !current.ValidUntil.After(old.ValidUntil) {
		t.Fatal("starting run heartbeat did not refresh projection", current, old)
	}
	// acknowledging the new cursor while retaining an older installed policy
	// cannot turn the heartbeat response into local serving preparation.
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: owner, RoutingTableRevision: currentRevision,
		PreparedPublicRuns: []IngressPublicRunObservation{old}}, later, time.Minute); err != nil {
		t.Fatal(err)
	}
	servingPreparationPending(t, f, later)
	observeServingIngress(t, f, owner, later)
	if _, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), later); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationPublicReadinessOutOfOrderInstallationReports(t *testing.T) {
	f := newPublishRunFixture(t)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, f.now)
	owner := registerServingIngress(t, f, "out-of-order", f.now)
	old, oldCursor := servingObservation(t, f, owner, f.now)
	old.ValidUntil = f.now.Add(20 * time.Second)
	report := func(observation IngressPublicRunObservation, cursor uint64) {
		t.Helper()
		if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: owner, RoutingTableRevision: cursor,
			PreparedPublicRuns: []IngressPublicRunObservation{observation}}, f.now.Add(2*time.Second), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	assertInstalled := func(expected IngressPublicRunObservation) {
		t.Helper()
		var revision int64
		var until time.Time
		if err := f.database.pool.QueryRow(t.Context(), `SELECT entry_revision,valid_until FROM control.ingress_public_run_observations
			WHERE ingress_id=$1 AND publish_run_id=$2 AND ingress_run_id=$3 AND ingress_lease_revision=$4 AND publish_run_number=$5`,
			owner.IngressID, expected.PublishRunID, owner.IngressRunID, owner.IngressLeaseRevision, expected.PublishRunNumber).Scan(&revision, &until); err != nil {
			t.Fatal(err)
		}
		if revision != expected.EntryRevision || !until.Equal(expected.ValidUntil) {
			t.Fatal("installation order changed evidence", revision, until, expected)
		}
	}
	report(old, oldCursor)
	if _, err := f.database.HeartbeatPublishRun(t.Context(), f.authentication(), f.now.Add(time.Second), time.Minute, time.Minute); err != nil {
		t.Fatal(err)
	}
	current, cursor := servingObservation(t, f, owner, f.now.Add(time.Second))
	current.ValidUntil = f.now.Add(5 * time.Second)
	if current.EntryRevision <= old.EntryRevision {
		t.Fatal("heartbeat did not create a new projection")
	}
	report(current, cursor)
	assertInstalled(current) // a newer revision replaces an older, longer deadline.
	// these are valid requests from the same process: lease identity and the
	// greatest acknowledged cursor do not establish installation arrival order.
	report(old, oldCursor)
	assertInstalled(current)
	report(old, cursor)
	assertInstalled(current)
	shorter := current
	shorter.ValidUntil = f.now.Add(3 * time.Second)
	report(shorter, cursor)
	assertInstalled(current)
	longer := current
	longer.ValidUntil = f.now.Add(12 * time.Second)
	report(longer, cursor)
	report(current, cursor)
	assertInstalled(longer)
	servingPreparationPending(t, f, longer.ValidUntil) // retries cannot revive expired evidence.

	// even an overlong reported deadline is bounded by the stored projection
	// and publisher lifetime, rather than becoming fresh authority on receipt.
	bounded, cursor := servingObservation(t, f, owner, f.now.Add(2*time.Second))
	overlong := bounded
	overlong.ValidUntil = f.now.Add(time.Hour)
	report(overlong, cursor)
	assertInstalled(bounded)
}

func TestIntegrationPublicReadinessClosureAndObservationLockOrder(t *testing.T) {
	f := newPublishRunFixture(t)
	prepareServingPublisher(t, f)
	servingPreparationPending(t, f, f.now)
	owner := registerServingIngress(t, f, "closure-race", f.now)
	observeServingIngress(t, f, owner, f.now)
	observation, revision := servingObservation(t, f, owner, f.now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT 1 FROM control.ingress_public_run_observations WHERE publish_run_id=$1 FOR UPDATE`, f.setup.PublishRunID); err != nil {
		t.Fatal(err)
	}
	closed, renewed := make(chan error, 1), make(chan error, 1)
	workers.Go(func() {
		closed <- f.database.ClosePublishRun(ctx, f.setup.PublishRunID, f.setup.PublishRunToken, f.now)
	})
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), closed)
	workers.Go(func() {
		_, err := f.database.RenewIngress(ctx, IngressRenewal{IngressLeaseIdentity: owner, RoutingTableRevision: revision,
			PreparedPublicRuns: []IngressPublicRunObservation{observation}}, f.now, time.Minute)
		renewed <- err
	})
	// closure holds the run; renewal must reach the observation row without
	// waiting on that run. the wait graph proves both lock footprints.
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), renewed)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan error{closed, renewed} {
		if err := awaitIntegrationResult(t, ctx, done); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.database.MarkPublishRunReady(ctx, f.authentication(), f.now); !errors.Is(err, ErrPublishRunStale) {
		t.Fatal("observation revived a closed run", err)
	}
	snapshot, err := f.database.ReadIngressRoutingTableSnapshot(ctx, owner, f.now)
	if err != nil || len(snapshot.Entries) != 0 {
		t.Fatal("closed preparation remained selectable", snapshot, err)
	}
}
