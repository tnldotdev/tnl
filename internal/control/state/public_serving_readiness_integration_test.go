package state

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
)

func publicServingFixture(t *testing.T, f servicePublicationFixture) servicePublicationFixture {
	t.Helper()
	actor := f.actor(t)
	declaration, _, err := f.database.GetServiceConfiguration(t.Context(), f.service.ID, actor)
	if err != nil || declaration == nil {
		t.Fatal("missing service declaration", err)
	}
	declaration.Public = new(true)
	f.service, err = f.database.ConfigureService(t.Context(), f.service.ID, actor, f.service.ServiceMetadata,
		declaration, ServiceUpdateConditions{}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func prepareServingPublisher(t *testing.T, f servicePublicationFixture) {
	t.Helper()
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	f.readyConnections(t, f.now)
	state, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || state.State != "ready" {
		t.Fatal("certificate and ready publisher connections did not enable serving", state.State, err)
	}
}

func registerServingIngress(t *testing.T, f servicePublicationFixture, name string, now time.Time) IngressLeaseIdentity {
	t.Helper()
	var pool string
	if err := f.database.pool.QueryRow(t.Context(), `SELECT ingress_pool_id FROM control.services WHERE id=$1`, f.service.ID).Scan(&pool); err != nil {
		t.Fatal(err)
	}
	lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: name, IngressRunID: name + "-process", ProtocolVersion: 1, ConnectionCapacity: 64,
		IngressPoolID: pool, HTTPS: true,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return lease.IngressLeaseIdentity
}

func admitServingVisitor(t *testing.T, f servicePublicationFixture, owner IngressLeaseIdentity, now time.Time) (PublicServiceVisitorAdmission, error) {
	t.Helper()
	return f.database.AdmitPublicServiceVisitor(t.Context(), owner, PrimaryIngressPoolID,
		mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), f.service.Endpoint.Hostname, 443, netip.MustParseAddr("192.0.2.10"), now)
}

func TestIntegrationPublicServingReadinessRequiresPublisherCertificateAndConnections(t *testing.T) {
	f := publicServingFixture(t, newServicePublicationFixture(t))
	owner := registerServingIngress(t, f, "receiver-a", f.now)
	if _, err := admitServingVisitor(t, f, owner, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("starting run admitted a visitor", err)
	}
	f.readyConnections(t, f.now)
	if state, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "starting" {
		t.Fatal("connected publisher bypassed certificate readiness", state.State, err)
	}
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	if state, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
		t.Fatal("complete publisher did not become ready", state.State, err)
	}
	// ingress processes select current service state, not per-process
	// installation acknowledgements. a joining process needs no run mutation.
	other := registerServingIngress(t, f, "receiver-b", f.now)
	for _, ingress := range []IngressLeaseIdentity{owner, other} {
		admission, err := admitServingVisitor(t, f, ingress, f.now)
		if err != nil || admission.RunID != f.run.RunID || admission.RunNumber != f.run.RunNumber {
			t.Fatal("ingress selected a different run or required stale installation state", err)
		}
	}
}

func TestIntegrationPublicServingReadinessExactBindingAndDrain(t *testing.T) {
	f := publicServingFixture(t, newServicePublicationFixture(t))
	prepareServingPublisher(t, f)
	owner := registerServingIngress(t, f, "receiver", f.now)
	for _, change := range []func(*IngressLeaseIdentity){
		func(i *IngressLeaseIdentity) { i.IngressRunID = "another-process" },
		func(i *IngressLeaseIdentity) { i.IngressLeaseRevision++ },
	} {
		stale := owner
		change(&stale)
		if _, err := admitServingVisitor(t, f, stale, f.now); err == nil {
			t.Fatal("stale ingress process or lease admitted a visitor")
		}
	}
	if _, err := f.database.BeginIngressDrain(t.Context(), owner, f.now, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := admitServingVisitor(t, f, owner, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("draining ingress accepted a new visitor", err)
	}
	other := registerServingIngress(t, f, "serving", f.now)
	if _, err := admitServingVisitor(t, f, other, f.now); err != nil {
		t.Fatal("one draining ingress suppressed a healthy receiver", err)
	}
}

func TestIntegrationPublicReadinessSerializesRegistrationWithFinalVisibility(t *testing.T) {
	f := publicServingFixture(t, newServicePublicationFixture(t))
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	f.readyConnections(t, f.now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := controlstatedb.New(gate).LockService(ctx, f.service.ID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() {
		state, err := f.database.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now,
			ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if err == nil && state.State != "ready" {
			err = errors.New("complete publication remained starting")
		}
		done <- err
	})
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), done)
	// process registration is independent of a service's locked readiness
	// transition. admission checks that transition under its own service guard.
	owner := registerServingIngress(t, f, "joining", f.now)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	if _, err := admitServingVisitor(t, f, owner, f.now); err != nil {
		t.Fatal("joining ingress could not use committed readiness", err)
	}
}

func TestIntegrationPublicServingReadinessIsolationAndStartingClosure(t *testing.T) {
	a := publicServingFixture(t, newServicePublicationFixture(t))
	b := a.sibling(t, "independent", a.now)
	b = publicServingFixture(t, b)
	b.start(t, "first", b.now)
	prepareServingPublisher(t, b)
	owner := registerServingIngress(t, b, "receiver", b.now)
	if err := a.database.CloseServiceRun(t.Context(), a.service.ID, a.run.RunID, a.run.Token, a.now); err != nil {
		t.Fatal(err)
	}
	if _, err := admitServingVisitor(t, a, owner, a.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("closed starting run remained selectable", err)
	}
	admission, err := admitServingVisitor(t, b, owner, b.now)
	if err != nil || admission.RunID != b.run.RunID {
		t.Fatal("closing a starting service suppressed its ready sibling", err)
	}
}

func TestIntegrationPublicReadinessReplacementCannotReuseObservation(t *testing.T) {
	f := publicServingFixture(t, newServicePublicationFixture(t))
	prepareServingPublisher(t, f)
	registration := IngressRegistration{IngressID: "replacement", IngressRunID: "first", HTTPS: true,
		ProtocolVersion: 1, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID}
	first, err := f.database.RegisterIngress(t.Context(), registration, f.now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	registration.IngressRunID = "second"
	later := f.now.Add(time.Second)
	replacement, err := f.database.RegisterIngress(t.Context(), registration, later, time.Minute)
	if err != nil || replacement.IngressLeaseRevision <= first.IngressLeaseRevision {
		t.Fatal("ingress replacement lost its lease fence", err)
	}
	if _, err := admitServingVisitor(t, f, first.IngressLeaseIdentity, later); err == nil {
		t.Fatal("old ingress process admitted on its replacement's lease")
	}
	if _, err := admitServingVisitor(t, f, replacement.IngressLeaseIdentity, later); err != nil {
		t.Fatal("replacement could not select current service readiness", err)
	}
}

func TestIntegrationPublicReadinessIngressRenewalCannotExtendRunDeadline(t *testing.T) {
	f := publicServingFixture(t, newServicePublicationFixture(t))
	prepareServingPublisher(t, f)
	owner := registerServingIngress(t, f, "receiver", f.now)
	at := f.run.ExpiresAt
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: owner}, at, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := admitServingVisitor(t, f, owner, at); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("ingress renewal revived an expired publisher", err)
	}
	if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, at,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("first-ready history revived an expired publisher", err)
	}
}

func TestIntegrationServiceReadinessStartsGuestClockAndMetricTogether(t *testing.T) {
	f, guest := guestAuthorityFixture(t, false)
	d, now := f.database, f.now
	metrics := observability.New("control")
	t.Cleanup(func() { _ = metrics.Shutdown(t.Context()) })
	d.Instrument(metrics)
	for _, at := range []time.Time{now, now.Add(2 * time.Second)} {
		if _, err := f.heartbeat(at); err != nil {
			t.Fatal(err)
		}
	}
	var premature bool
	if err := d.pool.QueryRow(t.Context(), `SELECT run.ready_at IS NOT NULL OR guest.active_ready_at IS NOT NULL OR guest.first_ready_at IS NOT NULL OR guest.used_ready_ns<>0 FROM control.service_runs run JOIN control.guest_trials guest ON guest.id=run.guest_id WHERE run.id=$1 AND guest.id=$2`, f.run.RunID, guest.ID).Scan(&premature); err != nil || premature {
		t.Fatal("preparation consumed guest ready time", premature, err)
	}
	metricText := func() string {
		w := httptest.NewRecorder()
		metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		return w.Body.String()
	}
	if strings.Contains(metricText(), "tnl_control_service_runs_ready_total ") {
		t.Fatal("preparation emitted ready metric")
	}
	final := now.Add(3 * time.Second)
	f.ready(t, final)
	var together bool
	if err := d.pool.QueryRow(t.Context(), `SELECT run.ready_at IS NOT NULL AND run.ready_at=guest.active_ready_at
	    AND run.ready_at=guest.first_ready_at AND run.ready_at>=$3 AND guest.used_ready_ns=0
	    FROM control.service_runs run JOIN control.guest_trials guest ON guest.id=run.guest_id
	    WHERE run.id=$1 AND guest.id=$2`, f.run.RunID, guest.ID, final).Scan(&together); err != nil || !together {
		t.Fatal("ready clocks differ", together, err)
	}
	for range 2 {
		if _, err := f.heartbeat(final.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(metricText(), "tnl_control_service_runs_ready_total 1\n") {
		t.Fatal("ready metric counted more than first transition")
	}
}
