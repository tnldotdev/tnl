package state

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
)

func guestReadinessMetrics(t *testing.T, f guestServiceFixture) func() string {
	t.Helper()
	metrics := observability.New("control")
	t.Cleanup(func() { _ = metrics.Shutdown(t.Context()) })
	f.database.Instrument(metrics)
	return func() string {
		w := httptest.NewRecorder()
		metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		return w.Body.String()
	}
}

func assertGuestWaitingForDNS(t *testing.T, f guestServiceFixture, metricText func() string, at time.Time) {
	t.Helper()
	state, err := f.heartbeat(at)
	if err != nil || state.State != "starting" || state.PublicEndpointReady || state.EndpointRevision != f.service.EndpointRevision {
		t.Fatal("guest became ready before public DNS", state.State, state.PublicEndpointReady, err)
	}
	var untouched bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT run.ready_at IS NULL AND guest.active_ready_at IS NULL
	    AND guest.first_ready_at IS NULL AND guest.ready_deadline IS NULL AND guest.serving_until IS NULL AND guest.used_ready_ns=0
	    FROM control.service_runs run JOIN control.guest_trials guest ON guest.id=run.guest_id WHERE run.id=$1`,
		f.run.RunID).Scan(&untouched); err != nil || !untouched {
		t.Fatal("DNS preparation consumed guest allowance", untouched, err)
	}
	if strings.Contains(metricText(), "tnl_control_service_runs_ready_total ") {
		t.Fatal("DNS preparation emitted first-ready metric")
	}
}

func TestIntegrationGuestFirstReadinessWaitsForPublicDNS(t *testing.T) {
	for _, entry := range []string{"heartbeat", "connection ready"} {
		t.Run(entry, func(t *testing.T) {
			f, _ := guestAuthorityFixture(t, false)
			metricText := guestReadinessMetrics(t, f)
			registerTestIngress(t, f.database, f.now)
			setDNS := func(state ServiceEndpointDNSState) {
				setEndpointReadinessDNS(t, servicePublicationFixture{database: f.database, service: f.service, now: f.now}, true, state)
			}
			setDNS(ServiceEndpointDNSPending)
			if entry == "connection ready" {
				if _, err := f.heartbeat(f.now); err != nil {
					t.Fatal(err)
				}
			}
			f.preparePublisher(t, f.now)
			assertGuestWaitingForDNS(t, f, metricText, f.now)
			work, found, err := f.database.ClaimServiceEndpointDNSWork(f.ctx, "guest-dns-pending", f.now, time.Minute)
			if err != nil || !found || work.ServiceID != f.service.ID {
				t.Fatal("prepared starting guest could not publish DNS", found, err)
			}
			if err := f.database.ValidateServiceEndpointDNSWork(f.ctx, work, f.now); err != nil {
				t.Fatal("claim and validation disagree for prepared guest", err)
			}
			work.State, work.AvailableAt = ServiceEndpointDNSFailed, time.Time{}
			if _, err := f.database.SaveServiceEndpointDNSWork(f.ctx, work, f.now); err != nil {
				t.Fatal(err)
			}
			assertGuestWaitingForDNS(t, f, metricText, f.now.Add(time.Second))
			setDNS(ServiceEndpointDNSPending)
			work, found, err = f.database.ClaimServiceEndpointDNSWork(f.ctx, "guest-dns-retry", f.now.Add(2*time.Second), time.Minute)
			if err != nil || !found {
				t.Fatal("prepared guest lost DNS retry eligibility", found, err)
			}
			if err := f.database.ValidateServiceEndpointDNSWork(f.ctx, work, f.now.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			work.State, work.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
			if _, err := f.database.SaveServiceEndpointDNSWork(f.ctx, work, f.now.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			final := f.now.Add(3 * time.Second)
			if entry == "connection ready" {
				slot := f.run.Connections[0]
				// defer one current connection's ready report until DNS has
				// published, then cross the real connection-ready entry point.
				if _, err := f.database.pool.Exec(f.ctx, `UPDATE control.service_connection_slots SET state='connected'
				    WHERE publisher_connection_id=$1`, slot.PublisherConnectionID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.database.ReadyServicePublisherConnection(f.ctx, slot.PublisherConnectionID, f.run.RunID,
					f.run.RunNumber, slot.Revision, f.leases[slot.RelayServiceID].RelayLeaseIdentity, final); err != nil {
					t.Fatal(err)
				}
				if !f.stored(t).ActiveReadyAt.Valid || !strings.Contains(metricText(), "tnl_control_service_runs_ready_total 1\n") {
					t.Fatal("connection-ready entry point did not start the clock and metric")
				}
			}
			state, err := f.heartbeat(final)
			if err != nil || state.State != "ready" || !state.PublicEndpointReady {
				t.Fatal("published DNS did not release guest readiness", state.State, state.PublicEndpointReady, err)
			}
			var together bool
			if err := f.database.pool.QueryRow(t.Context(), `SELECT run.ready_at=guest.active_ready_at
			    AND run.ready_at=guest.first_ready_at AND run.ready_at>=$2 AND guest.used_ready_ns=0
			    FROM control.service_runs run JOIN control.guest_trials guest ON guest.id=run.guest_id WHERE run.id=$1`,
				f.run.RunID, final).Scan(&together); err != nil || !together {
				t.Fatal("first-ready clocks were not initialized together after DNS", together, err)
			}
			before := f.stored(t)
			for _, dns := range []ServiceEndpointDNSState{ServiceEndpointDNSFailed, ServiceEndpointDNSPublished} {
				setDNS(dns)
				state, err = f.heartbeat(final.Add(time.Second))
				if err != nil || state.State != "ready" || state.PublicEndpointReady != (dns == ServiceEndpointDNSPublished) {
					t.Fatal("later DNS changed ordinary run readiness", state.State, state.PublicEndpointReady, err)
				}
				after := f.stored(t)
				if after.ActiveReadyAt != before.ActiveReadyAt || after.FirstReadyAt != before.FirstReadyAt ||
					after.ReadyDeadline != before.ReadyDeadline || after.ExpiresAt != before.ExpiresAt || after.UsedReadyNs != before.UsedReadyNs {
					t.Fatal("later DNS paused, refilled, or reset the guest clock")
				}
				if !after.ServingUntil.Valid || !after.ServingUntil.Time.Equal(state.ServingUntil) ||
					!state.ServingUntil.After(state.ExpiresAt) || state.ServingUntil.After(after.ReadyDeadline.Time) ||
					state.ServingUntil.After(after.ExpiresAt.Time) {
					t.Fatal("DNS heartbeat lost separately bounded issued serving authority")
				}
			}
			if !strings.Contains(metricText(), "tnl_control_service_runs_ready_total 1\n") {
				t.Fatal("DNS recovery counted another first-ready transition")
			}
			if err := f.database.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, final.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			closed := f.stored(t)
			issued := state.ServingUntil.Sub(before.ActiveReadyAt.Time)
			if closed.UsedReadyNs != int64(issued) || closed.ReadyDeadline.Valid || closed.ActiveReadyAt.Valid ||
				closed.ActiveServiceRunID.Valid || closed.ExpiresAt != before.ExpiresAt ||
				!closed.ServingUntil.Time.Equal(state.ServingUntil) {
				t.Fatal("DNS failure or recovery changed fixed-deadline issued-tail settlement")
			}
		})
	}
}

func TestIntegrationGuestFirstReadinessRequiresCompatibleIngress(t *testing.T) {
	f, _ := guestAuthorityFixture(t, false)
	metricText := guestReadinessMetrics(t, f)
	setEndpointReadinessDNS(t, servicePublicationFixture{database: f.database, service: f.service, now: f.now}, true, ServiceEndpointDNSPublished)
	f.preparePublisher(t, f.now)
	assertGuestWaitingForDNS(t, f, metricText, f.now)
	ingress, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "guest-incompatible", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1,
		ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID, HTTPS: false,
	}, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	registerTestIngress(t, f.database, f.now)
	assertGuestWaitingForDNS(t, f, metricText, f.now)
	if _, err := f.database.BeginIngressDrain(t.Context(), ingress.IngressLeaseIdentity, f.now, f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	state, err := f.heartbeat(f.now)
	if err != nil || state.State != "ready" || !state.PublicEndpointReady || !f.stored(t).ActiveReadyAt.Valid ||
		!strings.Contains(metricText(), "tnl_control_service_runs_ready_total 1\n") {
		t.Fatal("compatible ingress did not release first readiness", state.State, state.PublicEndpointReady, err)
	}
}

func TestIntegrationGuestFirstReadinessRechecksIngressAfterDNSWait(t *testing.T) {
	f, _ := guestAuthorityFixture(t, false)
	metricText := guestReadinessMetrics(t, f)
	ingress := registerTestIngress(t, f.database, f.now)
	setEndpointReadinessDNS(t, servicePublicationFixture{database: f.database, service: f.service, now: f.now}, true, ServiceEndpointDNSPending)
	f.preparePublisher(t, f.now)
	assertGuestWaitingForDNS(t, f, metricText, f.now)
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `UPDATE control.service_endpoints SET dns_state='published',dns_available_at=NULL WHERE service_id=$1`, f.service.ID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() {
		state, err := f.database.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now,
			ServiceRunHealth{Healthy: true, StreamCapacity: 32})
		if err == nil && (state.State != "starting" || state.PublicEndpointReady) {
			err = errors.New("guest used pre-wait ingress facts")
		}
		done <- err
	})
	waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), done)
	if _, err := f.database.BeginIngressDrain(t.Context(), ingress.IngressLeaseIdentity, f.now, f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	assertGuestWaitingForDNS(t, f, metricText, f.now)
}
