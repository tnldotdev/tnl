package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestIntegrationPrivateServiceHeartbeatReports(t *testing.T) {
	f := newConnectorPairFixture(t)
	d, run, now := f.d, f.run, f.now
	heartbeat := func(t *testing.T, report ServiceRunHealth, at time.Time) ServiceRunState {
		t.Helper()
		state, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, at, report)
		if err != nil {
			t.Fatal(err)
		}
		if state.Healthy != report.Healthy || state.StreamCapacity != report.StreamCapacity || state.ReportedStreams != report.ActiveStreams || !state.ExpiresAt.Equal(at.Add(45*time.Second)) {
			t.Fatalf("heartbeat lost its report or lease: %+v", state)
		}
		return state
	}
	selectable := func(t *testing.T, want bool, at time.Time) {
		t.Helper()
		selected, err := d.SelectServiceRun(f.visitor, run.ServiceID, f.request.Subject.IdentityID, f.request.Subject.DeviceID, at)
		if want {
			if err != nil || selected.ServiceRunID != run.RunID {
				t.Fatal("healthy publisher with spare capacity was not selected", err)
			}
		} else if !errors.Is(err, ErrServiceAccess) {
			t.Fatal("unavailable publisher retained selection", err)
		}
	}
	// read the durable report and deadline without performing another renewal.
	snapshot := func(t *testing.T) string {
		t.Helper()
		var row string
		if err := d.pool.QueryRow(t.Context(), `SELECT to_jsonb(run)::text FROM control.service_runs run WHERE id=$1`, run.RunID).Scan(&row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	for _, tc := range []struct {
		name       string
		report     ServiceRunHealth
		state      string
		selectable bool
	}{
		{"spare capacity", ServiceRunHealth{Healthy: true, StreamCapacity: 3, ActiveStreams: 2}, "ready", true},
		{"saturated", ServiceRunHealth{Healthy: true, StreamCapacity: 3, ActiveStreams: 3}, "ready", false},
		{"capacity reduced below active count", ServiceRunHealth{Healthy: true, StreamCapacity: 1, ActiveStreams: 3}, "ready", false},
		{"unhealthy", ServiceRunHealth{Healthy: false, StreamCapacity: 3, ActiveStreams: 2}, "starting", false},
		{"healthy recovery", ServiceRunHealth{Healthy: true, StreamCapacity: 3, ActiveStreams: 2}, "ready", true},
		{"maximum capacity", ServiceRunHealth{Healthy: true, StreamCapacity: 1 << 20, ActiveStreams: 0}, "ready", true},
		{"maximum active count", ServiceRunHealth{Healthy: true, StreamCapacity: 1 << 20, ActiveStreams: 1<<31 - 1}, "ready", false},
		{"minimum capacity", ServiceRunHealth{Healthy: true, StreamCapacity: 1, ActiveStreams: 0}, "ready", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now = now.Add(time.Second)
			state := heartbeat(t, tc.report, now)
			if state.State != tc.state {
				t.Fatalf("heartbeat readiness=%s, want %s", state.State, tc.state)
			}
			selectable(t, tc.selectable, now)
		})
	}
	for _, tc := range []struct {
		name   string
		report ServiceRunHealth
	}{
		{"zero capacity", ServiceRunHealth{Healthy: false, StreamCapacity: 0, ActiveStreams: 0}},
		{"negative capacity", ServiceRunHealth{Healthy: false, StreamCapacity: -1, ActiveStreams: 0}},
		{"capacity above maximum", ServiceRunHealth{Healthy: false, StreamCapacity: 1<<20 + 1, ActiveStreams: 0}},
		{"negative active count", ServiceRunHealth{Healthy: false, StreamCapacity: 3, ActiveStreams: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := snapshot(t)
			if _, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now.Add(time.Second), tc.report); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("invalid report renewed publisher", err)
			}
			if snapshot(t) != before {
				t.Fatal("invalid report changed durable health, readiness or lease")
			}
		})
	}
	before := snapshot(t)
	wrongToken, _, err := credentials.NewServiceRunToken()
	if err != nil {
		t.Fatal(err)
	}
	unhealthy := ServiceRunHealth{Healthy: false, StreamCapacity: 7, ActiveStreams: 4}
	if _, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, wrongToken.String(), now.Add(time.Second), unhealthy); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("wrong credential renewed publisher", err)
	}
	if snapshot(t) != before {
		t.Fatal("wrong credential changed durable health, readiness or lease")
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now.Add(45*time.Second), unhealthy); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("expired publisher lease accepted a report", err)
	}
	if snapshot(t) != before {
		t.Fatal("expired publisher report revived readiness or lease")
	}
	selectable(t, false, now.Add(45*time.Second))
}
