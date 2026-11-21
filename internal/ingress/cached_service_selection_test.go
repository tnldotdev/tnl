package ingress

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

// a prepared HTTP selection must not call a visitor control operation.
type preparedSelectionControl struct{ PublicServiceControl }

func cachedSelectionServer(t *testing.T, count int, anonymous bool) (*Server, ingressv1.IngressLease, []ingressv1.PublicServiceVisitorAdmission) {
	t.Helper()
	config, control, _ := serviceSelectionConfig(t, count, anonymous)
	for index := range control.runs {
		control.runs[index].Traffic.TotalConnections = new(int64(1))
	}
	server := serviceSelectionHTTPServer(t, config)
	server.config.Control = preparedSelectionControl{}
	return server, config.CurrentLease(), control.runs
}

func selectCachedService(ctx context.Context, server *Server, lease ingressv1.IngressLease, capacity *visitorAdmission) (selectedServiceRun, error) {
	return server.selectPublicRun(ctx, lease, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.10:443"), "route.example", capacity)
}

func TestCachedServiceSelectionSkipsOnlyTheExhaustedRun(t *testing.T) {
	for _, reason := range []string{"service_connections", "service_connection_total", "service_connection_rate", "pending_service_connections", "pending_service_rate"} {
		t.Run(reason, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server, lease, runs := cachedSelectionServer(t, 9, !strings.HasPrefix(reason, "pending_"))
				for _, run := range runs[:8] {
					exhaustSelectionRun(t, server, run, reason)
				}
				capacity, reason := server.admitPendingService()
				if capacity == nil {
					t.Fatal(reason)
				}
				defer capacity.close()
				deadline := capacity.deadline
				selected, err := selectCachedService(t.Context(), server, lease, capacity)
				if err != nil || selected.access != httpRequestAccess || selected.serviceID != runs[8].ServiceId ||
					selected.runID != runs[8].ServiceRunId || selected.number != runs[8].RunNumber ||
					!capacity.deadline.Equal(deadline) || selected.visitorID == "" {
					t.Fatal("cached selection changed the sibling identity or setup deadline", err)
				}
				// selection holds one class of process capacity, never one per candidate.
				if server.admitted[pendingConnection]+server.admitted[visitorConnection] != 1 {
					t.Fatal("candidate search duplicated process capacity")
				}
				capacity.close()
				pending, active := publicServiceAdmissionCounts(server)
				key := selectionRunKey(runs[8])
				if pending != 0 || active != 0 || server.traffic.runs[key] != nil && server.traffic.runs[key].active != 0 ||
					server.traffic.pendingRuns[key] != nil && server.traffic.pendingRuns[key].active != 0 {
					t.Fatal("selected candidate retained capacity after close")
				}
			})
		})
	}
}

func TestCachedServiceSelectionFindsHealthyNinthWithoutControl(t *testing.T) {
	server, lease, runs := cachedSelectionServer(t, 9, true)
	for _, run := range runs[:8] {
		exhaustSelectionRun(t, server, run, "service_connections")
	}
	capacity, reason := server.admitPendingService()
	if capacity == nil {
		t.Fatal(reason)
	}
	defer capacity.close()
	selected, err := selectCachedService(t.Context(), server, lease, capacity)
	if err != nil || selected.runID != runs[8].ServiceRunId || capacity.key != selectionRunKey(runs[8]) {
		t.Fatal("eight exhausted runs hid the healthy ninth", selected.runID, err)
	}
	capacity.close()
	run := server.traffic.runs[selectionRunKey(runs[8])]
	if run == nil || run.active != 0 || run.connections != 1 {
		t.Fatal("closing selection lost the lifetime debit or retained active capacity", run)
	}
}

func TestCachedServiceSelectionFiltersUnavailableRunsBeforeSelection(t *testing.T) {
	for _, mode := range []string{"expired run", "expired relays", "IP denial", "all exhausted", "setup expired", "stale lease"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server, lease, runs := cachedSelectionServer(t, 9, true)
				capacity, reason := server.admitPendingService()
				if capacity == nil {
					t.Fatal(reason)
				}
				defer capacity.close()
				deny, err := ippolicy.New([32]byte{1}, nil)
				if err != nil {
					t.Fatal(err)
				}
				server.services.mu.Lock()
				for _, run := range runs[:8] {
					route := server.services.runs[run.ServiceRunId]
					switch mode {
					case "expired run":
						route.until = time.Now()
					case "expired relays":
						route.run.ConnectedRelays[0].ServingUntil = time.Now()
					case "IP denial":
						route.ip = &deny
					default:
						exhaustSelectionRun(t, server, run, "service_connections")
					}
				}
				server.services.mu.Unlock()
				switch mode {
				case "all exhausted":
					exhaustSelectionRun(t, server, runs[8], "service_connections")
				case "setup expired":
					capacity.deadline = time.Now()
				case "stale lease":
					lease.IngressLeaseRevision++
				}
				selected, err := selectCachedService(t.Context(), server, lease, capacity)
				healthy := mode == "expired run" || mode == "expired relays"
				if healthy {
					if err != nil || selected.runID != runs[8].ServiceRunId {
						t.Fatal("unavailable runs hid the healthy ninth", err, selected.runID)
					}
				} else if err == nil || capacity.key != (trafficKey{}) || capacity.state != pendingCapacity {
					t.Fatal("denial selected a run or retained its accounting", mode, err)
				}
				if mode == "setup expired" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("selection did not retain the original expired deadline", err)
				}
				capacity.close()
				pending, active := publicServiceAdmissionCounts(server)
				if pending != 0 || active != 0 {
					t.Fatal("selection leaked process capacity", pending, active)
				}
				if !healthy {
					key := selectionRunKey(runs[8])
					if run := server.traffic.runs[key]; run != nil && mode != "all exhausted" {
						t.Fatal("denial spent the healthy run's budget", run)
					}
				}
			})
		})
	}
}

func TestCachedServiceSelectionRotatesTheEligiblePool(t *testing.T) {
	server, lease, runs := cachedSelectionServer(t, 10, false)
	for _, run := range runs[:8] {
		exhaustSelectionRun(t, server, run, "pending_service_connections")
	}
	for _, start := range []uint64{8, 9} {
		server.nextServiceRun.Store(start)
		capacity, reason := server.admitPendingService()
		if capacity == nil {
			t.Fatal(reason)
		}
		selected, err := selectCachedService(t.Context(), server, lease, capacity)
		capacity.close()
		if err != nil || selected.runID != runs[start].ServiceRunId {
			t.Fatal("selection stopped rotating within the eligible pool", err, selected.runID)
		}
	}
}
