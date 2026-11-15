package ingress

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

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
			server, lease, runs := cachedSelectionServer(t, 2, !strings.HasPrefix(reason, "pending_"))
			exhaustSelectionRun(t, server, runs[0], reason)
			capacity, reason := server.admitPendingService()
			if capacity == nil {
				t.Fatal(reason)
			}
			defer capacity.close()
			deadline := capacity.deadline
			selected, err := selectCachedService(t.Context(), server, lease, capacity)
			if err != nil || selected.access != httpRequestAccess || selected.serviceID != runs[1].ServiceId ||
				selected.runID != runs[1].ServiceRunId || selected.number != runs[1].RunNumber ||
				!capacity.deadline.Equal(deadline) || selected.visitorID == "" {
				t.Fatal("cached selection changed the sibling identity or setup deadline", err)
			}
			// selection holds one class of process capacity, never one per candidate.
			if server.admitted[pendingConnection]+server.admitted[visitorConnection] != 1 {
				t.Fatal("candidate search duplicated process capacity")
			}
			capacity.close()
			pending, active := publicServiceAdmissionCounts(server)
			key := selectionRunKey(runs[1])
			if pending != 0 || active != 0 || server.traffic.runs[key] != nil && server.traffic.runs[key].active != 0 ||
				server.traffic.pendingRuns[key] != nil && server.traffic.pendingRuns[key].active != 0 {
				t.Fatal("selected candidate retained capacity after close")
			}
		})
	}
}

func TestCachedServiceSelectionBoundsTheSearchWithoutControl(t *testing.T) {
	server, lease, runs := cachedSelectionServer(t, 9, true)
	for _, run := range runs[:8] {
		exhaustSelectionRun(t, server, run, "service_connections")
	}
	capacity, reason := server.admitPendingService()
	if capacity == nil {
		t.Fatal(reason)
	}
	defer capacity.close()
	_, err := selectCachedService(t.Context(), server, lease, capacity)
	if !errors.Is(err, ErrServiceSelectionLimit) || capacity.key != (trafficKey{}) || capacity.state != pendingCapacity {
		t.Fatal("cached selection searched beyond eight candidates or retained a failed candidate", err)
	}
	if _, exists := server.traffic.runs[selectionRunKey(runs[8])]; exists {
		t.Fatal("bounded search spent the ninth run's quota")
	}
}
