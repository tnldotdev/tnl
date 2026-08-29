package observability

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMetrics(t *testing.T) {
	metrics := New("worker")
	metrics.SetRoutes("active", 7)
	metrics.SetWorkerRoutes(7)
	metrics.SetWorkerCapacity(500)
	metrics.SetWorkerDraining(true)
	metrics.SetStreams(3)
	metrics.SetTailcatPaths("derp", 5)
	metrics.IncTailcatFailure("start", "timeout")
	metrics.AddTailcatForcedCloses(2)
	metrics.IncCapacityRejection("routes")
	metrics.AddForwardedBytes("ingress", 1024)

	server, err := Listen("127.0.0.1:0", metrics.Handler())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})

	response, err := http.Get("http://" + server.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		`tnl_info{mode="worker"} 1`,
		`tnl_routes{state="active"} 7`,
		`tnl_worker_routes_active 7`,
		`tnl_worker_route_capacity 500`,
		`tnl_worker_draining 1`,
		`tnl_streams_active 3`,
		`tnl_tailcat_paths{path="derp"} 5`,
		`tnl_tailcat_failures_total{operation="start",reason="timeout"} 1`,
		`tnl_tailcat_forced_closes_total 2`,
		`tnl_capacity_rejections_total{resource="routes"} 1`,
		`tnl_forwarded_bytes_total{direction="ingress"} 1024`,
	} {
		if !strings.Contains(string(body), line) {
			t.Errorf("scrape does not contain %q", line)
		}
	}
}
