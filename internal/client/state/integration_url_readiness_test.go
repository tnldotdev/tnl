package state

import (
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationURLReadinessOnlyCurrentPublisherInstanceCanClear(t *testing.T) {
	state, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	const server = "https://control.example.test"
	const hostname = "oauth.member.example.test"
	if _, err := state.Server(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		id     string
		number uint64
	}{{"", 1}, {"url_retired", 1}, {"svc_0123456789abcdefghijkl", 0}} {
		if err := state.MarkIntegrationURLReady(t.Context(), server, hostname, "invalid", input.id, input.number); err == nil {
			t.Fatal("incomplete service authority marked an integration ready")
		}
	}
	var replacementServiceID string
	for _, publisherInstanceID := range []string{"first", "replacement"} {
		id, err := opaqueid.New(opaqueid.ServicePrefix)
		if err != nil {
			t.Fatal(err)
		}
		if err := state.MarkIntegrationURLReady(t.Context(), server, hostname, publisherInstanceID, id, 1); err != nil {
			t.Fatal(err)
		}
		replacementServiceID = id
	}
	var serviceID string
	var number int64
	if err := state.db.QueryRowContext(t.Context(), `SELECT service_id, run_number FROM integration_url_leases WHERE server_origin=? AND hostname=?`,
		server, hostname).Scan(&serviceID, &number); err != nil || serviceID != replacementServiceID || number != 1 {
		t.Fatalf("replacement readiness lost its service run: %q/%d, %v", serviceID, number, err)
	}
	if err := state.ClearIntegrationURLReady(t.Context(), server, hostname, "first"); err != nil {
		t.Fatal(err)
	}
	ready, err := state.IntegrationURLReady(t.Context(), server, hostname)
	if err != nil || !ready {
		t.Fatalf("stale publisher cleared the new instance's lease: ready=%t, err=%v", ready, err)
	}
	if err := state.ClearIntegrationURLReady(t.Context(), server, hostname, "replacement"); err != nil {
		t.Fatal(err)
	}
	ready, err = state.IntegrationURLReady(t.Context(), server, hostname)
	if err != nil || ready {
		t.Fatalf("current publisher retained its lease after clearing: ready=%t, err=%v", ready, err)
	}
}
