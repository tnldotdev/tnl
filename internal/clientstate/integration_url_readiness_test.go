package clientstate

import (
	"path/filepath"
	"testing"
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
	for _, publisherInstanceID := range []string{"first", "replacement"} {
		if err := state.MarkIntegrationURLReady(t.Context(), server, hostname, publisherInstanceID); err != nil {
			t.Fatal(err)
		}
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
