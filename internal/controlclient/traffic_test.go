package controlclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestPublisherRunTrafficUsesTypedBodyAndProofHeaders(t *testing.T) {
	var bodies []controlv1.CreatePublishRunRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/public-urls/url/publish-runs" || r.Header.Get("Authorization") != "Bearer publisher-access" || r.Header.Get("Idempotency-Key") != "retry" || r.Header.Get("Publisher-Run-Proof") != "signed-proof" {
			t.Error("traffic request lost the publisher authentication boundary")
		}
		var body controlv1.CreatePublishRunRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		bodies = append(bodies, body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(controlv1.PublishRunSetup{})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "control-session")
	if err != nil {
		t.Fatal(err)
	}
	connections, rate, per, upload := 48, 40, "2s", int64(4<<20)
	selection := &trafficlimits.Selection{Connections: &connections, Rate: &rate, RatePer: &per, UploadBytes: &upload}
	if _, err := client.CreatePublisherRunWithTraffic(t.Context(), "url", "retry", "publisher-access", "signed-proof", selection); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreatePublisherRun(t.Context(), "url", "retry", "publisher-access", "signed-proof"); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || bodies[0].Traffic == nil || *bodies[0].Traffic.Connections != 48 || *bodies[0].Traffic.RatePer != "2s" || *bodies[0].Traffic.UploadBytes != upload || bodies[0].Traffic.DownloadBytes != nil || bodies[1].Traffic != nil {
		t.Fatalf("typed traffic selections: %+v", bodies)
	}
	invalid := 0
	if _, err := client.CreatePublisherRunWithTraffic(t.Context(), "url", "retry", "publisher-access", "signed-proof", &trafficlimits.Selection{Rate: &invalid}); err == nil || len(bodies) != 2 {
		t.Fatal("invalid selection reached the server")
	}
}
