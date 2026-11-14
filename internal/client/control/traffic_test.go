package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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
	selection := &trafficlimits.Selection{Connections: new(48), Rate: new(40), RatePer: new("2s"), Burst: new(50), UploadBytes: new(int64(4 << 20)), DownloadBytes: new(int64(8 << 20)), TotalConnections: new(int64(0)), TotalUploadBytes: new(int64(1 << 30)), TotalDownloadBytes: new(int64(2 << 30))}
	if _, err := client.CreatePublisherRun(t.Context(), "url", "retry", "publisher-access", "signed-proof", selection, controlv1.HTTPProtection{TemporaryBlocks: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreatePublisherRun(t.Context(), "url", "retry", "publisher-access", "signed-proof", nil, controlv1.HTTPProtection{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreatePublisherRun(t.Context(), "url", "retry", "publisher-access", "signed-proof", &trafficlimits.Selection{Connections: new(24)}, controlv1.HTTPProtection{}, "AWS:US-WEST-1", "fly:sjc"); err != nil {
		t.Fatal(err)
	}
	want := &controlv1.TrafficSelection{
		Connections: selection.Connections, Rate: selection.Rate, RatePer: selection.RatePer, Burst: selection.Burst,
		UploadBytes: selection.UploadBytes, DownloadBytes: selection.DownloadBytes,
		TotalConnections: selection.TotalConnections, TotalUploadBytes: selection.TotalUploadBytes, TotalDownloadBytes: selection.TotalDownloadBytes,
	}
	if len(bodies) != 3 || !reflect.DeepEqual(bodies[0].Traffic, want) || bodies[1].Traffic != nil || !reflect.DeepEqual(bodies[2].Traffic, &controlv1.TrafficSelection{Connections: new(24)}) {
		t.Fatalf("typed traffic selections: %+v", bodies)
	}
	if bodies[0].HttpProtection == nil || !bodies[0].HttpProtection.BlocksSources() {
		t.Fatal("typed publish-run body lost effective HTTP protection")
	}
	if bodies[2].PreferredRegions == nil || !reflect.DeepEqual(*bodies[2].PreferredRegions, []string{"aws:us-west-1", "fly:sjc"}) {
		t.Fatal("provider-qualified preference was lost")
	}
	if _, err := client.CreatePublisherRun(t.Context(), "url", "retry", "publisher-access", "signed-proof", nil, controlv1.HTTPProtection{}, "sjc"); err == nil || len(bodies) != 3 {
		t.Fatal("generic location reached the server")
	}
	for _, invalid := range []*trafficlimits.Selection{
		{Rate: new(0)},
		{Connections: new(0)},
		{RatePer: new("invalid")},
		{TotalUploadBytes: new(int64(-1))},
	} {
		if _, err := client.CreatePublisherRun(t.Context(), "url", "retry", "publisher-access", "signed-proof", invalid, controlv1.HTTPProtection{}); err == nil || len(bodies) != 3 {
			t.Fatal("invalid selection reached the server")
		}
	}
}
