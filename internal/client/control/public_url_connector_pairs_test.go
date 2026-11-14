package control

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublicURLConnectorPublisherAdaptersKeepExactTokenAndDecimalNumber(t *testing.T) {
	const run, pair = "pr_1234567890123456789012", "cpp_1234567890123456789012"
	number := uint64(math.MaxInt64)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer exact-publish-run" {
			t.Error("publisher connector call borrowed a control session")
		}
		if r.URL.Path == "/v1/publish-runs/"+run+"/connector-peer-pairs" {
			if r.Method != http.MethodGet || r.URL.Query().Get("publish_run_number") != "9223372036854775807" || r.URL.Query().Get("after") != pair {
				t.Error("candidate adapter lost exact decimal number or cursor")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[]}`))
			return
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if string(body["publish_run_number"]) != `"9223372036854775807"` || body["run_number"] != nil || body["service_run_id"] != nil {
			t.Error("publisher adapter changed typed publication number")
		}
		switch r.URL.Path {
		case "/v1/publish-runs/" + run + "/connector-peer-pairs/" + pair + "/delivery":
			if string(body["delivery_generation"]) != `"9007199254740993"` {
				t.Error("publisher adapter rounded binding revision")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"pair_id":"` + pair + `","publish_run_number":"9223372036854775807"}`))
		case "/v1/publish-runs/" + run + "/connector-peer-pairs/" + pair + "/prepared":
			if body["prepared"] == nil {
				t.Error("publisher adapter lost exact installation report")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("unexpected public URL connector publisher path")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "must-not-use-control-session")
	if err != nil {
		t.Fatal(err)
	}
	token := credentials.PublishRunToken("exact-publish-run")
	if _, err := client.ListPublicURLConnectorPeerPairs(t.Context(), run, number, pair, token); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeliverPublicURLConnectorPeerPair(t.Context(), run, number, pair, 9007199254740993, token); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfirmPublicURLConnectorPeerPairPrepared(t.Context(), run, number, pair, controlv1.ConnectorPeerPairPrepared{}, token); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []uint64{0, math.MaxUint64} {
		if _, err := client.ListPublicURLConnectorPeerPairs(context.Background(), run, invalid, "", token); err == nil {
			t.Fatal("out-of-range public run number reached the network")
		}
	}
	if calls != 3 {
		t.Fatal("invalid publisher credentials caused an HTTP call")
	}
}
