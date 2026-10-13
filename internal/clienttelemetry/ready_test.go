package clienttelemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientserver"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestGoAdHocReadyReportsOnlyCoarseFieldsOnce(t *testing.T) {
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	received := make(chan []byte, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		received <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	reporter := readyReporter{receiver: server.URL, client: server.Client()}
	id, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if !reporter.queue(t.Context(), state, clientserver.DefaultURL, id) || reporter.queue(t.Context(), state, clientserver.DefaultURL, id) {
		t.Fatal("ad-hoc invocation did not deduplicate its ready event")
	}
	select {
	case body := <-received:
		var batch struct {
			Events []struct {
				Name    string          `json:"name"`
				Payload json.RawMessage `json:"payload"`
			} `json:"events"`
		}
		if err := json.Unmarshal(body, &batch); err != nil || len(batch.Events) != 1 || batch.Events[0].Name != "tunnel.ready" {
			t.Fatalf("ready batch is invalid: %v", err)
		}
		var payload map[string]string
		if err := json.Unmarshal(batch.Events[0].Payload, &payload); err != nil || len(payload) != 4 ||
			payload["entry_mode"] != "ad_hoc" || payload["server_kind"] != "hosted" ||
			payload["source"] != "publish" || payload["publish_mode"] != "app" {
			t.Fatalf("ready payload = %+v, error=%v", payload, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ready telemetry was not flushed")
	}
	t.Setenv("TNL_NO_TELEMETRY", "1")
	other, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if reporter.queue(t.Context(), state, clientserver.DefaultURL, other) {
		t.Fatal("disabled ad-hoc SDK telemetry was queued")
	}
}
