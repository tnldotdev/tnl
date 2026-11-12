package authority

import (
	"encoding/json"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestEnvironmentVisitorSessionRequiresDefiningWireFields(t *testing.T) {
	payload := []byte(`{"id":"session","credential":"credential","subject":{"kind":"workload_session","workload_session_id":"session"},"service_ids":[],"renewal_sequence":0,"lease_expires_at":"2026-12-01T00:01:00Z","identity_expires_at":"2026-12-01T00:02:00Z","renew_after":"2026-12-01T00:00:30Z"}`)
	var original map[string]json.RawMessage
	if err := json.Unmarshal(payload, &original); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEnvironmentVisitorSession(payload); err != nil {
		t.Fatal("valid empty current service snapshot rejected", err)
	}
	for name := range original {
		t.Run(name, func(t *testing.T) {
			for _, null := range []bool{false, true} {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(payload, &fields); err != nil {
					t.Fatal(err)
				}
				if null {
					fields[name] = json.RawMessage("null")
				} else {
					delete(fields, name)
				}
				body, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := decodeEnvironmentVisitorSession(body); err == nil {
					t.Fatal("missing or null required field accepted", null)
				} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
					t.Fatal("wire failure lost its diagnostic", err)
				}
			}
		})
	}
	// provider metadata is no longer a session wire shape, including explicit
	// null. generic response decoding must not silently preserve the old model.
	original["github"] = json.RawMessage("null")
	body, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEnvironmentVisitorSession(body); err == nil {
		t.Fatal("retired execution metadata accepted")
	}
}
