package serviceaccess

import (
	"encoding/json"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func TestServiceProjectionsKeepActualOwnerAndFixedExpiry(t *testing.T) {
	until := time.Now().UTC().Add(time.Hour)
	for _, owner := range []struct {
		field, other, value string
	}{
		{"team_id", "guest_id", "team"},
		{"guest_id", "team_id", "gst_1111111111111111111111"},
	} {
		record := controlstate.ServiceRecord{
			ID: "svc_1111111111111111111111", Name: "demo", Enabled: true,
			Ephemeral: true, ExpiresAt: &until,
			ServiceMetadata: controlstate.ServiceMetadata{Protocol: "http", TrustRevision: 1},
		}
		if owner.field == "team_id" {
			record.TeamID = owner.value
		} else {
			record.GuestID = owner.value
		}
		service := Service(record)
		if service.ExpiresAt == nil || !service.ExpiresAt.Equal(until) {
			t.Fatal("service projection changed its fixed expiry")
		}
		for _, projection := range []any{service, Summary(record)} {
			encoded, err := json.Marshal(projection)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			var actual string
			if err := json.Unmarshal(fields[owner.field], &actual); err != nil || actual != owner.value || fields[owner.other] != nil {
				t.Fatal("projection lost its real owner or fabricated another", string(encoded))
			}
		}
	}
}

func TestServiceProjectionsPreserveSavedPostQuantumPolicy(t *testing.T) {
	for _, required := range []bool{false, true} {
		record := controlstate.ServiceRecord{RequirePostQuantum: required}
		for _, projection := range []any{Service(record), Summary(record)} {
			encoded, err := json.Marshal(projection)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			var actual bool
			if err := json.Unmarshal(fields["require_post_quantum"], &actual); err != nil || actual != required {
				t.Fatalf("projection lost saved post-quantum policy %t: %s", required, encoded)
			}
		}
	}
}

func TestServiceProjectionKeepsBodyTimeoutPublisherOnly(t *testing.T) {
	record := controlstate.ServiceRecord{HTTPRequestBodyIdleTimeout: new("45s")}
	if service := Service(record); service.HttpRequestBodyIdleTimeout == nil || *service.HttpRequestBodyIdleTimeout != "45s" {
		t.Fatal("publisher projection lost the configured HTTP body timeout")
	}
	encoded, err := json.Marshal(Summary(record))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil || fields["http_request_body_idle_timeout"] != nil {
		t.Fatal("inventory exposed publisher-only HTTP settings", string(encoded), err)
	}
}
