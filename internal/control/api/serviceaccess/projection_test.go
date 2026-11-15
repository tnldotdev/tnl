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
