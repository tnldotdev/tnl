package controlv1_test

import (
	"encoding/json"
	"testing"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestOwnershipWireOmitsAbsentOwner(t *testing.T) {
	const team = "team"
	const guest = "gst_gggggggggggggggggggggg"
	for _, test := range []struct {
		name        string
		team, guest any
	}{
		{"service", controlv1.Service{TeamId: team}, controlv1.Service{GuestId: guest}},
		{"summary", controlv1.ServiceSummary{TeamId: team}, controlv1.ServiceSummary{GuestId: guest}},
		{"preparation", controlv1.ServiceRunPreparation{TeamId: team}, controlv1.ServiceRunPreparation{GuestId: guest}},
		{"preview", controlv1.Preview{TeamId: team}, controlv1.Preview{GuestId: guest}},
		{"share", controlv1.Share{TeamId: team}, controlv1.Share{GuestId: guest}},
		{"publisher", controlv1.PublisherIdentity{TeamId: team}, controlv1.PublisherIdentity{GuestId: guest}},
		{"grant", controlv1.PublisherGrant{TeamId: team}, controlv1.PublisherGrant{GuestId: guest}},
		{"public enrollment", controlv1.PublisherEnrollmentResult{TeamId: team}, controlv1.PublisherEnrollmentResult{GuestId: guest}},
		{"authority enrollment", authorityv1.PublisherEnrollmentResult{TeamId: team}, authorityv1.PublisherEnrollmentResult{GuestId: guest}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, owner := range []struct {
				model        any
				want, absent string
				value        string
			}{
				{test.team, "team_id", "guest_id", team},
				{test.guest, "guest_id", "team_id", guest},
			} {
				t.Run(owner.want, func(t *testing.T) {
					data, err := json.Marshal(owner.model)
					if err != nil {
						t.Fatal(err)
					}
					var fields map[string]json.RawMessage
					if err = json.Unmarshal(data, &fields); err != nil {
						t.Fatal(err)
					}
					if _, exists := fields[owner.absent]; exists {
						t.Fatalf("absent %s was emitted: %s", owner.absent, data)
					}
					var got string
					if err = json.Unmarshal(fields[owner.want], &got); err != nil || got != owner.value {
						t.Fatalf("%s = %q, %v: %s", owner.want, got, err, data)
					}
				})
			}
		})
	}
}
