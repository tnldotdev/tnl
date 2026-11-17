package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceReservationStore struct {
	ServiceStore
	calls     int
	placement controlstate.ServicePlacement
	recovered bool
}

func (s *serviceReservationStore) CreateServiceAt(_ context.Context, team, actor, name, key string, placement controlstate.ServicePlacement, _ time.Time, metadata controlstate.ServiceMetadata, configuration *controlstate.ProjectServiceConfiguration) (controlstate.ServiceRecord, error) {
	if team != "team_1" || actor != testControlReadPrincipal().identityID || name != "preview" || key != "operation" ||
		metadata.Protocol != "http" || configuration == nil || configuration.Target != "app" {
		panic("reservation changed the authenticated actor or canonical creation intent")
	}
	s.calls++
	s.placement = placement
	return controlstate.ServiceRecord{ID: "svc_aaaaaaaaaaaaaaaaaaaaaa", TeamID: team, Name: name,
		ServiceMetadata: metadata, Recovered: s.recovered}, nil
}

func TestServiceReservationWireUsesCanonicalCreateAndRecoveryStatus(t *testing.T) {
	for _, test := range []struct {
		name, field string
		recovered   bool
		status      int
		calls       int
		reserve     bool
	}{
		{"ordinary", "", false, 201, 1, false},
		{"explicit ordinary", `,"reserve":false`, false, 201, 1, false},
		{"create", `,"reserve":true`, false, 201, 1, true},
		{"recover", `,"reserve":true`, true, 200, 1, true},
		{"null", `,"reserve":null`, false, 400, 0, false},
		{"string", `,"reserve":"true"`, false, 400, 0, false},
		{"number", `,"reserve":1`, false, 400, 0, false},
		{"scope override", `,"reserve":true,"reservation_scope":"shared"`, false, 400, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &serviceReservationStore{recovered: test.recovered}
			h := &handler{dependencies: Stores{Services: store}, authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
			body := `{"team_id":"team_1","name":"preview","protocol":"http","placement":{"domain_id":"dom_aaaaaaaaaaaaaaaaaaaaaa","hostname":"preview.member.example.test"},"configuration":{"target":"app"}` + test.field + `}`
			r := httptest.NewRequest(http.MethodPost, "/v1/services", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer access-token")
			r.Header.Set("Idempotency-Key", "operation")
			w := httptest.NewRecorder()
			h.CreateService(w, r, controlv1.CreateServiceParams{})
			if w.Code != test.status || store.calls != test.calls || store.placement.Reserve != test.reserve {
				t.Fatal("reservation changed creation dispatch or recovery status", w.Code, store.calls, w.Body.String())
			}
			if store.calls != 0 {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
					t.Fatal(err)
				}
				if _, present := fields["reserve"]; present {
					t.Fatal("request-only reservation intent became saved service state")
				}
				if store.placement.DomainID != "dom_aaaaaaaaaaaaaaaaaaaaaa" || store.placement.Hostname != "preview.member.example.test" {
					t.Fatal("canonical creation lost its exact placement", store.placement)
				}
			}
		})
	}
}
