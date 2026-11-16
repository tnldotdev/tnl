package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

type publisherProtocolsStore struct {
	PublisherIdentityStore
	calls     int
	protocols []string
}

func (s *publisherProtocolsStore) IdentityContext(context.Context, string) (controlstate.IdentityContext, error) {
	return controlstate.IdentityContext{Memberships: []controlstate.Membership{{ID: "membership", TeamID: "team_1", PolicyRevision: 9}}}, nil
}

func (s *publisherProtocolsStore) IssuePublisherEnrollment(_ context.Context, r controlstate.CreatePublisherEnrollmentRequest) (controlstate.PublisherEnrollment, error) {
	if r.EditorID != testControlReadPrincipal().identityID || r.EditorMembershipID != "membership" || r.PolicyRevision != 9 {
		panic("protocol input replaced current issuer authority")
	}
	s.calls++
	s.protocols = r.Protocols
	return controlstate.PublisherEnrollment{ID: "enrollment", Key: "secret", Scope: r.Scope, Until: r.Now.Add(time.Minute), Protocols: []string{"http", "postgres"}}, nil
}

func (s *publisherProtocolsStore) AuthorizePublisherManagement(context.Context, string, string, string) error {
	return nil
}

func (s *publisherProtocolsStore) CreatePublisherGrant(_ context.Context, r controlstate.CreatePublisherGrantRequest) (string, error) {
	if r.EditorID != testControlReadPrincipal().identityID || r.EditorMembershipID != "membership" || r.PolicyRevision != 9 {
		panic("protocol input replaced current issuer authority")
	}
	s.calls++
	s.protocols = r.Protocols
	return "grant", nil
}

func (s *publisherProtocolsStore) PublisherIdentityRecord(context.Context, string, string) (controlstate.PublisherRecord, error) {
	return controlstate.PublisherRecord{Grants: []controlstatedb.ControlPublisherGrant{{
		ID: "grant", Kind: "service", TeamID: pgtype.Text{String: "team_1", Valid: true},
		ServiceID: pgtype.Text{String: "svc_aaaaaaaaaaaaaaaaaaaaaa", Valid: true}, Protocols: []string{"http", "postgres"},
	}}}, nil
}

func TestPublisherProtocolWireCapturesInputAndProjectsActualStoredSet(t *testing.T) {
	for _, operation := range []string{"enrollment", "grant"} {
		for _, test := range []struct {
			name, field string
			want        []string
			valid       bool
		}{
			{"issuer default", "", nil, true},
			{"explicit", `,"protocols":["postgres","http"]`, []string{"postgres", "http"}, true},
			{"null", `,"protocols":null`, nil, false},
			{"empty", `,"protocols":[]`, nil, false},
			{"duplicate", `,"protocols":["http","http"]`, nil, false},
			{"unknown", `,"protocols":["ssh"]`, nil, false},
			{"wildcard", `,"protocols":["*"]`, nil, false},
			{"wrong type", `,"protocols":"http"`, nil, false},
			{"unknown field", `,"allowed_protocols":["http"]`, nil, false},
		} {
			t.Run(operation+"/"+test.name, func(t *testing.T) {
				store := &publisherProtocolsStore{}
				h := &handler{dependencies: Stores{PublisherIdentities: store}, authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
				fields := `"team_id":"team_1","service_id":"svc_aaaaaaaaaaaaaaaaaaaaaa"`
				if operation == "enrollment" {
					fields += `,"name":"publisher","kind":"installed"`
				}
				r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{"+fields+test.field+"}"))
				r.Header.Set("Authorization", "Bearer access-token")
				w := httptest.NewRecorder()
				if operation == "enrollment" {
					h.CreatePublisherEnrollment(w, r)
				} else {
					h.CreatePublisherGrant(w, r, "publisher")
				}
				if !test.valid {
					if w.Code != 400 || store.calls != 0 {
						t.Fatal("invalid capability reached issuance", w.Code, store.calls, w.Body.String())
					}
					return
				}
				if w.Code != 201 || store.calls != 1 || !reflect.DeepEqual(store.protocols, test.want) {
					t.Fatal("issuance changed the explicit request or default selection", w.Code, store.protocols, w.Body.String())
				}
				var result struct {
					Protocols []string `json:"protocols"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || !reflect.DeepEqual(result.Protocols, []string{"http", "postgres"}) {
					t.Fatal("response echoed input instead of actual stored capability", result, err)
				}
			})
		}
	}
}

func TestNamespaceGrantProjectionOmitsExactProtocolCapability(t *testing.T) {
	value := publisherGrantResponse(controlstatedb.ControlPublisherGrant{Kind: "namespace", TeamID: pgtype.Text{String: "team", Valid: true}})
	if value.Protocols != nil {
		t.Fatal("namespace grant acquired exact protocol capability")
	}
}
