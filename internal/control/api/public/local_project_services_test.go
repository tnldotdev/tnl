package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type localProjectVisitorStore struct {
	LocalProjectStore
	request controlstate.GetLocalProjectServiceRequest
	err     error
	calls   int
}

func (s *localProjectVisitorStore) GetLocalProjectService(_ context.Context, r controlstate.GetLocalProjectServiceRequest) (controlstate.LocalProjectService, error) {
	s.calls++
	s.request = r
	if s.err != nil {
		return controlstate.LocalProjectService{}, s.err
	}
	return controlstate.LocalProjectService{Service: r.Service, WorktreeKey: r.WorktreeKey, ServiceID: "svc_exact", Metadata: &controlstate.ServiceMetadata{Protocol: "http", TrustRevision: 1}}, nil
}

type localProjectRealizationStore struct {
	LocalProjectStore
	request controlstate.RealizeLocalProjectServiceRequest
	calls   int
}

func (s *localProjectRealizationStore) RealizeLocalProjectService(_ context.Context, r controlstate.RealizeLocalProjectServiceRequest) (controlstate.LocalProjectService, error) {
	s.calls++
	s.request = r
	return controlstate.LocalProjectService{Service: r.Service, WorktreeKey: r.WorktreeKey, ServiceID: "svc_exact"}, nil
}

func TestRealizeLocalProjectServiceUsesOneConfigurationSelection(t *testing.T) {
	for _, extra := range []string{"", "domain_id", "public_url_id"} {
		t.Run("root-field-"+extra, func(t *testing.T) {
			store := &localProjectRealizationStore{}
			h := &handler{dependencies: Stores{LocalProjects: store}, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
			body := map[string]any{
				"team_id": "team_1", "source_fingerprint": strings.Repeat("a", 64),
				"worktree_key": "checkout-a", "configuration": map[string]any{
					"target": "app", "domain_id": "dom_selected", "hostname": "app.example.test",
				},
			}
			if extra != "" {
				body[extra] = "another-selection"
			}
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/v1/projects/shop/local-services/orders", strings.NewReader(string(encoded)))
			r.Header.Set("Authorization", "Bearer manager-token")
			w := httptest.NewRecorder()
			h.RealizeLocalProjectService(w, r, "shop", "orders")
			if extra != "" {
				if w.Code != http.StatusBadRequest || store.calls != 0 {
					t.Fatal("retired root selection reached realization", w.Code, store.calls)
				}
				return
			}
			if w.Code != http.StatusOK || store.calls != 1 || store.request.Configuration.DomainID != "dom_selected" ||
				store.request.Configuration.Hostname != "app.example.test" || store.request.Service != "orders" ||
				store.request.ProjectKey != "shop" || store.request.ActorID != "identity_1" {
				t.Fatal("direct configuration lost its selected endpoint or authenticated project", w.Code, store.request)
			}
		})
	}
}

func TestGetLocalProjectServiceUsesVisitorAuthorizationAndSafeResponse(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		auth   bool
	}{
		{"ordinary visitor", nil, 200, true},
		{"unsigned", nil, 401, false},
		{"unavailable or unauthorized", controlstate.ErrServiceAccess, 404, true},
		{"source collision", controlstate.ErrProjectSourceConflict, 409, true},
		{"invalid scope", controlstate.ErrProjectConfigurationInvalid, 400, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &localProjectVisitorStore{err: test.err}
			principal := testPublicURLReadPrincipal()
			principal.teamIDs = nil // a direct visitor grant does not require team management.
			h := &handler{store: store, dependencies: Stores{LocalProjects: store}, authorizer: &recordingAuthorizer{principal: principal}}
			r := httptest.NewRequest(http.MethodGet, "/v1/projects/shop/local-services/orders", nil)
			if test.auth {
				r.Header.Set("Authorization", "Bearer visitor-token")
			}
			w := httptest.NewRecorder()
			params := controlv1.GetLocalProjectServiceParams{TeamId: "team_one", SourceFingerprint: strings.Repeat("a", 64), WorktreeKey: "checkout-a"}
			h.GetLocalProjectService(w, r, "shop", "orders", params)
			if w.Code != test.status || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("lookup = %d %s", w.Code, w.Body.String())
			}
			if test.auth {
				got := store.request
				if store.calls != 1 || got.TeamID != params.TeamId || got.ProjectKey != "shop" || got.Service != "orders" || got.SourceFingerprint != params.SourceFingerprint || got.WorktreeKey != params.WorktreeKey || got.ActorID != principal.identityID || got.Now.IsZero() {
					t.Fatal("lookup lost authenticated exact scope", got)
				}
			} else if store.calls != 0 {
				t.Fatal("unsigned caller reached provenance storage")
			}
			if test.status == 200 {
				var response controlv1.LocalProjectService
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.ServiceId != "svc_exact" || response.Metadata == nil || response.Metadata.Protocol != controlv1.ServiceProtocolHTTP {
					t.Fatal("response lost authoritative safe metadata", response, err)
				}
			} else if strings.Contains(w.Body.String(), "manager") || strings.Contains(w.Body.String(), "svc_exact") {
				t.Fatal("visitor error leaked identity or required management", w.Body.String())
			}
		})
	}
}
