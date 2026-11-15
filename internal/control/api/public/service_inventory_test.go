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

type inventoryContextKey struct{}

type serviceInventoryStore struct {
	ServiceStore
	path  controlv1.ServiceAccessPath
	calls int
}

func (s *serviceInventoryStore) ListAvailableServices(ctx context.Context, identity, cursor string, path controlv1.ServiceAccessPath, _ time.Time) ([]controlstate.ServiceInventory, string, error) {
	if ctx.Value(inventoryContextKey{}) != "caller-context" || identity != testControlReadPrincipal().identityID || cursor != "svc_aaaaaaaaaaaaaaaaaaaaaa" {
		panic("visitor inventory changed the authenticated caller context or cursor")
	}
	s.calls++
	s.path = path
	reason := "identity_grant"
	if path == controlv1.ServiceAccessPathPublicEndpoint {
		reason = "preview_team"
	}
	return []controlstate.ServiceInventory{{
		ID: "svc_bbbbbbbbbbbbbbbbbbbbbb", TeamID: "tm_aaaaaaaaaaaaaaaaaaaaaa", TeamName: "stored-team-name", Name: "web", VisitorAccess: reason,
		ServiceMetadata: controlstate.ServiceMetadata{Protocol: "http", TrustRevision: 4,
			Endpoint: &controlstate.ServiceEndpoint{Hostname: "web.example.test", Port: 443, Public: true},
			TLS:      &controlstate.ServiceTargetTLS{Hostname: "private-target", PEM: "private-ca-material"}},
	}}, "svc_bbbbbbbbbbbbbbbbbbbbbb", nil
}

func TestServiceInventoryHTTPPathUsesSameDefiningSummaryWithoutPrivateFacts(t *testing.T) {
	for _, path := range []*controlv1.ServiceAccessPath{nil, new(controlv1.ServiceAccessPathPublicEndpoint), new(controlv1.ServiceAccessPath("manager"))} {
		name := "default connector"
		if path != nil {
			name = string(*path)
		}
		t.Run(name, func(t *testing.T) {
			store := &serviceInventoryStore{}
			h := &handler{dependencies: Stores{Services: store}, authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
			request := httptest.NewRequest(http.MethodGet, "/v1/visitor/services", nil)
			request = request.WithContext(context.WithValue(request.Context(), inventoryContextKey{}, "caller-context"))
			request.Header.Set("Authorization", "Bearer control-access")
			response := httptest.NewRecorder()
			cursor := "svc_aaaaaaaaaaaaaaaaaaaaaa"
			h.ListAvailableServices(response, request, controlv1.ListAvailableServicesParams{Cursor: &cursor, AccessPath: path})
			if path != nil && !path.Valid() {
				if response.Code != http.StatusBadRequest || store.calls != 0 {
					t.Fatal("invalid path reached service authority", response.Code, store.calls)
				}
				return
			}
			expected := controlv1.ServiceAccessPathConnector
			if path != nil {
				expected = *path
			}
			if response.Code != http.StatusOK || store.calls != 1 || store.path != expected {
				t.Fatal("HTTP inventory changed access-path defaults or selection", response.Code, store.calls, store.path)
			}
			var page controlv1.ServicePage
			if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			if len(page.Services) != 1 || page.Services[0].TeamName != "stored-team-name" || page.Services[0].VisitorAccess == "" || page.NextCursor == nil || *page.NextCursor != "svc_bbbbbbbbbbbbbbbbbbbbbb" {
				t.Fatal("visitor summary lost actual identity, team, permission, or paging facts")
			}
			for _, secret := range []string{"private-target", "private-ca-material", "target_tls", "http_limits", "endpoint_revision", "ephemeral", "require_post_quantum"} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatal("visitor inventory exposed or synthesized a publisher-only/full-service field", secret)
				}
			}
		})
	}
}
