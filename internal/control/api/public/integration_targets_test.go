package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPurposeRejectsTargetOnCreateAndUpdate(t *testing.T) {
	for _, purpose := range []controlstate.PublicURLPurpose{controlstate.PublicURLPurposeOAuth, controlstate.PublicURLPurposeWebhooks} {
		t.Run(string(purpose), func(t *testing.T) {
			for _, target := range []string{"http://127.0.0.1:3000", "invalid"} {
				store := &publicURLCreationStore{}
				body := `{"team_id":"team_1","domain_id":"domain_1","canonical_hostname":"integration.example","public_url_scope":"shared","purpose":"` + string(purpose) + `","target":"` + target + `"}`
				response := httptest.NewRecorder()
				(&handler{store: store}).CreatePublicURL(response, httptest.NewRequest(http.MethodPost, "/v1/public-urls", strings.NewReader(body)), controlv1.CreatePublicURLParams{})
				if response.Code != http.StatusBadRequest || len(store.requests) != 0 {
					t.Fatalf("create integration with target = %d: %s", response.Code, response.Body.String())
				}
				mutation := &publicURLMutationStoreStub{publicURL: controlstate.PublicURL{ID: "public_url_1", TeamID: "team_1", Purpose: purpose, ServiceProtocol: controlstate.PublicURLServiceHTTP, MutationRevision: 1}}
				request := httptest.NewRequest(http.MethodPatch, "/v1/public-urls/public_url_1", strings.NewReader(`{"expected_mutation_revision":"1","target":"`+target+`","allowed_ip_prefixes":[]}`))
				request.Header.Set("Authorization", "Bearer session")
				response = httptest.NewRecorder()
				authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal()}
				(&handler{store: mutation, authorizer: authorizer}).UpdatePublicURL(response, request, "public_url_1")
				if response.Code != http.StatusBadRequest || mutation.updates != 0 || len(authorizer.requests) != 0 {
					t.Fatalf("update integration with target = %d: %s", response.Code, response.Body.String())
				}
				mutation.publicURL.TeamID = "team_other"
				request = httptest.NewRequest(http.MethodPatch, "/v1/public-urls/public_url_1", strings.NewReader(`{"expected_mutation_revision":"1","target":"http://127.0.0.1:3000","allowed_ip_prefixes":[]}`))
				request.Header.Set("Authorization", "Bearer session")
				response = httptest.NewRecorder()
				(&handler{store: mutation, authorizer: authorizer}).UpdatePublicURL(response, request, "public_url_1")
				if response.Code != http.StatusNotFound || mutation.updates != 0 || len(authorizer.requests) != 0 {
					t.Fatalf("integration target rules revealed a different team's URL = %d: %s", response.Code, response.Body.String())
				}
			}
		})
	}
}
