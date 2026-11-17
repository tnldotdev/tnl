package public

import (
	"net/http"
	"net/http/httptest"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceDeleteRequiresOneExplicitCondition(t *testing.T) {
	for _, query := range []string{
		"",
		"?expected_service_revision=7&unconditional_delete=true",
		"?expected_service_revision=0",
		"?expected_service_revision=0&unconditional_delete=true",
		"?expected_service_revision=-1",
		"?expected_service_revision=01",
		"?expected_service_revision=%2B1",
		"?expected_service_revision=9223372036854775808",
		"?expected_service_revision=service-id",
		"?unconditional_delete=false",
		"?unconditional_delete=1",
		"?unconditional_delete=TRUE",
		"?unconditional_delete=",
		"?expected_service_revision=7&expected_service_revision=8",
		"?unconditional_delete=true&unconditional_delete=true",
	} {
		t.Run(query, func(t *testing.T) {
			store := &serviceMutationAuthenticationStore{}
			h := &handler{dependencies: Stores{Services: store}, authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()},
				guests: &guestCreationStoreStub{}}
			r := httptest.NewRequest(http.MethodDelete, "/v1/services/svc_aaaaaaaaaaaaaaaaaaaaaa"+query, nil)
			r.Header.Set("Authorization", "Bearer exact-access-token")
			w := httptest.NewRecorder()
			controlv1.HandlerWithOptions(h, controlv1.StdHTTPServerOptions{}).ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || store.calls != 0 {
				t.Fatal("invalid ordinary deletion reached service state", w.Code, store.calls, w.Body.String())
			}
		})
	}
}
