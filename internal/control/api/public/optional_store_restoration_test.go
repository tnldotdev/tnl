package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOptionalStoreRestorationDoesNotInferVisitorPolicyFromAdmin(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "omitted", true: "provided"}[explicit], func(t *testing.T) {
			backend := &publisherPolicyStoreFixture{AdminStore: &adminStoreStub{}}
			stores := Stores{Admin: backend}
			if explicit {
				stores.VisitorPolicy = backend
			}
			handler, err := NewHandler(Config{}, stores, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"resource":{"kind":"service","id":"svc_` + strings.Repeat("A", 22) + `"},"run_id":"srun_` + strings.Repeat("R", 22) + `","run_number":"1","after_revision":"0"}`
			request := httptest.NewRequest(http.MethodPost, "/v1/visitor-policy", strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer fixture-run-secret")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if explicit {
				if response.Code != http.StatusOK || backend.calls != 1 {
					t.Fatal("explicit visitor policy store was not used", response.Code, backend.calls)
				}
			} else if response.Code != http.StatusServiceUnavailable || backend.calls != 0 {
				t.Fatal("admin backend implicitly enabled visitor policy", response.Code, backend.calls)
			}
		})
	}
}
