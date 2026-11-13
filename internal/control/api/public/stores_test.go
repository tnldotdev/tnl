package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOptionalStoreMustBeExplicitlyWired(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "omitted", true: "provided"}[enabled], func(t *testing.T) {
			backend := &publisherPolicyStoreFixture{}
			stores := Stores{PublicURLs: backend, Certificates: backend, Admin: backend}
			if enabled {
				stores.VisitorPolicy = backend
			}
			h, err := NewHandler(Config{}, stores, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"resource":{"kind":"public_url","id":"url_` + strings.Repeat("A", 22) + `"},"run_id":"run","run_number":"1","after_revision":"0"}`
			request := httptest.NewRequest(http.MethodPost, "/v1/visitor-policy", strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer fixture-run-secret")
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if enabled {
				if response.Code != http.StatusOK || backend.calls != 1 {
					t.Fatal("explicit visitor policy store was not used", response.Code, backend.calls)
				}
			} else if response.Code != http.StatusServiceUnavailable || backend.calls != 0 {
				t.Fatal("another store implicitly enabled visitor policy", response.Code, backend.calls)
			}
		})
	}
}
