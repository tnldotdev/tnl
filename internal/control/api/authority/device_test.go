package authority

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/oidc"
)

func TestDeviceProviderFailureIsOwnedAndSafe(t *testing.T) {
	w := httptest.NewRecorder()
	(&handler{}).deviceError(t.Context(), w, fmt.Errorf("%w: provider-secret", oidc.ErrUnavailable))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "identity provider is unavailable") || strings.Contains(w.Body.String(), "provider-secret") {
		t.Fatalf("unsafe provider failure: %d %s", w.Code, w.Body)
	}
}

func TestDeviceLoginStillRequiresConfiguredOIDC(t *testing.T) {
	// any storage call panics; the disabled feature must fail before storage.
	h := testHandler(t, Config{}, struct{ Store }{})
	for _, path := range []string{"/v1/auth/device", "/v1/auth/device/poll", "/v1/auth/device/cancel"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"code":"unavailable"`) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unconfigured device login %s = %d %s", path, w.Code, w.Body)
		}
	}
}
