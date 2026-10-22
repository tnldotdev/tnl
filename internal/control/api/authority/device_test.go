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
	(&handler{}).deviceError(w, fmt.Errorf("%w: provider-secret", oidc.ErrUnavailable))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "identity provider is unavailable") || strings.Contains(w.Body.String(), "provider-secret") {
		t.Fatalf("unsafe provider failure: %d %s", w.Code, w.Body)
	}
}
