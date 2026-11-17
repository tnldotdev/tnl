package authority

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/browserpage"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestDeviceProviderFailureIsOwnedAndSafe(t *testing.T) {
	w := httptest.NewRecorder()
	(&handler{}).deviceError(t.Context(), w, fmt.Errorf("%w: provider-secret", oidc.ErrUnavailable))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "identity provider is unavailable") || strings.Contains(w.Body.String(), "provider-secret") {
		t.Fatalf("unsafe provider failure: %d %s", w.Code, w.Body)
	}
}

type devicePageStore struct {
	Store
	approved bool
}

func (*devicePageStore) ReadDeviceBrowser(context.Context, string, time.Time) (controlstate.DeviceLogin, error) {
	return controlstate.DeviceLogin{}, nil
}

func (s *devicePageStore) ApproveDeviceLogin(_ context.Context, code string, binding []byte, _ string, _, _ time.Duration, _ time.Time) error {
	if code != "ABCDEF-GHIJKL" || string(binding) != strings.Repeat("b", 32) {
		return controlstate.ErrDeviceLogin
	}
	s.approved = true
	return nil
}

func TestDeviceBrowserPagesAndSuccess(t *testing.T) {
	store := &devicePageStore{}
	h := &handler{config: Config{ControlURL: "https://control.example.test"}, oidc: &oidc.Server{}, store: store}
	team := httptest.NewRecorder()
	h.BeginDeviceBrowser(team, httptest.NewRequest(http.MethodGet, "/v1/auth/device/approve?code=ABCDEF-GHIJKL", nil), authorityv1.BeginDeviceBrowserParams{})
	if team.Code != http.StatusOK || team.Header().Get("Content-Security-Policy") != browserpage.FormSecurityPolicy ||
		!strings.Contains(team.Body.String(), `name="code" value="ABCDEF-GHIJKL"`) ||
		!strings.Contains(team.Body.String(), `aria-describedby="team-hint"`) ||
		!strings.Contains(team.Body.String(), "data:font/woff2;base64,") {
		t.Fatal("team selection lost its shared shell, form binding, or accessible label")
	}
	approval := approvalPage.HTML(browserpage.Page{Title: "approve tnl login", Content: struct{ Name, Code, Binding string }{`Sam <script>bad</script>`, "ABCDEF-GHIJKL", "binding"}})
	if strings.Contains(approval, "<script>") || !strings.Contains(approval, "Sam &lt;script&gt;bad&lt;/script&gt;") ||
		!strings.Contains(approval, `name="binding" value="binding"`) ||
		!strings.Contains(approval, `<strong class="code">ABCDEF-GHIJKL</strong>`) {
		t.Fatal("approval page lost escaping or confirmation fields")
	}
	binding := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	for _, accept := range []string{"", "text/html"} {
		store.approved = false
		request := httptest.NewRequest(http.MethodPost, "https://control.example.test/v1/auth/device/approve", strings.NewReader(url.Values{"code": {"ABCDEF-GHIJKL"}, "binding": {binding}}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Accept", accept)
		request.AddCookie(&http.Cookie{Name: deviceCookie, Value: binding})
		response := httptest.NewRecorder()
		h.ApproveDeviceBrowser(response, request)
		cookies := response.Result().Cookies()
		if response.Code != http.StatusOK || !store.approved || len(cookies) != 1 || cookies[0].Name != deviceCookie ||
			cookies[0].MaxAge != -1 || !cookies[0].Secure || !cookies[0].HttpOnly {
			t.Fatal("approval changed its store call or cookie cleanup", response.Code, response.Header())
		}
		if accept == "" {
			if response.Body.String() != "login approved. return to your terminal.\n" || response.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
				t.Fatal("non-browser approval response changed")
			}
		} else if !strings.Contains(response.Body.String(), "<h1>login approved</h1>") ||
			response.Header().Get("Content-Security-Policy") != browserpage.ContentSecurityPolicy {
			t.Fatal("browser approval success is not styled")
		}
	}
}

func TestDeviceErrorsStyleBrowserEndpointsOnly(t *testing.T) {
	h := testHandler(t, Config{}, nil)
	for _, test := range []struct {
		method, path, contentType string
	}{
		{http.MethodGet, "/v1/auth/device/approve?code=ABCDEF-GHIJKL", "text/html; charset=utf-8"},
		{http.MethodGet, "/v1/auth/device/callback?code=code&state=state", "text/html; charset=utf-8"},
		{http.MethodPost, "/v1/auth/device/approve", "text/html; charset=utf-8"},
		{http.MethodPost, "/v1/auth/device", "application/problem+json"},
		{http.MethodPost, "/v1/auth/device/poll", "application/problem+json"},
		{http.MethodPost, "/v1/auth/device/cancel", "application/problem+json"},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader(`{}`))
		request.Header.Set("Accept", "text/html")
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable || response.Header().Get("Content-Type") != test.contentType {
			t.Fatalf("%s %s = %d %s", test.method, test.path, response.Code, response.Header().Get("Content-Type"))
		}
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
