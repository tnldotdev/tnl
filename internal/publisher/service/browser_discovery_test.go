package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPBrowserDiscoveryCapturesAvailabilityBeforePolicy(t *testing.T) {
	failure := errors.New("discovery unavailable")
	for _, test := range []struct {
		name      string
		available *bool
		captured  *bool
		failure   error
		private   bool
	}{
		{name: "available", available: new(true)},
		{name: "disabled", available: new(false)},
		{name: "omitted"},
		{name: "failed", failure: failure},
		{name: "captured available", captured: new(true), failure: failure},
		{name: "captured disabled", captured: new(false), failure: failure},
		{name: "connector-only", private: true, failure: failure},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := &visitorfixture.PolicyClient{Key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("d", 32)))}
			calls := 0
			control := serviceBrowserControl{HTTPControl: serviceHTTPControl{}, origin: "https://control.example.test", policy: policy,
				discovery: func(ctx context.Context) (controlv1.ControlDiscovery, error) {
					if ctx != t.Context() {
						t.Fatal("discovery changed the preparation context")
					}
					calls++
					return controlv1.ControlDiscovery{BrowserLoginAvailable: test.available}, test.failure
				}}
			prepared, closeHTTP, err := PrepareHTTP(t.Context(), HTTP{Control: control, PublicEndpoint: !test.private,
				BrowserLoginAvailable: test.captured, Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_0123456789abcdefghijkl"},
				RunID: "srun_0123456789abcdefghijkl", Number: 1, Token: credentials.ServiceRunToken("run-secret")})
			if test.failure != nil && test.captured == nil && !test.private {
				if !errors.Is(err, failure) || closeHTTP != nil || prepared.browser != nil || calls != 1 || policy.Calls.Load() != 0 {
					t.Fatal("failed discovery started policy work or lost its original cause", err, calls, policy.Calls.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer closeHTTP()
			want := test.available != nil && *test.available
			wantCalls := 1
			if test.captured != nil {
				want, wantCalls = *test.captured, 0
			}
			if test.private {
				wantCalls = 0
			} else if prepared.BrowserLoginAvailable == nil || *prepared.BrowserLoginAvailable != want {
				t.Fatal("public HTTP did not capture the advertised capability")
			}
			if calls != wantCalls || prepared.browser == nil || prepared.browser.Tokens == nil {
				t.Fatal("browser discovery was repeated or disabled installed-session renewal", calls, wantCalls)
			}
			if test.captured != nil {
				*test.captured = !want
				if *prepared.BrowserLoginAvailable != want {
					t.Fatal("caller mutation changed the prepared capability")
				}
			}
			// disabled new sign-in must not disable the existing-session renewal
			// path used by reviewers after an ordinary service restart.
			navigation := httptest.NewRequest(http.MethodGet, "https://preview.example.test/settings?tab=profile", nil)
			navigation.Header.Set("Sec-Fetch-Mode", "navigate")
			navigation.Header.Set("Sec-Fetch-Dest", "document")
			navigation.AddCookie(&http.Cookie{Name: httpaccess.BrowserCookieName, Value: visitorfixture.BrowserCookie})
			response := httptest.NewRecorder()
			if !prepared.browser.RedirectRestricted(response, navigation, false) || response.Code != http.StatusSeeOther ||
				response.Header().Get("Location") != "/__tnl/team/renew?return=%2Fsettings%3Ftab%3Dprofile" {
				t.Fatal("unavailable new sign-in blocked current-session renewal")
			}
		})
	}
}
