package oidcauth

import (
	"errors"
	"net/http"
	"testing"

	"golang.org/x/oauth2"
)

func TestPollDeviceReturnsStructuredProviderStatesWithoutRetry(t *testing.T) {
	for _, code := range []string{"authorization_pending", "slow_down", "access_denied", "expired_token"} {
		t.Run(code, func(t *testing.T) {
			p := newTestProvider(t, "")
			calls := 0
			p.mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				calls++
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.Form.Get("device_code") != "private-code" || r.Form.Get("client_id") != "cli" || r.Header.Get("Authorization") != "" {
					t.Error("wrong device credential request")
				}
				w.WriteHeader(400)
				writeProviderJSON(t, w, map[string]string{"error": code, "error_description": "secret provider message"})
			})
			_, err := PollDevice(t.Context(), Config{ClientID: "cli", HTTPClient: p.client}, DeviceChallenge{TokenURL: p.issuer + "/token", DeviceCode: "private-code"})
			var provider *oauth2.RetrieveError
			if !errors.As(err, &provider) || provider.ErrorCode != code || calls != 1 || provider.ErrorDescription != "" || len(provider.Body) != 0 {
				t.Fatalf("provider state = %#v, calls = %d", provider, calls)
			}
		})
	}
}

func TestStartDeviceRejectsApprovalURLContainingPrivateChallenge(t *testing.T) {
	p := newTestProvider(t, "")
	p.mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		writeProviderJSON(t, w, map[string]any{"device_code": "private-code", "user_code": "USER-CODE", "verification_uri_complete": p.issuer + "/approve?secret=private-code", "expires_in": 60})
	})
	if _, err := StartDevice(t.Context(), Config{Issuer: p.issuer, ClientID: "cli", Scopes: []string{"openid"}, HTTPClient: p.client}); err == nil {
		t.Fatal("private code accepted in public approval URL")
	}
}
