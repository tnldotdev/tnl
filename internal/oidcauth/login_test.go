package oidcauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestLoginDeviceCode(t *testing.T) {
	p := newTestProvider(t, "")
	ctx := loginTestContext(t)
	var mu sync.Mutex
	var nonce, idToken string
	deviceCalls, tokenCalls := 0, 0
	p.mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		deviceCalls++
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		nonce = r.Form.Get("nonce")
		if r.Method != http.MethodPost || r.Form.Get("client_id") != "tnl-cli" || r.Form.Get("scope") != "openid" || nonce == "" {
			t.Errorf("device request = %s %v", r.Method, r.Form)
		}
		writeProviderJSON(t, w, map[string]any{
			"device_code": "device-code", "user_code": "ABCD-1234",
			"verification_uri": p.issuer + "/device-login", "expires_in": 60, "interval": 1,
		})
	})
	p.mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		tokenCalls++
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || r.Form.Get("client_id") != "tnl-cli" ||
			r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.Form.Get("device_code") != "device-code" {
			t.Errorf("token request = %s %v, authorization = %q", r.Method, r.Form, r.Header.Get("Authorization"))
		}
		writeProviderJSON(t, w, map[string]any{"access_token": "provider-access", "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
	})
	var output bytes.Buffer
	openCount := 0
	result, err := Login(ctx, Config{
		Issuer: p.issuer, ClientID: "tnl-cli", LoginFlow: LoginFlowDeviceCode, Scopes: []string{"openid"}, HTTPClient: p.client,
		OpenURL: func(target string) error {
			openCount++
			if target != p.issuer+"/device-login" {
				t.Errorf("browser target = %q", target)
			}
			mu.Lock()
			defer mu.Unlock()
			// OpenURL runs on the test goroutine. Prepare the token here, not in /token.
			idToken = p.signer.Token(t, "key-1", map[string]any{
				"iss": p.issuer, "sub": "user-123", "aud": "tnl-cli", "nonce": nonce,
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			})
			return errors.New("browser unavailable") // Manual device login remains usable.
		},
	}, &output)
	mu.Lock()
	defer mu.Unlock()
	if err != nil || result.IDToken != idToken || result.Identity.Issuer != p.issuer || result.Identity.Subject != "user-123" ||
		result.Identity.Nonce != nonce || result.Identity.ExpiresAt.IsZero() || openCount != 1 || deviceCalls != 1 || tokenCalls != 1 ||
		output.String() != "Open "+p.issuer+"/device-login\nCode: ABCD-1234\n" {
		t.Fatalf("result=%#v error=%v output=%q calls=%d/%d/%d", result, err, output.String(), openCount, deviceCalls, tokenCalls)
	}
}

func TestAuthorizationCodePKCELogin(t *testing.T) {
	p := newTestProvider(t, "")
	ctx := loginTestContext(t)
	var mu sync.Mutex
	var challenge, redirectURI, idToken string
	authorizeCalls, tokenCalls := 0, 0
	p.mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		authorizeCalls++
		query := r.URL.Query()
		challenge, redirectURI = query.Get("code_challenge"), query.Get("redirect_uri")
		if r.Method != http.MethodGet || query.Get("code_challenge_method") != "S256" || query.Get("nonce") == "" || challenge == "" ||
			query.Get("client_id") != "tnl-cli" || query.Get("response_type") != "code" || query.Get("scope") != "openid" || query.Get("state") == "" {
			t.Errorf("authorization request = %s %v", r.Method, query)
		}
		http.Redirect(w, r, redirectURI+"?code=authorization-code&state="+url.QueryEscape(query.Get("state")), http.StatusFound)
	})
	p.mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		tokenCalls++
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		verifier := r.Form.Get("code_verifier")
		verifierHash := sha256.Sum256([]byte(verifier))
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || r.Form.Get("client_id") != "tnl-cli" ||
			r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "authorization-code" ||
			r.Form.Get("redirect_uri") != redirectURI || len(verifier) < 43 || len(verifier) > 128 ||
			base64.RawURLEncoding.EncodeToString(verifierHash[:]) != challenge {
			t.Errorf("token request = %s %v", r.Method, r.Form)
		}
		writeProviderJSON(t, w, map[string]any{"access_token": "provider-access", "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
	})
	driveBrowser := func(target string) error {
		authorizationURL, err := url.Parse(target)
		if err != nil {
			return err
		}
		preparedToken := p.signer.Token(t, "key-1", map[string]any{
			"iss": p.issuer, "sub": "user-123", "aud": "tnl-cli", "nonce": authorizationURL.Query().Get("nonce"),
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		mu.Lock()
		idToken = preparedToken
		mu.Unlock()
		for _, visit := range []struct {
			target string
			status int
		}{
			{authorizationURL.Query().Get("redirect_uri") + "?code=ignored&state=invalid", http.StatusBadRequest},
			{target, http.StatusOK},
		} {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, visit.target, nil)
			if err != nil {
				return err
			}
			response, err := p.client.Do(request)
			if err != nil {
				return err
			}
			if err := response.Body.Close(); err != nil {
				return err
			}
			if response.StatusCode != visit.status {
				return fmt.Errorf("browser status = %d, want %d", response.StatusCode, visit.status)
			}
		}
		return nil
	}
	var output bytes.Buffer
	var driverErr error
	openCount := 0
	result, err := Login(ctx, Config{
		Issuer: p.issuer, ClientID: "tnl-cli", LoginFlow: LoginFlowAuthorizationCodePKCE, Scopes: []string{"openid"}, HTTPClient: p.client,
		OpenURL: func(target string) error {
			openCount++
			driverErr = driveBrowser(target)
			return driverErr
		},
	}, &output)
	if driverErr != nil {
		t.Fatalf("browser driver: %v (Login: %v)", driverErr, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if err != nil || result.IDToken != idToken || result.Identity.Subject != "user-123" ||
		openCount != 1 || authorizeCalls != 1 || tokenCalls != 1 || !strings.Contains(output.String(), p.issuer+"/authorize") {
		t.Fatalf("result=%#v error=%v output=%q calls=%d/%d/%d", result, err, output.String(), openCount, authorizeCalls, tokenCalls)
	}
}

func TestVerifiedResultClaims(t *testing.T) {
	p := newTestProvider(t, "")
	ctx := oidc.ClientContext(loginTestContext(t), p.client)
	provider, err := oidc.NewProvider(ctx, p.issuer)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name                   string
		change                 func(map[string]any)
		deviceValid, pkceValid bool
	}{
		{"valid", func(map[string]any) {}, true, true},
		{"missing nonce", func(c map[string]any) { delete(c, "nonce") }, true, false},
		{"wrong nonce", func(c map[string]any) { c["nonce"] = "wrong" }, false, false},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }, false, false},
		{"wrong audience", func(c map[string]any) { c["aud"] = "other" }, false, false},
		{"multiple audiences missing azp", func(c map[string]any) { c["aud"] = []string{"tnl-cli", "other"} }, false, false},
		{"multiple audiences wrong azp", func(c map[string]any) { c["aud"] = []string{"tnl-cli", "other"}; c["azp"] = "other" }, false, false},
		{"multiple audiences correct azp", func(c map[string]any) { c["aud"] = []string{"tnl-cli", "other"}; c["azp"] = "tnl-cli" }, true, true},
		{"single audience wrong azp", func(c map[string]any) { c["azp"] = "other" }, false, false},
		{"single audience correct azp", func(c map[string]any) { c["azp"] = "tnl-cli" }, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			expires := time.Now().Add(time.Hour).Truncate(time.Second)
			claims := map[string]any{"iss": p.issuer, "sub": "user-123", "aud": "tnl-cli", "nonce": "expected", "iat": time.Now().Unix(), "exp": expires.Unix()}
			test.change(claims)
			raw := p.signer.Token(t, "key-1", claims)
			token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": raw})
			for _, flow := range []struct {
				name  string
				valid bool
			}{{LoginFlowDeviceCode, test.deviceValid}, {LoginFlowAuthorizationCodePKCE, test.pkceValid}} {
				t.Run(flow.name, func(t *testing.T) {
					result, err := verifiedResult(ctx, provider, "tnl-cli", "expected", flow.name, token)
					if (err == nil) != flow.valid {
						t.Fatalf("result=%#v error=%v, want valid=%t", result, err, flow.valid)
					}
					if flow.valid && (result.IDToken != raw || result.Identity.Issuer != p.issuer || result.Identity.Subject != "user-123" || !result.Identity.ExpiresAt.Equal(expires)) {
						t.Fatalf("result = %#v", result)
					}
				})
			}
		})
	}
}

func TestLoginRequiresExplicitOpenIDScopes(t *testing.T) {
	for _, scopes := range [][]string{nil, {}, {"operations"}, {"openid", "openid"}} {
		if _, err := Login(t.Context(), Config{
			Issuer: "https://issuer.example", ClientID: "tnl-cli", LoginFlow: LoginFlowDeviceCode, Scopes: scopes,
		}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "invalid configuration") {
			t.Fatalf("scopes %v error = %v", scopes, err)
		}
	}
}
