package oidc_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	controloidc "github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/development/oidc"
	"golang.org/x/net/html"
)

func TestLoopbackHTTPLogin(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	issuer := "http://" + server.Listener.Addr().String()
	redirect := "http://localhost:8445/v1/auth/device/callback"
	provider, err := oidc.New(oidc.Config{Issuer: issuer, ClientID: "local", ClientSecret: "secret", Subject: "developer", RedirectURLs: []string{redirect}})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = provider
	server.Start()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	control, err := controloidc.NewServer(controloidc.ServerConfig{Issuer: server.URL, ClientID: "local", ClientSecret: "secret", RedirectURL: redirect, Scopes: []string{"openid"}, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 43)
	nonce := strings.Repeat("n", 43)
	authorization, err := control.AuthorizationURL(t.Context(), strings.Repeat("s", 32), nonce, verifier)
	if err != nil {
		t.Fatal(err)
	}
	authorize, err := url.Parse(authorization)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.Get(authorization)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(page.Body)
	page.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if page.StatusCode != http.StatusOK || page.Header.Get("Content-Type") != "text/html; charset=utf-8" ||
		!strings.Contains(page.Header.Get("Content-Security-Policy"), "form-action 'self' http://localhost:8445") ||
		!strings.Contains(page.Header.Get("Content-Security-Policy"), "font-src data:") ||
		!strings.Contains(string(body), "data:font/woff2;base64,") || !strings.Contains(string(body), "[ development only ]") {
		t.Fatal("development sign-in lost its styling or exact callback policy")
	}
	document, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	fields := make(url.Values)
	for node := range document.Descendants() {
		if node.Type != html.ElementNode || node.Data != "input" {
			continue
		}
		var name, value string
		for _, attribute := range node.Attr {
			switch attribute.Key {
			case "name":
				name = attribute.Val
			case "value":
				value = attribute.Val
			}
		}
		fields.Add(name, value)
	}
	if fields.Encode() != authorize.Query().Encode() {
		t.Fatal("sign-in form changed its authorization fields")
	}
	response, err := client.PostForm(server.URL+"/authorize", fields)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	location, err := response.Location()
	if err != nil || response.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize: %d, %v", response.StatusCode, err)
	}
	identity, err := control.Redeem(t.Context(), location.Query().Get("code"), nonce, verifier)
	if err != nil || identity.Subject != "developer" || identity.Issuer != server.URL {
		t.Fatalf("redeem: %+v, %v", identity, err)
	}
	if _, err := control.Redeem(t.Context(), location.Query().Get("code"), nonce, verifier); err == nil {
		t.Fatal("authorization code was reused")
	}
}

func TestDevelopmentAuthorizationErrorsPreserveMachineResponses(t *testing.T) {
	provider, err := oidc.New(oidc.Config{ClientID: "local", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, accept := range []string{"", "text/html"} {
			request := httptest.NewRequest(method, "/authorize", nil)
			request.Header.Set("Accept", accept)
			response := httptest.NewRecorder()
			provider.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatal("invalid authorization changed status", response.Code)
			}
			if accept == "" {
				if response.Body.String() != "invalid authorization\n" {
					t.Fatal("non-browser authorization error changed")
				}
			} else if response.Header().Get("Content-Type") != "text/html; charset=utf-8" ||
				!strings.Contains(response.Body.String(), "<h1>bad request</h1>") {
				t.Fatal("browser authorization error is not styled")
			}
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/token", nil)
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()
	provider.ServeHTTP(response, request)
	if response.Header().Get("Content-Type") != "application/json" || response.Body.String() != "{\"error\":\"invalid_client\"}\n" {
		t.Fatal("token endpoint negotiated a browser response", response.Body.String())
	}
}
