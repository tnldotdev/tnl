package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	controloidc "github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/development/oidc"
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
	response, err := client.PostForm(server.URL+"/authorize", authorize.Query())
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
