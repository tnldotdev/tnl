package authorityapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/devoidc"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestIntegrationControlOwnedDeviceLogin(t *testing.T) {
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "oidc_device")
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	controlMux, providerMux := http.NewServeMux(), http.NewServeMux()
	control, provider := httptest.NewTLSServer(controlMux), httptest.NewTLSServer(providerMux)
	t.Cleanup(control.Close)
	t.Cleanup(provider.Close)
	p, err := devoidc.New(devoidc.Config{Issuer: provider.URL, ClientID: "server", ClientSecret: "secret", Subject: "named-person", RedirectURLs: []string{control.URL + deviceCallbackPath}})
	if err != nil {
		t.Fatal(err)
	}
	providerMux.Handle("/", p)
	config := Config{ControlURL: control.URL, ManagedDomain: "apps.example.test", OIDCIssuer: provider.URL, OIDCClientID: "server", OIDCClientSecret: "secret", OIDCScopes: []string{"openid", "profile", "email"}, HTTPClient: provider.Client(), AccessTokenLifetime: 5 * time.Minute, RefreshTokenLifetime: time.Hour}
	if _, err := Register(controlMux, config, d); err != nil {
		t.Fatal(err)
	}
	api, err := authorityclient.New(control.URL, control.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := api.StartDeviceLogin(ctx, authorityv1.StartDeviceLoginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(challenge.ApprovalUrl, control.URL+"/v1/auth/device/approve?") || len(challenge.PollingCredential) != 43 || len(challenge.UserCode) != 13 {
		t.Fatalf("invalid challenge: %#v", challenge)
	}
	pending, err := api.PollDeviceLogin(ctx, challenge.PollingCredential)
	if err != nil || string(pending.Status) != "pending" || pending.Session != nil {
		t.Fatalf("pending: %#v %v", pending, err)
	}
	if _, err := api.PollDeviceLogin(ctx, strings.Repeat("x", 43)); !errors.Is(err, authorityclient.ErrUnauthenticated) {
		t.Fatalf("public code guessed private result: %v", err)
	}
	beginBrowser := func(approval string) (string, *http.Cookie) {
		t.Helper()
		client := *control.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, err := client.Get(approval + "&team=")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		location, err := url.Parse(response.Header.Get("Location"))
		if err != nil || response.StatusCode != 302 || len(response.Cookies()) != 1 {
			t.Fatalf("browser start: %d %v", response.StatusCode, err)
		}
		return location.Query().Get("state"), response.Cookies()[0]
	}
	callback := func(state, query string, cookie *http.Cookie) int {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, "GET", control.URL+deviceCallbackPath+"?state="+url.QueryEscape(state)+"&"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.AddCookie(cookie)
		response, err := control.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	_, cookie := beginBrowser(challenge.ApprovalUrl)
	if status := callback(strings.Repeat("s", 43), "code=untrusted-code", cookie); status != 401 {
		t.Fatalf("invalid state: %d", status)
	}
	if err := oidctest.Approve(ctx, control.Client(), challenge.ApprovalUrl); err != nil {
		t.Fatal(err)
	}
	issued, err := api.PollDeviceLogin(ctx, challenge.PollingCredential)
	if err != nil || issued.Session == nil || string(issued.Status) != "approved" {
		t.Fatalf("approved: %#v %v", issued, err)
	}
	if issued.Session.Identity.Identity.Administrator {
		t.Fatal("first login became administrator")
	}
	repeated, err := api.PollDeviceLogin(ctx, challenge.PollingCredential)
	if err != nil || !reflect.DeepEqual(issued, repeated) {
		t.Fatalf("lost-response retry changed session: %v", err)
	}
	principal, err := d.AuthenticateAccessToken(ctx, credentials.AccessToken(issued.Session.AccessToken), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := api.CancelDeviceLogin(ctx, challenge.PollingCredential); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticateAccessToken(ctx, credentials.AccessToken(issued.Session.AccessToken), time.Now()); !errors.Is(err, controlstate.ErrControlAuthentication) {
		t.Fatalf("cancelled session remains live: %v", err)
	}
	if err := api.CancelDeviceLogin(ctx, challenge.PollingCredential); err != nil {
		t.Fatal(err)
	}
	_ = principal
	second, err := api.StartDeviceLogin(ctx, authorityv1.StartDeviceLoginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.CancelDeviceLogin(ctx, second.PollingCredential); err != nil {
		t.Fatal(err)
	}
	if err := oidctest.Approve(ctx, control.Client(), second.ApprovalUrl); err == nil {
		t.Fatal("cancelled login was approved")
	}
	if _, err := d.PollDeviceLogin(ctx, second.PollingCredential, time.Now().Add(11*time.Minute)); !errors.Is(err, controlstate.ErrDeviceLogin) {
		t.Fatalf("expired device login: %v", err)
	}
	denied, err := api.StartDeviceLogin(ctx, authorityv1.StartDeviceLoginRequest{})
	if err != nil {
		t.Fatal(err)
	}
	state, cookie := beginBrowser(denied.ApprovalUrl)
	if status := callback(state, "error=access_denied", cookie); status != 401 {
		t.Fatalf("denial callback: %d", status)
	}
	result, err := api.PollDeviceLogin(ctx, denied.PollingCredential)
	if err != nil || string(result.Status) != "denied" || result.Session != nil {
		t.Fatalf("denied poll: %#v %v", result, err)
	}
	if status := callback(state, "error=access_denied", cookie); status != 401 {
		t.Fatalf("replayed state: %d", status)
	}
}
