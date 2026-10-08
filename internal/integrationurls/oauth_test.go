package integrationurls

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
)

const testServer = "https://control.example.test"
const testOAuthHost = "oauth.project.example.test"

func callbackState(t *testing.T) (*clientstate.Database, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Server(t.Context(), testServer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return state, root
}

func readyTunnel(t *testing.T, state *clientstate.Database, target, hostname string) (*clientstate.Tunnel, publisher.PublishRunIdentity) {
	t.Helper()
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: testServer, Target: target,
		Project: t.TempDir(), Service: "api", CallbackHostname: testOAuthHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
	id, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetPublicURL(t.Context(), id, hostname); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "https://"+hostname, 1); err != nil {
		t.Fatal(err)
	}
	return tunnel, publisher.PublishRunIdentity{PublicURLID: id, Number: 1}
}

func authorizationResponse(state, query string) *http.Response {
	request := httptest.NewRequest(http.MethodPost, "https://feature.example.test/api/auth/sign-in/social", nil)
	response := &http.Response{Request: request, Header: make(http.Header)}
	response.Header.Set("Location", "https://github.com/login/oauth/authorize?response_type=code&state="+state+"&redirect_uri=https%3A%2F%2F"+testOAuthHost+"%2Fapi%2Fauth%2Fcallback%2Fgithub"+query)
	return response
}

func TestOAuthCallbacksDispatchAcrossWorktreesAndStateHandles(t *testing.T) {
	state, root := callbackState(t)
	leader, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leader.Close() })
	if err := leader.MarkIntegrationURLReady(t.Context(), testServer, testOAuthHost, "leader"); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"main", "feature"} {
		tunnel, run := readyTunnel(t, state, "3000", label+".example.test")
		observer := Observer(state, testServer, testOAuthHost, tunnel.ID())
		// the provider returns the existing redirect-URI query followed by its
		// authorization response; the dispatcher must not duplicate that query.
		if err := observer(authorizationResponse(label+"-state", "%3Fflow%3Dgithub"), run); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "https://"+testOAuthHost+"/api/auth/callback/github?flow=github&code=opaque&state="+label+"-state", nil)
		response := httptest.NewRecorder()
		OAuthHandler(leader, testServer, testOAuthHost).ServeHTTP(response, request)
		want := "https://" + label + ".example.test/api/auth/callback/github?flow=github&code=opaque&state=" + label + "-state"
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != want {
			t.Fatalf("callback = %d %q, want %q", response.Code, response.Header().Get("Location"), want)
		}
		response = httptest.NewRecorder()
		OAuthHandler(leader, testServer, testOAuthHost).ServeHTTP(response, request)
		if response.Code != http.StatusGone {
			t.Fatalf("state was replayed: %d", response.Code)
		}
	}
}

func TestOAuthObservationRejectsUnavailableOrReplacedRuns(t *testing.T) {
	state, _ := callbackState(t)
	tunnel, run := readyTunnel(t, state, "3000", "feature.example.test")
	observe := Observer(state, testServer, testOAuthHost, tunnel.ID())
	if err := observe(authorizationResponse("one", ""), run); err == nil {
		t.Fatal("unready integration URL publisher accepted a login")
	}
	if err := state.MarkIntegrationURLReady(t.Context(), testServer, testOAuthHost, "leader"); err != nil {
		t.Fatal(err)
	}
	if err := observe(authorizationResponse("one", ""), run); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetProvisioning(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "https://feature.example.test", 2); err != nil {
		t.Fatal(err)
	}
	if err := observe(authorizationResponse("two", ""), run); err == nil {
		t.Fatal("an old response was bound to the new run")
	}
	request := httptest.NewRequest(http.MethodGet, "https://"+testOAuthHost+"/api/auth/callback/github?code=opaque&state=one", nil)
	response := httptest.NewRecorder()
	OAuthHandler(state, testServer, testOAuthHost).ServeHTTP(response, request)
	if response.Code != http.StatusGone {
		t.Fatalf("old run got callback: %d", response.Code)
	}
}

func TestOAuthObserverRejectsDuplicateStateAndIgnoresUnrelatedRedirects(t *testing.T) {
	state, _ := callbackState(t)
	tunnel, run := readyTunnel(t, state, "3000", "feature.example.test")
	if err := state.MarkIntegrationURLReady(t.Context(), testServer, testOAuthHost, "leader"); err != nil {
		t.Fatal(err)
	}
	observe := Observer(state, testServer, testOAuthHost, tunnel.ID())
	withoutResponseType := authorizationResponse("provider-without-response-type", "")
	withoutResponseType.Header.Set("Location", strings.Replace(withoutResponseType.Header.Get("Location"), "response_type=code&", "", 1))
	if err := observe(withoutResponseType, run); err != nil {
		t.Fatalf("provider omitted optional response_type: %v", err)
	}
	callback := httptest.NewRequest(http.MethodGet, "https://"+testOAuthHost+"/api/auth/callback/github?code=opaque&state=provider-without-response-type", nil)
	response := httptest.NewRecorder()
	OAuthHandler(state, testServer, testOAuthHost).ServeHTTP(response, callback)
	if response.Code != http.StatusSeeOther || !strings.Contains(response.Header().Get("Location"), "feature.example.test") {
		t.Fatalf("provider callback was not routed: %d %q", response.Code, response.Header().Get("Location"))
	}
	if err := observe(authorizationResponse("one", ""), run); err != nil {
		t.Fatal(err)
	}
	if err := observe(authorizationResponse("one", ""), run); err == nil {
		t.Fatal("duplicate state replaced its origin")
	}
	unrelated := authorizationResponse("two", "")
	unrelated.Header.Set("Location", "https://example.test/dashboard")
	if err := observe(unrelated, run); err != nil {
		t.Fatal(err)
	}
	invalid := authorizationResponse("two", "")
	invalid.Header.Set("Location", invalid.Header.Get("Location")+"&state=three")
	if err := observe(invalid, run); err == nil {
		t.Fatal("ambiguous state accepted")
	}
}

func TestOAuthConcurrentConsumptionAndCrossServerAdmission(t *testing.T) {
	state, _ := callbackState(t)
	tunnel, run := readyTunnel(t, state, "3000", "feature.example.test")
	if err := state.MarkIntegrationURLReady(t.Context(), testServer, testOAuthHost, "leader"); err != nil {
		t.Fatal(err)
	}
	if err := Observer(state, testServer, testOAuthHost, tunnel.ID())(authorizationResponse("one", ""), run); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://"+testOAuthHost+"/api/auth/callback/github?code=opaque&state=one", nil)
	wrong := httptest.NewRecorder()
	OAuthHandler(state, "https://other.example.test", testOAuthHost).ServeHTTP(wrong, request)
	if wrong.Code != http.StatusGone {
		t.Fatalf("another server used the callback: %d", wrong.Code)
	}
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			response := httptest.NewRecorder()
			OAuthHandler(state, testServer, testOAuthHost).ServeHTTP(response, request.Clone(t.Context()))
			statuses <- response.Code
		})
	}
	wg.Wait()
	one, two := <-statuses, <-statuses
	if (one == http.StatusSeeOther) == (two == http.StatusSeeOther) {
		t.Fatalf("one callback must succeed: %d/%d", one, two)
	}
}

func TestOAuthFailuresDoNotExposeCallbackValues(t *testing.T) {
	state, _ := callbackState(t)
	request := httptest.NewRequest(http.MethodGet, "https://"+testOAuthHost+"/api/auth/callback/github?code=secret-code&state=secret-state", nil)
	response := httptest.NewRecorder()
	OAuthHandler(state, testServer, testOAuthHost).ServeHTTP(response, request)
	if response.Header().Get("Tnl-Error-Code") != string(diagnostic.OAuthCallbackExpired) || strings.Contains(response.Body.String(), "secret-code") || strings.Contains(response.Body.String(), "secret-state") {
		t.Fatalf("unexpected callback diagnostic: %d %q", response.Code, response.Header().Get("Tnl-Error-Code"))
	}
}
