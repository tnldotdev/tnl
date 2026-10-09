package tnldruntime

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/integrationurls"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func startIntegrationURLWorker(t *testing.T, worker integrationurls.Publisher) <-chan publisher.Event {
	t.Helper()
	ready := make(chan publisher.Event, 4)
	worker.Report = func(event publisher.Event, err error) {
		if err != nil {
			t.Logf("integration URL worker: %v", err)
		}
		if event.Type == publisher.EventReady {
			ready <- event
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); worker.Maintain(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("integration URL worker did not stop")
		}
	})
	return ready
}

func waitIntegrationURLWorkerReady(t *testing.T, ready <-chan publisher.Event) publisher.Event {
	t.Helper()
	select {
	case event := <-ready:
		return event
	case <-time.After(45 * time.Second):
		t.Fatal("integration URL did not become ready")
		return publisher.Event{}
	}
}

func TestIntegrationAliasHandoffKeepsOAuthOriginAndRestoresPrimary(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "alias-oauth")
	state, err := clientstate.Open(t.Context(), filepath.Join(fixture.owner.directory, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	server, oauthHost := fixture.identity.controlOrigin, fixture.identity.hostname
	namespace := strings.TrimPrefix(oauthHost, "alias-oauth.")
	store, err := state.Server(t.Context(), server)
	if err != nil {
		t.Fatal(err)
	}
	quic, tcp := fixture.connectors()
	oauthConfig := fixture.identity.publisherConfig("http://127.0.0.1:1", quic, tcp)
	oauthConfig.Purpose = controlv1.PublicURLCreatePurposeOauth
	oauthConfig.Handler = integrationurls.OAuthHandler(state, server, oauthHost)
	oauthReady := startIntegrationURLWorker(t, integrationurls.Publisher{State: state, Store: store, Server: server, Hostname: oauthHost,
		Prepare: func(context.Context) (integrationurls.Snapshot, error) {
			return integrationurls.Snapshot{Config: oauthConfig}, nil
		}})
	waitIntegrationURLWorkerReady(t, oauthReady)
	primary := filepath.Join(t.TempDir(), "main")
	group := primary + "\x00" + namespace
	scope := clientstate.AliasScope{Server: server, ProjectKey: primary, TeamID: fixture.identity.teamID, MembershipID: fixture.identity.membershipID, Namespace: namespace, Name: "review"}
	aliasHost := "review." + namespace
	type app struct {
		name, project string
		callbacks     chan string
		ready         <-chan publisher.Event
	}
	apps := make([]app, 0, 2)
	for _, name := range []string{"main", "feature"} {
		callbacks := make(chan string, 3)
		target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/login", "/pending":
				http.SetCookie(response, &http.Cookie{Name: "session", Value: name, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
				query := url.Values{"state": {name + request.URL.Path}, "redirect_uri": {"https://" + oauthHost + "/callback"}}
				response.Header().Set("Location", "https://idp.example.test/authorize?"+query.Encode())
				response.WriteHeader(http.StatusFound)
			case "/callback":
				callbacks <- request.Header.Get("Cookie")
				response.WriteHeader(http.StatusNoContent)
			default:
				_, _ = io.WriteString(response, name)
			}
		}))
		t.Cleanup(target.Close)
		project := filepath.Join(filepath.Dir(primary), name)
		tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: server,
			Project: project, Service: "api", Target: target.URL, IntegrationGroup: group})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
		config := fixture.identity.publisherConfig(target.URL, quic, tcp)
		config.Hostname = "api-" + name + "." + namespace
		config.ObserveResponse = integrationurls.Observer(state, server, oauthHost, group, tunnel.ID())
		config.Observe = func(event publisher.Event) error {
			switch event.Type {
			case publisher.EventPublicURLAssigned:
				return tunnel.SetPublicURL(t.Context(), event.PublicURLID, event.Hostname)
			case publisher.EventProvisioning:
				return tunnel.SetProvisioning(t.Context(), event.PublishRunNumber)
			case publisher.EventReady:
				return tunnel.SetReady(t.Context(), event.PublicURL, event.PublishRunNumber)
			}
			return nil
		}
		parent := startOwnedIntegrationPublisher(t, fixture.owner, config, fixture.diagnostics)
		waitForPublisherReady(t, parent)
		selection, err := state.RegisterAlias(t.Context(), clientstate.AliasRegistration{Scope: scope, Hostname: aliasHost, Service: "api",
			TunnelID: tunnel.ID(), IntegrationGroup: group, Fingerprint: sha256.Sum256([]byte("review"))})
		if err != nil {
			t.Fatal(err)
		}
		aliasConfig := fixture.identity.publisherConfig(target.URL, quic, tcp)
		aliasConfig.Purpose = controlv1.PublicURLCreatePurposeAlias
		aliasConfig.Hostname, aliasConfig.ObserveResponse = aliasHost, config.ObserveResponse
		worker := integrationurls.AliasPublisher(state, store, selection, tunnel.ID(), aliasConfig, nil)
		apps = append(apps, app{name: name, project: project, callbacks: callbacks, ready: startIntegrationURLWorker(t, worker)})
	}
	first := waitIntegrationURLWorkerReady(t, apps[0].ready)
	waitForReadyPublisherConnections(t, fixture.inspect, first.PublicURLID, first.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	visitor := *fixture.visitor.client
	visitor.Jar, visitor.CheckRedirect = jar, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	visit := func(address string) (*http.Response, string) {
		t.Helper()
		response, err := visitor.Get(address)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return response, string(body)
	}
	if _, body := visit("https://" + aliasHost + "/"); body != "main" {
		t.Fatal("alias did not default to the primary checkout")
	}
	login, _ := visit("https://" + aliasHost + "/login")
	if login.StatusCode != http.StatusFound {
		t.Fatal("alias login failed")
	}
	callback, _ := visit("https://" + oauthHost + "/callback?state=main%2Flogin&code=opaque")
	if callback.StatusCode != http.StatusSeeOther || !strings.HasPrefix(callback.Header.Get("Location"), "https://"+aliasHost+"/callback?") {
		t.Fatal("callback returned to an ordinary worktree URL")
	}
	returned, _ := visit(callback.Header.Get("Location"))
	if returned.StatusCode != http.StatusNoContent || <-apps[0].callbacks != "session=main" {
		t.Fatal("alias-origin callback lost its host-only state cookie")
	}
	visit("https://" + aliasHost + "/pending")
	if _, err := state.SelectAlias(t.Context(), scope, apps[1].project, true); err != nil {
		t.Fatal(err)
	}
	second := waitIntegrationURLWorkerReady(t, apps[1].ready)
	if second.PublicURLID != first.PublicURLID || second.PublishRunNumber <= first.PublishRunNumber {
		t.Fatal("handoff did not replace the alias publish run")
	}
	waitForReadyPublisherConnections(t, fixture.inspect, second.PublicURLID, second.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	if _, body := visit("https://" + aliasHost + "/"); body != "feature" {
		t.Fatal("forced handoff did not reach the selected worktree")
	}
	stale, _ := visit("https://" + oauthHost + "/callback?state=main%2Fpending&code=opaque")
	if stale.StatusCode != http.StatusGone || len(apps[1].callbacks) != 0 {
		t.Fatal("old alias login reached the replacement worktree")
	}
	if _, err := state.ReleaseAlias(t.Context(), scope, apps[1].project); err != nil {
		t.Fatal(err)
	}
	third := waitIntegrationURLWorkerReady(t, apps[0].ready)
	waitForReadyPublisherConnections(t, fixture.inspect, third.PublicURLID, third.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	if _, body := visit("https://" + aliasHost + "/"); body != "main" {
		t.Fatal("release did not restore the primary checkout")
	}
}
