package daemon

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

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher/integrations"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func startIntegrationURLWorker(t *testing.T, worker integrations.Publisher) <-chan controlv1.ServiceRunPreparation {
	t.Helper()
	ready := make(chan controlv1.ServiceRunPreparation, 8)
	prepare := worker.Prepare
	worker.Prepare = func(ctx context.Context) (integrations.Snapshot, error) {
		snapshot, err := prepare(ctx)
		if err != nil {
			return snapshot, err
		}
		var binding controlv1.ServiceRunPreparation
		prepared, onReady := snapshot.Config.Prepared, snapshot.Config.Ready
		snapshot.Config.Prepared = func(run controlv1.ServiceRunPreparation) error {
			if prepared != nil {
				if err := prepared(run); err != nil {
					return err
				}
			}
			binding = run
			return nil
		}
		snapshot.Config.Ready = func() error {
			if onReady != nil {
				if err := onReady(); err != nil {
					return err
				}
			}
			select {
			case ready <- binding:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return snapshot, nil
	}
	report := worker.Report
	worker.Report = func(available bool, err error) {
		if report != nil {
			report(available, err)
		}
		if err != nil {
			t.Logf("integration URL worker: %v", err)
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

func waitIntegrationURLWorkerReady(t *testing.T, ready <-chan controlv1.ServiceRunPreparation) controlv1.ServiceRunPreparation {
	t.Helper()
	select {
	case event := <-ready:
		return event
	case <-time.After(45 * time.Second):
		t.Fatal("integration URL did not become ready")
		return controlv1.ServiceRunPreparation{}
	}
}

func TestIntegrationAliasHandoffKeepsOAuthOriginAndRestoresPrimary(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "alias-oauth")
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(fixture.owner.directory, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
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
	oauthService, oauthConfig := fixture.identity.prepareService(t, "", quic, tcp, controlv1.ProjectServiceConfiguration{})
	oauthConfig.Handler = integrations.OAuthHandler(state, server, oauthHost, nil)
	oauthReady := startIntegrationURLWorker(t, integrations.Publisher{State: state, Store: store, Server: server, Hostname: oauthHost,
		Prepare: func(context.Context) (integrations.Snapshot, error) {
			return integrations.Snapshot{Config: oauthConfig, Service: oauthService}, nil
		}})
	waitIntegrationURLWorkerReady(t, oauthReady)
	primary := filepath.Join(t.TempDir(), "main")
	group := clientstate.IntegrationScope{PrimaryProjectRoot: primary, Namespace: namespace}
	scope := clientstate.AliasScope{Server: server, ProjectKey: primary, TeamID: fixture.identity.teamID, MembershipID: fixture.identity.membershipID, Namespace: namespace, Name: "review"}
	aliasHost := "review." + namespace
	aliasService, aliasBase := fixture.identity.prepareService(t, "", quic, tcp, controlv1.ProjectServiceConfiguration{Hostname: &aliasHost})
	type app struct {
		name, project string
		callbacks     chan string
		ready         <-chan controlv1.ServiceRunPreparation
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
		hostname := "api-" + name + "." + namespace
		saved, config := fixture.identity.prepareService(t, target.URL, quic, tcp, controlv1.ProjectServiceConfiguration{Hostname: &hostname})
		tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: server,
			Project: project, Service: "api", ServiceID: saved.Id, ServiceProtocol: "http", Target: target.URL, IntegrationScope: group})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
		observe := integrations.Observer(state, server, oauthHost, group, tunnel.ID())
		config.HTTPResponseHooks = func(run publisherservice.HTTPRun) httpstream.ResponseHooks {
			return httpstream.ResponseHooks{Observe: func(response *http.Response) error { return observe(response, run) }}
		}
		var binding controlv1.ServiceRunPreparation
		config.Prepared = func(run controlv1.ServiceRunPreparation) error {
			binding = run
			return tunnel.SetProvisioning(t.Context(), uint64(run.RunNumber))
		}
		config.Ready = func() error {
			return tunnel.SetReady(t.Context(), serviceHTTPAddress(binding), uint64(binding.RunNumber))
		}
		parent := startOwnedIntegrationPublisher(t, fixture.owner, config, fixture.diagnostics)
		waitForPublisherReady(t, parent)
		selection, err := state.RegisterAlias(t.Context(), clientstate.AliasRegistration{Scope: scope, Hostname: aliasHost, Service: "api",
			TunnelID: tunnel.ID(), IntegrationScope: group, Fingerprint: sha256.Sum256([]byte("review"))})
		if err != nil {
			t.Fatal(err)
		}
		aliasConfig := aliasBase
		aliasConfig.Target = strings.TrimPrefix(target.URL, "http://")
		aliasConfig.HTTPResponseHooks = config.HTTPResponseHooks
		worker := integrations.AliasPublisher(state, store, selection, tunnel.ID(), func(context.Context) (integrations.Snapshot, error) {
			return integrations.Snapshot{Config: aliasConfig, Service: aliasService}, nil
		}, nil)
		apps = append(apps, app{name: name, project: project, callbacks: callbacks, ready: startIntegrationURLWorker(t, worker)})
	}
	first := waitIntegrationURLWorkerReady(t, apps[0].ready)
	waitForReadyPublisherConnections(t, fixture.inspect, first.ServiceId, first.RunNumber, 2)
	waitForAppliedServiceRouting(t, fixture.inspect, first.ServiceRunId, fixture.process.metricsAddress)
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
	if second.ServiceId != first.ServiceId || second.ServiceRunId == first.ServiceRunId || second.RunNumber <= first.RunNumber {
		t.Fatal("handoff did not replace the alias publish run")
	}
	waitForReadyPublisherConnections(t, fixture.inspect, second.ServiceId, second.RunNumber, 2)
	waitForAppliedServiceRouting(t, fixture.inspect, second.ServiceRunId, fixture.process.metricsAddress)
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
	if third.ServiceId != first.ServiceId || third.ServiceRunId == first.ServiceRunId ||
		third.ServiceRunId == second.ServiceRunId || third.RunNumber <= second.RunNumber {
		t.Fatal("release did not prepare a newer run of the same alias service")
	}
	waitForReadyPublisherConnections(t, fixture.inspect, third.ServiceId, third.RunNumber, 2)
	waitForAppliedServiceRouting(t, fixture.inspect, third.ServiceRunId, fixture.process.metricsAddress)
	if _, body := visit("https://" + aliasHost + "/"); body != "main" {
		t.Fatal("release did not restore the primary checkout")
	}
	saved, err := fixture.identity.routes.GetService(t.Context(), third.ServiceId)
	declaration, _, declarationErr := fixture.identity.routes.GetServiceConfiguration(t.Context(), third.ServiceId)
	if err != nil || declarationErr != nil || declaration == nil || declaration.Target != "app" || saved.Id != aliasService.Id || saved.Ephemeral || saved.Endpoint == nil || saved.Endpoint.Hostname != aliasHost {
		t.Fatalf("alias handoff exposed a worktree target or changed saved service identity: %+v, %v, %v", saved, err, declarationErr)
	}
}
