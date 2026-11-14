package local

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
)

func TestIntegrationLocalPublicAppPreparationOwnsEndpoint(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx, now := t.Context(), time.Now()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "local_public_app_preparation")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	if err := d.ConfigureIngressServicePorts(ctx, controlstate.PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25444}}); err != nil {
		t.Fatal(err)
	}
	inspect, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inspect.Close() })
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	h, err := controlpublic.NewHandler(controlpublic.Config{
		ManagedURLMode: naming.ManagedURLModeSimple, ManagedDomain: "example.test", OIDCIssuer: "https://identity.fixture.test",
	}, controlpublic.DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewTLSServer(h)
	t.Cleanup(remote.Close)
	if _, err := controlauthority.Register(h, controlauthority.Config{ControlURL: remote.URL}, d); err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	http.DefaultTransport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host == remote.URL {
			return remote.Client().Transport.RoundTrip(r)
		}
		return original.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	newRuntime := func() *appRuntime {
		a, _ := testAppRuntime(t)
		a.project.Config.Server = &remote.URL
		a.project.Config.Services = config.Services{"web": {Public: new(true)}, "api": {}}
		profile, err := a.state.Server(ctx, remote.URL)
		if err != nil {
			t.Fatal(err)
		}
		if err := profile.SaveControlSession(ctx, clientstate.ControlSession{
			SessionID: session.SessionID, AccessToken: session.AccessToken.String(), AccessExpiresAt: session.AccessExpiresAt,
			RefreshToken: session.RefreshToken.String(), RefreshExpiresAt: session.RefreshExpiresAt,
		}); err != nil {
			t.Fatal(err)
		}
		return a
	}
	prepare := func(a *appRuntime, name, owner string) (publisherprotocol.Endpoint, publisherprotocol.Assignment) {
		t.Helper()
		endpoint, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "app", Service: &name})
		if err != nil {
			t.Fatal(err)
		}
		var assignment publisherprotocol.Assignment
		if err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/prepare", publisherprotocol.Prepare{
			Version: 1, Owner: owner, PID: os.Getpid(), Framework: publisherprotocol.FrameworkNode, Directory: a.project.Root, Service: name,
		}, &assignment); err != nil {
			t.Fatal(err)
		}
		return endpoint, assignment
	}
	lookup := func(a *appRuntime) controlstate.LocalProjectService {
		t.Helper()
		source := a.project.LocalPublicationIdentity()
		saved, err := d.GetLocalProjectService(ctx, controlstate.GetLocalProjectServiceRequest{
			TeamID: session.Identity.Memberships[0].TeamID, ActorID: session.Identity.Identity.ID,
			ProjectKey: source.Key, SourceFingerprint: source.Fingerprint, WorktreeKey: a.project.LocalWorktreeKey(), Service: "web", Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return saved
	}
	counts := func(services, claims int) {
		t.Helper()
		var saved, reserved, runs, urls int
		if err := inspect.QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM control.services),
			(SELECT count(*) FROM control.service_port_claims),
			(SELECT count(*) FROM control.service_runs),
			(SELECT count(*) FROM control.public_urls)`).Scan(&saved, &reserved, &runs, &urls); err != nil ||
			saved != services || reserved != claims || runs != 0 || urls != 0 {
			t.Fatal("preparation started a run, created a preview URL, or consumed another binding", saved, reserved, runs, urls, err)
		}
	}
	a := newRuntime()
	// generic metadata reads do not realize even an explicitly public app.
	metadata, err := resolve.NewMetadataResolver(a.state, a.project, nil).Generate(ctx)
	if err != nil || len(metadata.Services) != 0 {
		t.Fatal("metadata read realized a deferred app", metadata, err)
	}
	counts(0, 0)
	const owner = "0123456789abcdef0123456789abcdef"
	endpoint, first := prepare(a, "web", owner)
	selected := first.Project.Services["web"]
	if first.Hostname == "" || first.PublicURL == "" || first.PublicURL != selected.URL ||
		first.Hostname != selected.Hostname || selected.Port < 1024 || !selected.Public {
		t.Fatal("first public app assignment omitted its exact allocated origin", first)
	}
	saved := lookup(a)
	if saved.Metadata == nil || saved.Metadata.Endpoint == nil || saved.Metadata.Protocol != "http" || saved.Metadata.TLS != nil ||
		saved.Metadata.Endpoint.Hostname != first.Hostname || saved.Metadata.Endpoint.Port != selected.Port {
		t.Fatal("preparation changed the exact saved binding or target trust", saved)
	}
	data, err := os.ReadFile(filepath.Join(a.project.Root, meta.DirectoryName, meta.JSONName))
	if err != nil {
		t.Fatal(err)
	}
	var disk meta.Metadata
	if err := json.Unmarshal(data, &disk); err != nil || disk.Services["web"].URL != selected.URL ||
		disk.Services["web"].Port != selected.Port || disk.Services["web"].Hostname != selected.Hostname {
		t.Fatal("first preparation wrote stale metadata", disk, err)
	}
	var snapshot publisherapp.Snapshot
	if err := publisherprotocol.Call(ctx, endpoint, "GET", "/v1/status", nil, &snapshot); err != nil ||
		len(snapshot.Services) != 1 || snapshot.Services[0].PublicURL != first.PublicURL ||
		snapshot.Services[0].Registered || snapshot.Services[0].Target != "" {
		t.Fatal("preparation invented an app listener or lost the public origin", snapshot, err)
	}
	counts(1, 1)
	if _, repeated := prepare(a, "web", owner); repeated.RegistrationID != first.RegistrationID || repeated.PublicURL != first.PublicURL {
		t.Fatal("repeated preparation changed the captured app assignment", repeated)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	registration := publisherprotocol.Registration{Version: 1, RegistrationID: first.RegistrationID, Owner: owner, Target: target.URL}
	if err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/register", registration, nil); err != nil {
		t.Fatal(err)
	}
	if err := publisherprotocol.Call(ctx, endpoint, "GET", "/v1/status", nil, &snapshot); err != nil ||
		len(snapshot.Services) != 1 || snapshot.Services[0].PublicURL != first.PublicURL ||
		!snapshot.Services[0].Registered || snapshot.Services[0].Target != target.URL {
		t.Fatal("registration lost the prepared public origin or actual listener", snapshot, err)
	}
	if err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
		t.Fatal(err)
	}
	_, restarted := prepare(a, "web", "abcdef0123456789abcdef0123456789")
	current := lookup(a)
	if restarted.PublicURL != first.PublicURL || restarted.RegistrationID == first.RegistrationID ||
		current.ServiceID != saved.ServiceID || current.Metadata.TrustRevision != saved.Metadata.TrustRevision {
		t.Fatal("app restart replaced the saved endpoint or trust", restarted, current)
	}
	_, private := prepare(a, "api", owner)
	if private.Hostname != "" || private.PublicURL != "" {
		t.Fatal("private app preparation gained a public endpoint", private)
	}
	if _, found := private.Project.Services["api"]; found {
		t.Fatal("private app preparation exposed a browser-visible endpoint")
	}
	counts(1, 1)
	other := newRuntime()
	_, isolated := prepare(other, "web", owner)
	isolatedSaved := lookup(other)
	if isolated.Hostname == first.Hostname || isolated.Project.Services["web"].Port == selected.Port || isolatedSaved.ServiceID == saved.ServiceID {
		t.Fatal("two worktrees shared an app binding or public port", isolated, isolatedSaved)
	}
	counts(2, 2)
}
