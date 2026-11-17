package integrations

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type aliasFixture struct {
	state         *clientstate.Database
	selection     clientstate.AliasSelection
	main, linked  *clientstate.Tunnel
	group         clientstate.IntegrationScope
	linkedProject string
}

func newAliasFixture(t *testing.T) aliasFixture {
	t.Helper()
	state, _ := callbackState(t)
	primary := filepath.Join(t.TempDir(), "main")
	linked := filepath.Join(filepath.Dir(primary), "feature")
	scope := clientstate.AliasScope{Server: testServer, ProjectKey: primary, TeamID: "team_fixture", MembershipID: "member_fixture", Namespace: "member.example.test", Name: "review"}
	group := clientstate.IntegrationScope{PrimaryProjectRoot: primary, Namespace: scope.Namespace}
	f := aliasFixture{state: state, group: group, linkedProject: linked}
	for index, project := range []string{primary, linked} {
		id, err := opaqueid.New(opaqueid.ServicePrefix)
		if err != nil {
			t.Fatal(err)
		}
		tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish,
			Server: testServer, Project: project, Service: "api", ServiceID: id, Target: "3000", IntegrationScope: group})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
		hostname := []string{"api-main", "api-feature"}[index] + "." + scope.Namespace
		if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.SetReady(t.Context(), "https://"+hostname, 1); err != nil {
			t.Fatal(err)
		}
		selection, err := state.RegisterAlias(t.Context(), clientstate.AliasRegistration{Scope: scope,
			Hostname: "review." + scope.Namespace, Service: "api", TunnelID: tunnel.ID(), IntegrationScope: group, Fingerprint: sha256.Sum256([]byte("review"))})
		if err != nil {
			t.Fatal(err)
		}
		f.selection = selection
		if index == 0 {
			f.main = tunnel
		} else {
			f.linked = tunnel
		}
	}
	return f
}

func aliasSnapshot(selection clientstate.AliasSelection, id string) func(context.Context) (Snapshot, error) {
	return func(context.Context) (Snapshot, error) {
		return Snapshot{Config: publisherservice.RunConfig{ServiceID: id, PreviewID: "old-preview", Feedback: true},
			Service: controlv1.Service{Id: id, Enabled: true, Protocol: controlv1.ServiceProtocolHTTP,
				Endpoint: &controlv1.ServiceEndpoint{Hostname: selection.Hostname, Public: true, Port: 443}}}, nil
	}
}

func aliasPreparation(t *testing.T, id, hostname string, number int64) controlv1.ServiceRunPreparation {
	t.Helper()
	runID, err := opaqueid.New(opaqueid.ServiceRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	return controlv1.ServiceRunPreparation{ServiceId: id, ServiceRunId: runID, Hostname: hostname, RunNumber: number}
}

func TestAliasRequestsStopAfterSelectionChange(t *testing.T) {
	f := newAliasFixture(t)
	store, err := f.state.Server(t.Context(), testServer)
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	worker := AliasPublisher(f.state, store, f.selection, f.main.ID(), aliasSnapshot(f.selection, id), nil)
	snapshot, err := worker.Prepare(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://"+f.selection.Hostname+"/", nil)
	if snapshot.Config.PreviewID != "" || snapshot.Config.Feedback {
		t.Fatal("alias inherited preview share or feedback state")
	}
	if err := snapshot.Config.AdmitRequest(request); err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.SelectAlias(t.Context(), f.selection.Scope, f.linkedProject, true); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Config.AdmitRequest(request); err == nil {
		t.Fatal("old publisher admitted a request after handoff")
	} else if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.AliasUnavailable {
		t.Fatalf("handoff rejection = %v", err)
	}
	eligible, err := worker.Eligible(t.Context())
	if err != nil || eligible {
		t.Fatal("old worktree retained publication eligibility")
	}
}

func TestAliasHTTPFailsWhenSelectedAppStopsDespiteHealthySibling(t *testing.T) {
	f := newAliasFixture(t)
	store, err := f.state.Server(t.Context(), testServer)
	if err != nil {
		t.Fatal(err)
	}
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "selected-primary")
	}))
	t.Cleanup(primary.Close)
	sibling := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "healthy-feature")
	}))
	t.Cleanup(sibling.Close)
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	worker := AliasPublisher(f.state, store, f.selection, f.main.ID(), func(ctx context.Context) (Snapshot, error) {
		snapshot, err := aliasSnapshot(f.selection, id)(ctx)
		snapshot.Config.Target = primary.URL
		return snapshot, err
	}, nil)
	snapshot, err := worker.Prepare(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Config.ServiceID != id || snapshot.Config.PreviewID != "" || snapshot.Config.Feedback {
		t.Fatal("alias borrowed its receiver's service, preview share, or feedback")
	}
	destination, err := url.Parse(snapshot.Config.Target)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(destination)
	alias := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := snapshot.Config.AdmitRequest(r); err != nil {
			code, _ := diagnostic.CodeOf(err)
			w.Header().Set("Tnl-Error-Code", string(code))
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(alias.Close)
	get := func(address string, status int, body, code string) {
		t.Helper()
		response, err := alias.Client().Get(address)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || response.StatusCode != status || string(data) != body || response.Header.Get("Tnl-Error-Code") != code {
			t.Fatalf("alias HTTP: status=%d body=%s code=%s read=%v close=%v", response.StatusCode, data, response.Header.Get("Tnl-Error-Code"), err, closeErr)
		}
	}
	get(alias.URL, http.StatusOK, "selected-primary", "")
	get(sibling.URL, http.StatusOK, "healthy-feature", "")
	if err := f.main.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	primary.Close()
	get(alias.URL, http.StatusServiceUnavailable, "", string(diagnostic.AliasUnavailable))
	get(sibling.URL, http.StatusOK, "healthy-feature", "")
	if eligible, err := worker.Eligible(t.Context()); err != nil || eligible {
		t.Fatal("stopped selected app retained alias eligibility", err)
	}
	other := AliasPublisher(f.state, store, f.selection, f.linked.ID(), aliasSnapshot(f.selection, id), nil)
	if eligible, err := other.Eligible(t.Context()); err != nil || eligible {
		t.Fatal("healthy sibling silently acquired a stopped app's alias", err)
	}
	selection, err := f.state.AliasSelection(t.Context(), f.selection.Scope)
	if err != nil || selection.Project != f.selection.Project || selection.Revision != f.selection.Revision {
		t.Fatal("alias failure changed the visible selected worktree", err)
	}
}

func TestAliasOAuthReturnsToInitiatingOriginAndExpiresAcrossHandoff(t *testing.T) {
	f := newAliasFixture(t)
	selection, receiver, err := f.state.AliasCandidate(t.Context(), f.selection.ID)
	if err != nil {
		t.Fatal(err)
	}
	aliasID, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	readyIntegrationURL(t, f.state, testOAuthHost, "oauth-publisher")
	prepared := aliasPreparation(t, aliasID, selection.Hostname, 1)
	if err := f.state.MarkIntegrationURLReady(t.Context(), testServer, prepared.Hostname, "alias-publisher", prepared.ServiceId, uint64(prepared.RunNumber)); err != nil {
		t.Fatal(err)
	}
	if err := f.state.MarkAliasRunReady(t.Context(), clientstate.AliasPublishRun{Selection: selection, Receiver: receiver, Owner: "alias-owner", ServiceID: prepared.ServiceId, Number: uint64(prepared.RunNumber)}); err != nil {
		t.Fatal(err)
	}
	observer := Observer(f.state, testServer, testOAuthHost, f.group, f.main.ID())
	run := publisherservice.HTTPRun{Hostname: prepared.Hostname, ServiceID: prepared.ServiceId, RunID: prepared.ServiceRunId, Number: prepared.RunNumber}
	for _, state := range []string{"returns-to-alias", "expires-on-handoff"} {
		if err := observer(authorizationResponse(state, ""), run); err != nil {
			t.Fatal(err)
		}
	}
	handler := OAuthHandler(f.state, testServer, testOAuthHost, nil)
	request := httptest.NewRequest(http.MethodGet, "https://"+testOAuthHost+"/api/auth/callback/github?state=returns-to-alias&code=provider-code", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "https://"+selection.Hostname+"/api/auth/callback/github?state=returns-to-alias&code=provider-code" {
		t.Fatalf("alias-origin callback = %d %s", response.Code, response.Header().Get("Location"))
	}
	if _, err := f.state.SelectAlias(t.Context(), selection.Scope, f.linkedProject, true); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "https://"+testOAuthHost+"/api/auth/callback/github?state=expires-on-handoff&code=provider-code", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Header().Get("Tnl-Error-Code") != string(diagnostic.OAuthCallbackExpired) || response.Header().Get("Location") != "" {
		t.Fatal("callback from the old alias run reached the new worktree")
	}
}

func TestAliasFinalOAuthHopRejectsReplacementRun(t *testing.T) {
	f := newAliasFixture(t)
	selection, receiver, err := f.state.AliasCandidate(t.Context(), f.selection.ID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	readyIntegrationURL(t, f.state, testOAuthHost, "oauth")
	prepared := aliasPreparation(t, id, selection.Hostname, 1)
	if err := f.state.MarkIntegrationURLReady(t.Context(), testServer, prepared.Hostname, "alias", prepared.ServiceId, uint64(prepared.RunNumber)); err != nil {
		t.Fatal(err)
	}
	if err := f.state.MarkAliasRunReady(t.Context(), clientstate.AliasPublishRun{Selection: selection, Receiver: receiver, Owner: "first", ServiceID: prepared.ServiceId, Number: uint64(prepared.RunNumber)}); err != nil {
		t.Fatal(err)
	}
	observer := Observer(f.state, testServer, testOAuthHost, f.group, f.main.ID())
	if err := observer(authorizationResponse("between-hops", ""), publisherservice.HTTPRun{Hostname: prepared.Hostname, ServiceID: prepared.ServiceId, RunID: prepared.ServiceRunId, Number: prepared.RunNumber}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	OAuthHandler(f.state, testServer, testOAuthHost, nil).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://"+testOAuthHost+"/api/auth/callback/github?state=between-hops&code=opaque", nil))
	if response.Code != http.StatusSeeOther {
		t.Fatal("stable callback did not redirect")
	}
	if _, err := f.state.SelectAlias(t.Context(), selection.Scope, f.linkedProject, true); err != nil {
		t.Fatal(err)
	}
	store, err := f.state.Server(t.Context(), testServer)
	if err != nil {
		t.Fatal(err)
	}
	worker := AliasPublisher(f.state, store, selection, f.linked.ID(), aliasSnapshot(selection, id), nil)
	snapshot, err := worker.Prepare(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, response.Header().Get("Location"), nil)
	replacement := aliasPreparation(t, id, selection.Hostname, prepared.RunNumber+1)
	if err := snapshot.Config.Prepared(replacement); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Config.AdmitRequest(request); err != nil {
		t.Fatal("current alias ownership was rejected before claim validation", err)
	}
	_, err = snapshot.Config.HTTPPrepareRequest(request, publisherservice.HTTPRun{ServiceID: id,
		RunID: replacement.ServiceRunId, Hostname: selection.Hostname, Number: replacement.RunNumber})
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.OAuthCallbackExpired {
		t.Fatalf("final-hop selection check = %v", err)
	}
}

func TestAliasPublisherReadinessKeepsThePreparedServiceRunThroughRenewalAndDrain(t *testing.T) {
	f := newAliasFixture(t)
	store, err := f.state.Server(t.Context(), testServer)
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	prepared := aliasPreparation(t, id, f.selection.Hostname, 7)
	worker := AliasPublisher(f.state, store, f.selection, f.main.ID(), aliasSnapshot(f.selection, id), nil)
	started, renewed := make(chan error, 1), make(chan struct{}, 1)
	draining, release, retire := make(chan struct{}), make(chan struct{}), make(chan struct{})
	revision := worker.Revision
	worker.Revision = func(ctx context.Context) (string, error) {
		current, err := revision(ctx)
		// serve checks the revision after renewing the captured run's lease.
		select {
		case renewed <- struct{}{}:
		default:
		}
		// keep cancellation out of the revision's SQLite read, then let the
		// test retire this snapshot after inspecting its renewed run facts.
		select {
		case <-retire:
			return current + ":retired", err
		case <-ctx.Done():
			return current, err
		}
	}
	worker.run = func(ctx context.Context, cfg publisherservice.RunConfig) error {
		if err := cfg.Prepared(prepared); err != nil {
			started <- err
			return err
		}
		if err := cfg.Ready(); err != nil {
			started <- err
			return err
		}
		started <- nil
		<-ctx.Done()
		cfg.ObserveReadiness(publisherservice.RunStatus{Ready: false})
		close(draining)
		<-release
		return nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	result, done := make(chan error, 1), make(chan struct{})
	go func() { defer close(done); result <- worker.serve(ctx, time.Millisecond).Err() }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-retire:
		default:
			close(retire)
		}
		select {
		case <-release:
		default:
			close(release)
		}
		waitIntegrationURLPublisher(t, done)
	})
	if err := waitIntegrationURLPublisher(t, started); err != nil {
		t.Fatal(err)
	}
	waitIntegrationURLPublisher(t, renewed)
	snapshot, err := f.state.SnapshotProject(t.Context(), f.group.PrimaryProjectRoot)
	if err != nil || len(snapshot.Aliases) != 1 || snapshot.Aliases[0].State != "ready" ||
		snapshot.Aliases[0].ServiceID != prepared.ServiceId || snapshot.Aliases[0].RunNumber != uint64(prepared.RunNumber) {
		t.Fatal("alias readiness or renewal lost the actual prepared service run", snapshot.Aliases, err)
	}
	close(retire)
	waitIntegrationURLPublisher(t, draining)
	snapshot, err = f.state.SnapshotProject(t.Context(), f.group.PrimaryProjectRoot)
	if err != nil || len(snapshot.Aliases) != 1 || snapshot.Aliases[0].State == "ready" {
		t.Fatal("alias readiness survived into drain", snapshot.Aliases, err)
	}
	select {
	case <-done:
		t.Fatal("alias serving operation returned before its publisher joined")
	default:
	}
	close(release)
	if err := waitIntegrationURLPublisher(t, result); err != nil {
		t.Fatal(err)
	}
}
