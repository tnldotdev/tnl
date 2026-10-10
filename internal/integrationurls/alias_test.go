package integrationurls

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type aliasFixture struct {
	state                *clientstate.Database
	selection            clientstate.AliasSelection
	main, linked         *clientstate.Tunnel
	group, linkedProject string
}

func newAliasFixture(t *testing.T) aliasFixture {
	t.Helper()
	state, _ := callbackState(t)
	primary := filepath.Join(t.TempDir(), "main")
	linked := filepath.Join(filepath.Dir(primary), "feature")
	scope := clientstate.AliasScope{Server: testServer, ProjectKey: primary, TeamID: "team_fixture", MembershipID: "member_fixture", Namespace: "member.example.test", Name: "review"}
	group := primary + "\x00" + scope.Namespace
	f := aliasFixture{state: state, group: group, linkedProject: linked}
	for index, project := range []string{primary, linked} {
		tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish,
			Server: testServer, Project: project, Service: "api", Target: "3000", IntegrationGroup: group})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
		id, err := opaqueid.New(opaqueid.PublicURLPrefix)
		if err != nil {
			t.Fatal(err)
		}
		hostname := []string{"api-main", "api-feature"}[index] + "." + scope.Namespace
		if err := tunnel.SetPublicURL(t.Context(), id, hostname); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.SetReady(t.Context(), "https://"+hostname, 1); err != nil {
			t.Fatal(err)
		}
		selection, err := state.RegisterAlias(t.Context(), clientstate.AliasRegistration{Scope: scope,
			Hostname: "review." + scope.Namespace, Service: "api", TunnelID: tunnel.ID(), IntegrationGroup: group, Fingerprint: sha256.Sum256([]byte("review"))})
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

func TestAliasRequestsAreFencedImmediatelyAfterSelectionChange(t *testing.T) {
	f := newAliasFixture(t)
	store, err := f.state.Server(t.Context(), testServer)
	if err != nil {
		t.Fatal(err)
	}
	worker := AliasPublisher(f.state, store, f.selection, f.main.ID(), publisher.Config{Hostname: f.selection.Hostname, PreviewID: "old-preview", Feedback: true}, nil)
	snapshot, err := worker.Prepare(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://"+f.selection.Hostname+"/", nil)
	if snapshot.Config.PreviewID != "" || snapshot.Config.Feedback {
		t.Fatal("alias inherited preview share or feedback state")
	}
	if err := snapshot.Config.AdmitRequest(request, publisher.PublishRunIdentity{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.SelectAlias(t.Context(), f.selection.Scope, f.linkedProject, true); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Config.AdmitRequest(request, publisher.PublishRunIdentity{}); err == nil {
		t.Fatal("old publisher admitted a request after handoff")
	} else if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.AliasUnavailable {
		t.Fatalf("handoff rejection = %v", err)
	}
	eligible, err := worker.Eligible(t.Context())
	if err != nil || eligible {
		t.Fatal("old worktree retained publication eligibility")
	}
}

func TestAliasOAuthReturnsToInitiatingOriginAndExpiresAcrossHandoff(t *testing.T) {
	f := newAliasFixture(t)
	selection, receiver, err := f.state.AliasCandidate(t.Context(), f.selection.ID)
	if err != nil {
		t.Fatal(err)
	}
	aliasID, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.state.MarkIntegrationURLReady(t.Context(), testServer, testOAuthHost, "oauth-publisher"); err != nil {
		t.Fatal(err)
	}
	if err := f.state.MarkIntegrationURLReady(t.Context(), testServer, selection.Hostname, "alias-publisher"); err != nil {
		t.Fatal(err)
	}
	if err := f.state.MarkAliasRunReady(t.Context(), clientstate.AliasPublishRun{Selection: selection, Receiver: receiver, Owner: "alias-owner", PublicURLID: aliasID, Number: 1}); err != nil {
		t.Fatal(err)
	}
	observer := Observer(f.state, testServer, testOAuthHost, f.group, f.main.ID())
	run := publisher.PublishRunIdentity{Hostname: selection.Hostname, PublicURLID: aliasID, Number: 1}
	for _, state := range []string{"returns-to-alias", "expires-on-handoff"} {
		if err := observer(authorizationResponse(state, ""), run); err != nil {
			t.Fatal(err)
		}
	}
	handler := OAuthHandler(f.state, testServer, testOAuthHost)
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
	id, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.state.MarkIntegrationURLReady(t.Context(), testServer, testOAuthHost, "oauth"); err != nil {
		t.Fatal(err)
	}
	if err := f.state.MarkIntegrationURLReady(t.Context(), testServer, selection.Hostname, "alias"); err != nil {
		t.Fatal(err)
	}
	if err := f.state.MarkAliasRunReady(t.Context(), clientstate.AliasPublishRun{Selection: selection, Receiver: receiver, Owner: "first", PublicURLID: id, Number: 1}); err != nil {
		t.Fatal(err)
	}
	observer := Observer(f.state, testServer, testOAuthHost, f.group, f.main.ID())
	if err := observer(authorizationResponse("between-hops", ""), publisher.PublishRunIdentity{Hostname: selection.Hostname, PublicURLID: id, Number: 1}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	OAuthHandler(f.state, testServer, testOAuthHost).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://"+testOAuthHost+"/api/auth/callback/github?state=between-hops&code=opaque", nil))
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
	worker := AliasPublisher(f.state, store, selection, f.linked.ID(), publisher.Config{Hostname: selection.Hostname}, nil)
	snapshot, err := worker.Prepare(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, response.Header().Get("Location"), nil)
	err = snapshot.Config.AdmitRequest(request, publisher.PublishRunIdentity{Hostname: selection.Hostname, PublicURLID: id, Number: 2})
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.OAuthCallbackExpired {
		t.Fatalf("final-hop selection check = %v", err)
	}
}
