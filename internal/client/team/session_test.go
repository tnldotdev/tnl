package team

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/zalando/go-keyring"
)

type selectedTeamAPI struct {
	API
	domainCalls int
}

func (api *selectedTeamAPI) GetTeam(_ context.Context, id string) (authorityv1.Team, error) {
	return authorityv1.Team{Id: id, DisplayName: id}, nil
}

func (api *selectedTeamAPI) ListTeamDomains(_ context.Context, _ string) (authorityv1.DomainPage, error) {
	api.domainCalls++
	return authorityv1.DomainPage{}, errors.New("domain service unavailable")
}

func TestTeamSelectionDoesNotRequireDomains(t *testing.T) {
	db, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := db.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSelectedTeam(t.Context(), "removed-team"); err != nil {
		t.Fatal(err)
	}
	api := &selectedTeamAPI{}
	session := Session{store: store, api: api, identity: authorityv1.IdentityContext{
		PersonalTeamId: "personal", Memberships: []authorityv1.Membership{
			{TeamId: "personal", TeamDisplayName: "Personal"},
			{TeamId: "studio-id", TeamDisplayName: "studio"},
			{TeamId: "other-id", TeamDisplayName: "other"},
		},
	}}
	current, err := session.Current(t.Context())
	if err != nil || current.team.Id != "personal" || api.domainCalls != 0 {
		t.Fatalf("stale saved team: %#v, %v; domain reads %d", current, err, api.domainCalls)
	}
	selected, _, err := store.SelectedTeam(t.Context())
	if err != nil || selected != "personal" {
		t.Fatalf("saved team = %q, %v", selected, err)
	}
	session.selectedTeam, session.projectTeam = "studio", "stale-project"
	current, err = session.Current(t.Context())
	if err != nil || current.team.Id != "studio-id" || api.domainCalls != 0 {
		t.Fatalf("explicit slug selection: %#v, %v; domain reads %d", current, err, api.domainCalls)
	}
	if _, err := session.CurrentWithDomains(t.Context()); err == nil || api.domainCalls != 1 {
		t.Fatalf("domain-dependent selection: %v; domain reads %d", err, api.domainCalls)
	}
	selected, _, err = store.SelectedTeam(t.Context())
	if err != nil || selected != "personal" {
		t.Fatalf("one-command override changed saved team: %q, %v", selected, err)
	}
	if _, err := session.ResolveMembership(t.Context(), "missing"); err == nil {
		t.Fatal("missing team was accepted")
	} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.TeamNotFound {
		t.Fatalf("missing team reason = %q, %v", reason, err)
	}
	session.identity.Memberships = append(session.identity.Memberships, authorityv1.Membership{TeamId: "another", TeamDisplayName: "studio"})
	if _, err := session.ResolveMembership(t.Context(), "studio"); err == nil {
		t.Fatal("ambiguous team was accepted")
	} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.TeamSelectionAmbiguous {
		t.Fatalf("ambiguous team reason = %q, %v", reason, err)
	}
}

func TestTeamConfiguredInitialSelection(t *testing.T) {
	db, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := db.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	session := Session{store: store, api: &selectedTeamAPI{}, identity: authorityv1.IdentityContext{PersonalTeamId: "personal", DefaultTeamId: new("studio"), Memberships: []authorityv1.Membership{{TeamId: "personal"}, {TeamId: "studio"}}}}
	current, err := session.Current(t.Context())
	if err != nil || current.team.Id != "studio" {
		t.Fatalf("initial team: %#v %v", current, err)
	}
	if err := store.SaveSelectedTeam(t.Context(), "personal"); err != nil {
		t.Fatal(err)
	}
	current, err = session.Current(t.Context())
	if err != nil || current.team.Id != "personal" {
		t.Fatalf("saved selection lost precedence: %#v %v", current, err)
	}
}

func TestTeamMembershipPriorityAndDiagnostics(t *testing.T) {
	db, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := db.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSelectedTeam(t.Context(), "saved"); err != nil {
		t.Fatal(err)
	}
	session := Session{store: store, identity: authorityv1.IdentityContext{
		PersonalTeamId: "personal", DefaultTeamId: new("initial"), Memberships: []authorityv1.Membership{
			{TeamId: "personal"}, {TeamId: "initial"}, {TeamId: "saved"},
			{TeamId: "studio", TeamDisplayName: "id-wins"},
			{TeamId: "project", TeamDisplayName: "studio"},
		},
	}}
	for _, test := range []struct{ explicit, project, want string }{
		{explicit: "studio", project: "missing", want: "studio"},
		{project: "studio", want: "studio"},
		{project: "project", want: "project"},
		{want: "saved"},
	} {
		session.selectedTeam, session.projectTeam = test.explicit, test.project
		got, err := session.CurrentMembership(t.Context())
		if err != nil || got.TeamId != test.want {
			t.Fatalf("selection %+v: %+v, %v", test, got, err)
		}
		if saved, _, err := store.SelectedTeam(t.Context()); err != nil || saved != "saved" {
			t.Fatalf("override changed saved selection: %q, %v", saved, err)
		}
	}
	session.projectTeam = "missing"
	_, err = session.CurrentMembership(t.Context())
	want := `resolve project team "missing": select team: team "missing" is not in the current identity's memberships (use --team to override or tnl team list to find a membership)`
	if reason, _, ok := failure.Describe(err); !ok || reason != failure.TeamNotFound || !strings.Contains(err.Error(), want) {
		t.Fatalf("project team diagnostic: %v", err)
	}
	session.identity.Memberships = append(session.identity.Memberships,
		authorityv1.Membership{TeamId: "first", TeamDisplayName: "duplicate"},
		authorityv1.Membership{TeamId: "second", TeamDisplayName: "duplicate"})
	_, err = session.ResolveMembership(t.Context(), "duplicate")
	if reason, _, ok := failure.Describe(err); !ok || reason != failure.TeamSelectionAmbiguous || !strings.Contains(err.Error(), `team name "duplicate" is ambiguous; matching IDs: first, second`) {
		t.Fatalf("ambiguous team diagnostic: %v", err)
	}
	session.projectTeam = ""
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.CurrentMembership(t.Context()); err == nil {
		t.Fatal("unavailable saved state was replaced with the initial team")
	}
}

func TestTeamSessionOpenAndLifetime(t *testing.T) {
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	domainReads := 0
	var identityReads, teamCreates atomic.Int64
	var teamCreated atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+token.String() {
			t.Errorf("missing explicit authentication on %s", r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var response any
		switch r.URL.Path {
		case "/v1/discovery":
			response = controlv1.ControlDiscovery{ManagedUrlMode: "simple", Authentication: controlv1.AuthenticationFacts{
				Methods: []controlv1.AuthenticationFactsMethods{controlv1.Oidc},
				Oidc:    &controlv1.OIDCAuthenticationFacts{Issuer: "https://identity.example", LoginFlow: controlv1.DeviceCode},
			}}
		case "/v1/identity":
			identityReads.Add(1)
			identity := authorityv1.IdentityContext{PersonalTeamId: "personal", Memberships: []authorityv1.Membership{
				{TeamId: "personal"}, {TeamId: "project", MemberSlug: "alex"},
			}}
			if teamCreated.Load() {
				identity.Memberships = append(identity.Memberships, authorityv1.Membership{
					TeamId: "created", TeamDisplayName: "new-studio", MemberSlug: "new-member", Role: authorityv1.TeamRoleOwner,
				})
			}
			response = identity
		case "/v1/teams":
			var request authorityv1.CreateTeamRequest
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&request) != nil || request.DisplayName != "new-studio" {
				t.Error("unexpected team creation request")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			teamCreates.Add(1)
			teamCreated.Store(true)
			w.WriteHeader(http.StatusCreated)
			response = authorityv1.Team{Id: "created", DisplayName: "new-studio", Kind: authorityv1.Organization, DefaultDomainId: "domain"}
		case "/v1/teams/project":
			response = authorityv1.Team{Id: "project", DisplayName: "studio", Kind: authorityv1.Organization, DefaultDomainId: "domain"}
		case "/v1/teams/created":
			response = authorityv1.Team{Id: "created", DisplayName: "new-studio", Kind: authorityv1.Organization, DefaultDomainId: "domain"}
		case "/v1/teams/project/domains", "/v1/teams/created/domains":
			domainReads++
			response = authorityv1.DomainPage{Domains: []authorityv1.Domain{{Id: "domain", CanonicalDomain: "example.test", Kind: authorityv1.Managed, State: authorityv1.DomainStateReady}}}
		default:
			t.Errorf("unexpected team session request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	session, err := Open(t.Context(), Options{StateDir: filepath.Join(t.TempDir(), "state"), ServerURL: server.URL,
		AccessToken: token.String(), ProjectTeam: "project", HTTPClient: server.Client(), Diagnostics: io.Discard,
		AuthenticationPrompt: func(clientauth.Prompt) error { t.Error("unexpected authentication prompt"); return nil },
		OpenURL:              func(string) error { t.Error("unexpected browser opener"); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	current, err := session.Current(t.Context())
	if err != nil || current.Team().Id != "project" || domainReads != 0 {
		t.Fatalf("team-only context: %+v, %v; domain reads %d", current, err, domainReads)
	}
	current, err = session.CurrentWithDomains(t.Context())
	if err != nil || len(current.Domains()) != 1 || domainReads != 1 {
		t.Fatalf("team domains: %+v, %v; domain reads %d", current, err, domainReads)
	}
	if namespace, _ := current.Namespace(current.Domains()[0]); namespace != "alex.studio.example.test" {
		t.Fatalf("discovery mode was lost: %q", namespace)
	}
	borrowed := NewSession(nil, session.Store(), session.Authenticated(), session.Identity(), Options{SelectedTeam: "project"})
	if err := borrowed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := session.Store().SelectedTeam(t.Context()); err != nil {
		t.Fatalf("borrowed session closed its caller's state: %v", err)
	}
	t.Run("team_creation_requires_fresh_identity", func(t *testing.T) {
		created, err := session.Authenticated().Authority.CreateTeam(t.Context(), authorityv1.CreateTeamRequest{DisplayName: "new-studio"}, "create-team")
		if err != nil {
			t.Fatal(err)
		}
		options := Options{ProjectTeam: "new-studio"}
		stale := NewSession(nil, session.Store(), session.Authenticated(), session.Identity(), options)
		if _, err := stale.CurrentWithDomains(t.Context()); err == nil {
			t.Fatal("pre-creation identity unexpectedly authorized the new team")
		} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.TeamNotFound {
			t.Fatalf("stale identity selection: %v", err)
		}
		if identityReads.Load() != 1 || teamCreates.Load() != 1 {
			t.Fatalf("selection implicitly refreshed identity or repeated creation: identity reads %d, creations %d", identityReads.Load(), teamCreates.Load())
		}
		identity, err := session.Authenticated().Authority.IdentityContext(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		fresh := NewSession(nil, session.Store(), session.Authenticated(), identity, options)
		current, err := fresh.CurrentWithDomains(t.Context())
		if err != nil || current.Team().Id != created.Id || current.Membership().TeamId != created.Id || len(current.Domains()) != 1 {
			t.Fatalf("post-creation identity selection: %+v, %v", current, err)
		}
		if namespace, _ := current.Namespace(current.Domains()[0]); namespace != "new-member.new-studio.example.test" {
			t.Fatalf("fresh membership namespace = %q", namespace)
		}
		if identityReads.Load() != 2 || teamCreates.Load() != 1 {
			t.Fatalf("explicit identity reload was not reused: identity reads %d, creations %d", identityReads.Load(), teamCreates.Load())
		}
	})
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := session.Store().SelectedTeam(t.Context()); err == nil {
		t.Fatal("owned session did not close client state")
	}
}

func TestTeamSessionRejectsGuestBeforeAuthentication(t *testing.T) {
	keyring.MockInit()
	root := filepath.Join(t.TempDir(), "state")
	db, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := "https://control.example.test"
	store, err := db.Server(t.Context(), server)
	if err != nil {
		t.Fatal(err)
	}
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGuestSession(t.Context(), clientstate.GuestSession{
		GuestID: "gst_0123456789abcdefghijkl", AccessToken: token.String(), ExpiresAt: time.Now().Add(time.Hour),
		TeamID: "tm_0123456789abcdefghijkl", MembershipID: "mem_0123456789abcdefghijkl", DomainID: "dom_0123456789abcdefghijkl", Namespace: "guest.example.test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveServer(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	session, err := Open(t.Context(), Options{StateDir: root})
	if reason, _, ok := failure.Describe(err); session != nil || !ok || reason != failure.GuestSignInRequired || !strings.Contains(err.Error(), "saved guest credential does not authorize this command") {
		t.Fatalf("guest command = %+v, %v", session, err)
	}
	if err := clientauth.RequireSignInOutsideDemo(t.Context(), db, server, token.String()); err != nil {
		t.Fatalf("explicit credential was replaced with a guest: %v", err)
	}
}
