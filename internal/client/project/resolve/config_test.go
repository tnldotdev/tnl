package resolve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestProjectServerSelection(t *testing.T) {
	projectServer := "https://project.example"
	for _, selected := range []string{"", "https://invocation.example"} {
		for _, project := range []*string{nil, &projectServer} {
			for _, token := range []string{"", "explicit-token"} {
				server, fromProject, err := Server(selected, project, token)
				wantProject := selected == "" && project != nil
				wantError := wantProject && token != ""
				if (err != nil) != wantError {
					t.Fatalf("selected=%q, project=%v, token=%q: %v", selected, project, token, err)
				}
				if wantError {
					continue
				}
				want := selected
				if wantProject {
					want = projectServer
				}
				if server != want || fromProject != wantProject {
					t.Fatalf("selection = %q, %v; want %q, %v", server, fromProject, want, wantProject)
				}
			}
		}
	}
}

func TestConfiguredProjectHostnameFixture(t *testing.T) {
	root := t.TempDir()
	worktree := clientproject.ApplyWorktreeHashSalt(clientproject.Worktree{Root: root, Name: "tnl"}, root, [32]byte{1})
	selected := authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_1"}
	membership := authorityv1.Membership{Id: "membership_1", TeamId: "team_1", Role: authorityv1.TeamRoleMember, ManagedLabel: "ecstatic-penguin", MemberSlug: "chase"}
	claimed := "studio.example.test"
	domains := []authorityv1.Domain{
		{Id: "domain_1", Kind: authorityv1.Managed, CanonicalDomain: "tnl.dev", State: authorityv1.DomainStateReady},
		{Id: "domain_2", Kind: authorityv1.Custom, CanonicalDomain: claimed, State: authorityv1.DomainStateReady},
	}
	current := team.NewContext(selected, membership, domains, "")
	for _, test := range []struct {
		name, namespace string
		domain          *string
		domainID        string
	}{
		{"managed", "ecstatic-penguin.tnl.dev", nil, ""},
		{"custom", "chase.studio.example.test", &claimed, "domain_2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			project := clientproject.Project{Root: root, Worktree: worktree,
				Selection: clientproject.Selection{Path: filepath.Join(root, "tnl.json")},
				Config:    config.TNL{Services: config.Services{"api": {Public: new(true), Domain: test.domain}}}}
			state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			project, err = project.BindLocalIdentity(t.Context(), state)
			if err != nil {
				t.Fatal(err)
			}
			source, worktreeKey := project.LocalPublicationIdentity(), project.LocalWorktreeKey()
			want := clientproject.ServiceWorktreeLabel("api", worktree) + "." + test.namespace
			var requests atomic.Int32
			// control owns allocation. exercise real project declaration and
			// metadata composition instead of assembling an endpoint with leaves.
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				query := r.URL.Query()
				if r.Method != http.MethodGet || r.URL.Path != "/v1/projects/"+source.Key+"/local-services/api" ||
					query.Get("team_id") != selected.Id || query.Get("source_fingerprint") != source.Fingerprint ||
					query.Get("worktree_key") != worktreeKey {
					t.Error("metadata changed its resolved project, worktree or current team")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(controlv1.LocalProjectService{
					Service: "api", ServiceId: "svc_" + strings.Repeat("A", 22), WorktreeKey: worktreeKey,
					Metadata: &controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1,
						Endpoint: &controlv1.ServiceEndpoint{Hostname: want, Port: 443, Public: true}},
				})
			}))
			defer server.Close()
			project.Config.Server = &server.URL
			declaration, err := Declaration(t.Context(), project, current, nil, "api")
			if err != nil {
				t.Fatal(err)
			}
			intent := declaration.Services["api"]
			if intent.Target != "app" || intent.Protocol == nil || *intent.Protocol != controlv1.ServiceProtocolHTTP ||
				intent.Public == nil || !*intent.Public ||
				(test.domainID == "") != (intent.DomainId == nil) ||
				intent.DomainId != nil && *intent.DomainId != test.domainID {
				t.Fatal("resolved configuration lost its selected HTTP declaration or domain")
			}
			control, err := clientcontrol.New(server.URL, server.Client(), "visitor-session")
			if err != nil {
				t.Fatal(err)
			}
			resolver := NewMetadataResolver(nil, project, nil)
			resolver.Seed(server.URL, &auth.Client{ServerEndpoint: server.URL, Control: control})
			resolver.contexts[server.URL+"\x00"] = current
			metadata, err := resolver.Generate(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			service := metadata.Services["api"]
			if requests.Load() != 1 || len(metadata.Services) != 1 || metadata.Worktree == nil ||
				!reflect.DeepEqual(metadata.Worktree.Label, worktree.Label) ||
				service.Namespace != test.namespace || service.Hostname != want || service.URL != "https://"+want ||
				service.Port != 443 || !service.Public {
				t.Fatalf("resolved project metadata = %#v", metadata)
			}
		})
	}
}

func TestServiceEndpointRejectsMissingPublicPortAndUnknownProtocol(t *testing.T) {
	for _, protocol := range []string{"tcp", "postgres", "mysql", "kubernetes", "", "ssh"} {
		t.Run(protocol, func(t *testing.T) {
			metadata, err := meta.NewEndpoint("tnl.dev", "api.member.tnl.dev", protocol, 0, true)
			if err == nil || !reflect.DeepEqual(metadata, meta.Service{}) {
				t.Fatalf("invalid service endpoint received metadata: %+v, error: %v", metadata, err)
			}
		})
	}
}

func TestProjectRootUsesCanonicalSelectedDirectoryWithoutEvaluation(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tnl.config.ts")
	if err := os.WriteFile(path, []byte(`throw new Error("must not evaluate");`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "project")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	got, err := Root(t.Context(), Options{Directory: link, EnvironmentPath: "tnl.config.ts"})
	if err != nil || got != root {
		t.Fatalf("project root = %q, %v; want %q", got, err, root)
	}
}
