package resolve

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
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
	domains := []authorityv1.Domain{{Id: "domain_1", Kind: authorityv1.Managed, CanonicalDomain: "tnl.dev", State: authorityv1.DomainStateReady}}
	current := team.NewContext(selected, membership, domains, "")
	service, err := ConfiguredService("api", worktree, clientproject.ResolvedService{}, current)
	if err != nil {
		t.Fatal(err)
	}
	want := clientproject.ServiceWorktreeLabel("api", worktree) + ".ecstatic-penguin.tnl.dev"
	if service.Namespace != "ecstatic-penguin.tnl.dev" || service.Hostname != want || service.URL != "https://"+want || service.Port != 443 || !service.Public {
		t.Fatalf("service metadata = %#v", service)
	}
	claimed := "studio.example.test"
	domains = append(domains, authorityv1.Domain{Id: "domain_2", Kind: authorityv1.Custom, CanonicalDomain: claimed, State: authorityv1.DomainStateReady})
	current = team.NewContext(selected, membership, domains, "")
	service, err = ConfiguredService("api", worktree, clientproject.ResolvedService{Tunnel: &config.Tunnel{Domain: &claimed}}, current)
	if err != nil {
		t.Fatal(err)
	}
	want = clientproject.ServiceWorktreeLabel("api", worktree) + ".chase.studio.example.test"
	if service.Namespace != "chase.studio.example.test" || service.Hostname != want || service.URL != "https://"+want || service.Port != 443 || !service.Public {
		t.Fatalf("custom-domain metadata = %#v", service)
	}
}

func TestConfiguredServiceRejectsNonHTTPPublicURLMetadata(t *testing.T) {
	for _, protocol := range []string{"tcp", "postgres", "mysql", "kubernetes", "", "ssh"} {
		t.Run(protocol, func(t *testing.T) {
			effective := clientproject.ResolvedService{
				Publish: &config.Publish{Protocol: &protocol},
				Tunnel:  &config.Tunnel{Name: new("api")},
			}
			metadata, err := ConfiguredService("api", clientproject.Worktree{}, effective, appliedTestContext())
			if err == nil || !reflect.DeepEqual(metadata, meta.Service{}) {
				t.Fatalf("non-HTTP public URL received endpoint metadata: %+v, error: %v", metadata, err)
			}
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ProjectConfigInvalid {
				t.Fatalf("protocol rejection lost its configuration failure classification: %v", err)
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
