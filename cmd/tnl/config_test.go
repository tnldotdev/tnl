package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestConfigPathDoesNotEvaluateTypeScript(t *testing.T) {
	directory := t.TempDir()
	stateRoot := filepath.Join(directory, "state")
	configPath := filepath.Join(directory, "tnl.config.ts")
	markerPath := filepath.Join(directory, "evaluated")
	source := `import { writeFileSync } from "node:fs";
writeFileSync("evaluated", "yes");
export default {};`
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)

	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"config", "path"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "-- selected ") || !strings.Contains(stdout.String(), "tnl.config.ts") {
		t.Fatalf("config path output = %q", stdout.String())
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("config path evaluated tnl.config.ts: %v", err)
	}
	if _, err := os.Stat(stateRoot); !os.IsNotExist(err) {
		t.Fatalf("config path created client state: %v", err)
	}
	stdout.Reset()
	if err := run(t.Context(), []string{"config", "check", "--state-dir", stateRoot}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("config check did not evaluate tnl.config.ts: %v", err)
	}
}

func TestProjectConfigurationUsesStateSpecificWorktreeLabelEverywhere(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "tnl.config.ts")
	source := `export default ({worktree}: any) => ({
  tunnel: {subdomain: worktree.label},
  publish: {target: 3000},
});`
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)
	flags := cli{}
	firstRoot := filepath.Join(directory, "first-state")
	first, err := loadProjectConfiguration(t.Context(), flags, firstRoot)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := loadProjectConfiguration(t.Context(), flags, firstRoot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadProjectConfiguration(t.Context(), flags, filepath.Join(directory, "second-state"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Worktree.Label == "" || first.Worktree.Label != repeated.Worktree.Label ||
		first.Worktree.Label == second.Worktree.Label || first.Config.Tunnel == nil || first.Config.Tunnel.Subdomain == nil ||
		*first.Config.Tunnel.Subdomain != first.Worktree.Label {
		t.Fatalf("worktree labels = %q, %q, %q; config = %#v", first.Worktree.Label, repeated.Worktree.Label, second.Worktree.Label, first.Config)
	}
	publish := publishCommand{}
	if err := first.applyPublish(&publish); err != nil {
		t.Fatal(err)
	}
	if publish.Subdomain != first.Worktree.Label {
		t.Fatalf("publish subdomain = %q, worktree label = %q", publish.Subdomain, first.Worktree.Label)
	}
}

func TestProjectConfigurationAppliesPrecedenceUnits(t *testing.T) {
	t.Setenv("TNL_SERVER", "https://environment.example")
	t.Setenv("TNL_HOST", "environment.example")
	t.Setenv("TNL_TEAM", "Environment Team")
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"publish", "--allow-ip", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	projectServer := "https://project.example"
	projectSubdomain := "project"
	public := true
	target := config.Target("3000")
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Server:  &projectServer,
		Tunnel:  &config.Tunnel{Subdomain: &projectSubdomain, Public: &public},
		Publish: &config.Publish{Target: &target},
	}}}
	if err := project.applyPublish(&flags.Publish); err != nil {
		t.Fatal(err)
	}
	if flags.Publish.ServerURL != "https://environment.example" || flags.Publish.Host != "environment.example" ||
		flags.Publish.selectedTeam != "Environment Team" ||
		flags.Publish.Subdomain != "" || flags.Publish.Target != "3000" || flags.Publish.Public ||
		!reflect.DeepEqual(flags.Publish.AllowIP, []string{"198.51.100.0/24"}) {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestProjectConfigurationSetsConfiguredCommandDirectory(t *testing.T) {
	directory := t.TempDir()
	command := []string{"vite"}
	project := projectConfiguration{
		Project: projectconfig.Project{
			Selection: projectconfig.Selection{Path: filepath.Join(directory, "tnl.yml")},
			Root:      directory,
			Config:    config.TNL{Dev: &config.Dev{Command: command}},
		},
	}
	flags := devCommand{}
	if err := project.applyDev(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.commandDir != directory || !reflect.DeepEqual(flags.Command, command) {
		t.Fatalf("configured dev command = %#v in %q", flags.Command, flags.commandDir)
	}
}

func TestProjectConfigurationResolvesNamedServiceAndBuiltInHostname(t *testing.T) {
	root := t.TempDir()
	rootServer := "https://root.example"
	serviceTeam := "Frontend Team"
	target := config.Target("4173")
	rootTimeout := config.Duration(20 * time.Second)
	project := projectConfiguration{
		Project: projectconfig.Project{
			Root: root,
			Worktree: projectconfig.Worktree{
				Root: root, Label: "feature-abcdef12",
			},
			Config: config.TNL{
				Server: &rootServer,
				Dev:    &config.Dev{StartupTimeout: &rootTimeout},
				Services: map[string]config.Service{
					"web": {Team: &serviceTeam, Publish: &config.Publish{Target: &target}},
				},
			},
		},
	}
	flags := publishCommand{Target: "web"}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.Service != "web" || flags.Target != "4173" || flags.ServerURL != rootServer ||
		flags.selectedTeam != serviceTeam || flags.projectRoot != root || flags.Subdomain != "web-feature-abcdef12" {
		t.Fatalf("publish flags = %#v", flags)
	}

	dev := devCommand{}
	if err := project.applyDev(&dev); err != nil {
		t.Fatal(err)
	}
	if dev.Service != "web" || dev.StartupTimeout != 20*time.Second || dev.Subdomain != "web-feature-abcdef12" {
		t.Fatalf("dev flags = %#v", dev)
	}
}

func TestPublishArgumentThatIsNotAServiceRemainsTarget(t *testing.T) {
	project := projectConfiguration{
		Project: projectconfig.Project{
			Root:     t.TempDir(),
			Worktree: projectconfig.Worktree{Label: "project-abcdef12"},
			Config: config.TNL{Services: map[string]config.Service{
				"web": {},
			}},
		},
	}
	flags := publishCommand{Target: "3000"}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.Service != "" || flags.Target != "3000" || flags.Subdomain != "project-abcdef12" {
		t.Fatalf("publish flags = %#v", flags)
	}
}

func TestProjectConfigurationRequiresServiceWhenAmbiguous(t *testing.T) {
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Services: map[string]config.Service{
		"api": {}, "web": {},
	}}}}
	if err := project.applyDev(&devCommand{}); err == nil || err.Error() != "service is required; configured services: api, web" {
		t.Fatalf("ambiguous service error = %v", err)
	} else if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.ServiceAmbiguous {
		t.Fatalf("ambiguous service diagnostic = %q, %t", code, ok)
	}
}

func TestProjectConfigurationUsesServiceDirectoryAsChildCWD(t *testing.T) {
	root := t.TempDir()
	serviceDirectory := filepath.Join(root, "apps", "web")
	if err := os.MkdirAll(serviceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := "apps/web"
	project := projectConfiguration{
		Project: projectconfig.Project{
			Root: root, Worktree: projectconfig.Worktree{Label: "tnl-bb4eff12"},
			Config:             config.TNL{Services: config.Services{"web": {Directory: &directory}}},
			ServiceDirectories: map[string]string{"web": serviceDirectory},
		},
	}
	flags := devCommand{Service: "web", Command: []string{"sh"}}
	if err := project.applyDev(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.commandDir != serviceDirectory {
		t.Fatalf("child cwd = %q", flags.commandDir)
	}
}

func TestConfiguredProjectHostnameFixture(t *testing.T) {
	current := teamContext{
		team: authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_1"},
		membership: authorityv1.Membership{
			Id: "membership_1", TeamId: "team_1", Role: authorityv1.TeamRoleMember,
			ManagedLabel: "busy-toast", MemberSlug: "chase",
		},
		domains: []authorityv1.Domain{{
			Id: "domain_1", Kind: authorityv1.Managed, CanonicalDomain: "tnl.dev", State: authorityv1.DomainStateReady,
		}},
	}
	service, err := configuredProjectService(
		"api", projectconfig.Worktree{Label: "tnl-bb4eff12"}, config.TNL{}, current,
	)
	if err != nil {
		t.Fatal(err)
	}
	if service.MemberNamespace != "busy-toast.tnl.dev" || service.Hostname != "api-tnl-bb4eff12.busy-toast.tnl.dev" ||
		service.URL != "https://api-tnl-bb4eff12.busy-toast.tnl.dev" {
		t.Fatalf("service metadata = %#v", service)
	}
}

func TestEphemeralTunnelDoesNotReceiveWorktreeSubdomain(t *testing.T) {
	flags := tunnelFlags{Ephemeral: true}
	applyBuiltInHostname(&flags, "api", projectconfig.Worktree{Label: "tnl-bb4eff12"})
	if flags.Host != "" || flags.Subdomain != "" {
		t.Fatalf("ephemeral hostname flags = %#v", flags)
	}
}

func TestEphemeralConfigUsesMetadataHostnameOnlyWithoutRuntimeContextOverride(t *testing.T) {
	ephemeral := true
	project := projectConfiguration{
		Project: projectconfig.Project{
			Root: t.TempDir(), Worktree: projectconfig.Worktree{Label: "tnl-bb4eff12"},
			Config: config.TNL{
				Tunnel: &config.Tunnel{Ephemeral: &ephemeral},
				Services: config.Services{
					"api": {},
				},
			},
			ServiceDirectories: map[string]string{"api": t.TempDir()},
		},
	}
	withoutOverride := devCommand{Service: "api"}
	if err := project.applyDev(&withoutOverride); err != nil {
		t.Fatal(err)
	}
	if !withoutOverride.useMetadataHostname {
		t.Fatal("configured ephemeral service did not use its generated metadata hostname")
	}
	withOverride := devCommand{Service: "api", tunnelFlags: tunnelFlags{Team: "Other Team"}}
	if err := project.applyDev(&withOverride); err != nil {
		t.Fatal(err)
	}
	if withOverride.useMetadataHostname {
		t.Fatal("runtime team override reused the static project metadata hostname")
	}
	withExplicitFalse := devCommand{
		Service:     "api",
		tunnelFlags: tunnelFlags{ephemeralFromCLI: true},
	}
	if err := project.applyDev(&withExplicitFalse); err != nil {
		t.Fatal(err)
	}
	if withExplicitFalse.useMetadataHostname || withExplicitFalse.Ephemeral || withExplicitFalse.Subdomain != "api-tnl-bb4eff12" {
		t.Fatalf("explicit false ephemeral flags = %#v", withExplicitFalse)
	}
}

func TestProjectCommandContextUsesRootAndPreservesExplicitServer(t *testing.T) {
	server, team := "https://project.example", "Project Team"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Server: &server, Team: &team}}}
	flags := cli{}
	if err := applyProjectCommandContext("route list", project, &flags); err != nil {
		t.Fatal(err)
	}
	if flags.Route.List.ServerURL != server || flags.Route.List.ProjectTeam != team {
		t.Fatalf("route flags = %#v", flags.Route.List)
	}
	flags.Domain.List.ServerURL = "https://explicit.example"
	if err := applyProjectCommandContext("domain list", project, &flags); err != nil {
		t.Fatal(err)
	}
	if flags.Domain.List.ServerURL != "https://explicit.example" || flags.Domain.List.ProjectTeam != team {
		t.Fatalf("domain flags = %#v", flags.Domain.List)
	}
	flags.Route.Delete.AccessToken = "explicit-token"
	if err := applyProjectCommandContext("route delete <route-id>", project, &flags); err == nil {
		t.Fatal("project server accepted an explicit access token without an invocation-level server")
	}
	flags.Route.Delete.ServerURL = "https://explicit.example"
	if err := applyProjectCommandContext("route delete <route-id>", project, &flags); err != nil {
		t.Fatal(err)
	}
}

func TestProjectServerSelection(t *testing.T) {
	projectServer := "https://project.example"
	for _, selected := range []string{"", "https://invocation.example"} {
		for _, project := range []*string{nil, &projectServer} {
			for _, token := range []string{"", "explicit-token"} {
				server, fromProject, err := resolveProjectServer(selected, project, token)
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

func TestPublishAndDevRejectProjectSelectedExplicitToken(t *testing.T) {
	server := "https://project.example"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Server: &server}}}
	for _, selected := range []string{"", "https://explicit.example"} {
		remote := remoteFlags{ServerURL: selected, AccessToken: "explicit-token"}
		publish := publishCommand{Target: "3000", remoteFlags: remote}
		dev := devCommand{remoteFlags: remote}
		for name, err := range map[string]error{"publish": project.applyPublish(&publish), "dev": project.applyDev(&dev)} {
			if (err != nil) != (selected == "") {
				t.Fatalf("%s selected=%q: %v", name, selected, err)
			}
		}
	}
}
