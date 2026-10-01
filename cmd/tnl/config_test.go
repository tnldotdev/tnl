package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestConfigPathDoesNotEvaluateTypeScript(t *testing.T) {
	directory := t.TempDir()
	stateRoot := filepath.Join(directory, "state")
	t.Setenv("TNL_STATE_DIR", stateRoot)
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
	want, err := clioutput.Render(clioutput.Frame{
		Command: "tnl config path", State: "selected", Blocks: []clioutput.Block{clioutput.Text(configPath)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != want {
		t.Fatalf("config path output = %q, want %q", got, want)
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
  tunnel: {name: worktree.label},
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
		first.Worktree.Label == second.Worktree.Label || first.Config.Tunnel == nil || first.Config.Tunnel.Name == nil ||
		*first.Config.Tunnel.Name != first.Worktree.Label {
		t.Fatalf("worktree labels = %q, %q, %q; config = %#v", first.Worktree.Label, repeated.Worktree.Label, second.Worktree.Label, first.Config)
	}
	publish := publishCommand{}
	if err := first.applyPublish(&publish); err != nil {
		t.Fatal(err)
	}
	if publish.Name != first.Worktree.Label {
		t.Fatalf("publish name = %q, worktree label = %q", publish.Name, first.Worktree.Label)
	}
}

func TestProjectConfigurationAppliesPrecedenceUnits(t *testing.T) {
	t.Setenv("TNL_SERVER", "https://environment.example")
	t.Setenv("TNL_NAME", "environment-name")
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
	projectName := "project"
	allowAllIPs := true
	target := config.Target("3000")
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Server:  &projectServer,
		Tunnel:  &config.Tunnel{Name: &projectName, AllowAllIPs: &allowAllIPs},
		Publish: &config.Publish{Target: &target},
	}}}
	if err := project.applyPublish(&flags.Publish); err != nil {
		t.Fatal(err)
	}
	if flags.Publish.ServerURL != "https://environment.example" || flags.Publish.Name != "environment-name" ||
		flags.Publish.selectedTeam != "Environment Team" ||
		flags.Publish.PublicURL != "" || flags.Publish.Target != "3000" || flags.Publish.AllowAllIPs ||
		!reflect.DeepEqual(flags.Publish.AllowIP, []string{"198.51.100.0/24"}) {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestProviderFlagsReplaceConfiguredProvidersAndCombineWithIPs(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"publish", "--allow-provider", "github", "--allow-ip", "198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	applyTunnelCLIUnits(parsed, &flags)
	target := config.Target("3000")
	root := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Tunnel:  &config.Tunnel{AllowProviders: []string{"stripe"}},
		Publish: &config.Publish{Target: &target},
	}}}
	if err := root.applyPublish(&flags.Publish); err != nil {
		t.Fatal(err)
	}
	if flags.Publish.AllowAllIPs || !reflect.DeepEqual(flags.Publish.AllowProvider, []string{"github"}) ||
		!reflect.DeepEqual(flags.Publish.AllowIP, []string{"198.51.100.0/24"}) {
		t.Fatalf("provider and IP flags = %#v", flags.Publish.tunnelFlags)
	}
	all := true
	publicFlags := tunnelFlags{AllowProvider: []string{"github"}}
	applyTunnelConfiguration(&publicFlags, &config.Tunnel{AllowAllIPs: &all})
	if publicFlags.AllowAllIPs || !reflect.DeepEqual(publicFlags.AllowProvider, []string{"github"}) {
		t.Fatalf("CLI provider did not override configured allow-all: %#v", publicFlags)
	}
}

func TestProviderFlagsRejectUnknownDuplicateAndPublicConflicts(t *testing.T) {
	for _, test := range []struct {
		name  string
		flags tunnelFlags
	}{
		{"unknown", tunnelFlags{AllowProvider: []string{"unknown"}}},
		{"duplicate", tunnelFlags{AllowProvider: []string{"stripe", "stripe"}}},
		{"public", tunnelFlags{AllowAllIPs: true, AllowProvider: []string{"github"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateTunnelFlags(test.flags); err == nil {
				t.Fatalf("invalid provider flags accepted: %#v", test.flags)
			}
		})
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
	worktree := namedTestWorktree(root, "feature")
	rootServer := "https://root.example"
	serviceTeam := "Frontend Team"
	target := config.Target("4173")
	rootTimeout := config.Duration(20 * time.Second)
	project := projectConfiguration{
		Project: projectconfig.Project{
			Root:     root,
			Worktree: worktree,
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
		flags.selectedTeam != serviceTeam || flags.projectRoot != root || flags.Name != projectconfig.ServiceWorktreeLabel("web", worktree) {
		t.Fatalf("publish flags = %#v", flags)
	}

	dev := devCommand{}
	if err := project.applyDev(&dev); err != nil {
		t.Fatal(err)
	}
	if dev.Service != "web" || dev.StartupTimeout != 20*time.Second || dev.Name != flags.Name {
		t.Fatalf("dev flags = %#v", dev)
	}
}

func TestPublishArgumentThatIsNotAServiceRemainsTarget(t *testing.T) {
	root := t.TempDir()
	worktree := namedTestWorktree(root, "project")
	project := projectConfiguration{
		Project: projectconfig.Project{
			Root:     root,
			Worktree: worktree,
			Config: config.TNL{Services: map[string]config.Service{
				"web": {},
			}},
		},
	}
	flags := publishCommand{Target: "3000"}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.Service != "" || flags.Target != "3000" || flags.Name != worktree.Label {
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
			Root: root, Worktree: namedTestWorktree(root, "tnl"),
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
	worktree := namedTestWorktree(t.TempDir(), "tnl")
	current := teamContext{
		team: authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_1"},
		membership: authorityv1.Membership{
			Id: "membership_1", TeamId: "team_1", Role: authorityv1.TeamRoleMember,
			ManagedLabel: "ecstatic-penguin", MemberSlug: "chase",
		},
		domains: []authorityv1.Domain{{
			Id: "domain_1", Kind: authorityv1.Managed, CanonicalDomain: "tnl.dev", State: authorityv1.DomainStateReady,
		}},
	}
	service, err := configuredProjectService(
		"api", worktree, config.TNL{}, current,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := projectconfig.ServiceWorktreeLabel("api", worktree) + ".ecstatic-penguin.tnl.dev"
	if service.Namespace != "ecstatic-penguin.tnl.dev" || service.Hostname != want ||
		service.URL != "https://"+want {
		t.Fatalf("service metadata = %#v", service)
	}
	claimed := "studio.example.test"
	current.domains = append(current.domains, authorityv1.Domain{
		Id: "domain_2", Kind: authorityv1.Claimed, CanonicalDomain: claimed, State: authorityv1.DomainStateReady,
	})
	service, err = configuredProjectService("api", worktree, config.TNL{Tunnel: &config.Tunnel{Domain: &claimed}}, current)
	if err != nil {
		t.Fatal(err)
	}
	want = projectconfig.ServiceWorktreeLabel("api", worktree) + ".chase.studio.example.test"
	if service.Namespace != "chase.studio.example.test" || service.Hostname != want || service.URL != "https://"+want {
		t.Fatalf("claimed-domain metadata = %#v", service)
	}
}

func TestProjectOpenAndDomainUseServiceOverridesAndCLIExplicitFalse(t *testing.T) {
	rootDomain, serviceDomain, name := "root.example.test", "service.example.test", "preview"
	configuredOpen, cliOpen := true, false
	project := projectConfiguration{Project: projectconfig.Project{
		Worktree: namedTestWorktree(t.TempDir(), "shop"),
		Config: config.TNL{
			Tunnel: &config.Tunnel{Domain: &rootDomain, Open: &configuredOpen},
			Services: config.Services{
				"web": {Tunnel: &config.Tunnel{Domain: &serviceDomain, Name: &name}},
				"api": {},
			},
		},
	}}
	for _, test := range []struct {
		service, wantDomain, wantName string
	}{
		{"web", serviceDomain, name},
		{"api", rootDomain, projectconfig.ServiceWorktreeLabel("api", project.Worktree)},
	} {
		flags := devCommand{Service: test.service, openOptions: openOptions{Open: cliOpen}}
		if err := project.applyDev(&flags); err != nil {
			t.Fatal(err)
		}
		if flags.Domain != test.wantDomain || flags.Name != test.wantName || !flags.Open {
			t.Fatalf("service %s flags = %#v", test.service, flags)
		}
	}
	var cliFlags cli
	parser, err := kong.New(&cliFlags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"dev", "web", "--open=false", "--domain=override.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	applyTunnelCLIUnits(parsed, &cliFlags)
	if err := project.applyDev(&cliFlags.Dev); err != nil {
		t.Fatal(err)
	}
	if cliFlags.Dev.Open || cliFlags.Dev.Domain != "override.example.test" || cliFlags.Dev.Name != name {
		t.Fatalf("explicit overrides = %#v", cliFlags.Dev)
	}
}

func TestEphemeralTunnelDoesNotReceiveWorktreeSubdomain(t *testing.T) {
	flags := tunnelFlags{Ephemeral: true}
	applyBuiltInHostname(&flags, "api", projectconfig.Worktree{Label: "tnl-bb4eff12"})
	if flags.PublicURL != "" || flags.Name != "" {
		t.Fatalf("ephemeral hostname flags = %#v", flags)
	}
}

func TestEphemeralConfigUsesMetadataHostnameOnlyWithoutRuntimeContextOverride(t *testing.T) {
	ephemeral := true
	root := t.TempDir()
	worktree := namedTestWorktree(root, "tnl")
	project := projectConfiguration{
		Project: projectconfig.Project{
			Root: root, Worktree: worktree,
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
	if withExplicitFalse.useMetadataHostname || withExplicitFalse.Ephemeral || withExplicitFalse.Name != projectconfig.ServiceWorktreeLabel("api", worktree) {
		t.Fatalf("explicit false ephemeral flags = %#v", withExplicitFalse)
	}
}

func namedTestWorktree(root, name string) projectconfig.Worktree {
	return projectconfig.ApplyWorktreeHashSalt(projectconfig.Worktree{Root: root, Name: name}, root, [32]byte{1})
}

func TestProjectCommandContextUsesRootAndPreservesExplicitServer(t *testing.T) {
	server, team := "https://project.example", "Project Team"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Server: &server, Team: &team}}}
	flags := cli{}
	if err := applyProjectCommandContext("url list", project, &flags); err != nil {
		t.Fatal(err)
	}
	if flags.URL.List.ServerURL != server || flags.URL.List.ProjectTeam != team {
		t.Fatalf("url flags = %#v", flags.URL.List)
	}
	flags.Domain.List.ServerURL = "https://explicit.example"
	if err := applyProjectCommandContext("domain list", project, &flags); err != nil {
		t.Fatal(err)
	}
	if flags.Domain.List.ServerURL != "https://explicit.example" || flags.Domain.List.ProjectTeam != team {
		t.Fatalf("domain flags = %#v", flags.Domain.List)
	}
	if err := applyProjectCommandContext("domain status <domain>", project, &flags); err != nil {
		t.Fatal(err)
	}
	if flags.Domain.Status.ServerURL != server || flags.Domain.Status.ProjectTeam != team {
		t.Fatalf("domain status flags = %#v", flags.Domain.Status)
	}
	flags.URL.Delete.AccessToken = "explicit-token"
	if err := applyProjectCommandContext("url delete <public-url-id>", project, &flags); err == nil {
		t.Fatal("project server accepted an explicit access token without an invocation-level server")
	}
	flags.URL.Delete.ServerURL = "https://explicit.example"
	if err := applyProjectCommandContext("url delete <public-url-id>", project, &flags); err != nil {
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
