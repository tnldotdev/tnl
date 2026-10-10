package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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
	var events []telemetryPayload
	if err := run(t.Context(), []string{"config", "path"}, &stdout, &stderr, func(string) telemetryReporter {
		return telemetryReporterFunc(func(event telemetryPayload) { events = append(events, event) })
	}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Command != "config" || events[0].Action != "path" || events[1].Event != telemetryCommandCompleted {
		t.Fatalf("config path telemetry = %+v", events)
	}
	want, err := clioutput.Render(clioutput.Frame{
		Command: "tnl config path", State: "selected", Blocks: []clioutput.Block{clioutput.Text(configPath)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != want+"\n" {
		t.Fatalf("config path output = %q, want %q", got, want+"\n")
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
  tunnel: {name: worktree.label.fullLabel},
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
	if first.Worktree.Label.FullLabel == "" || first.Worktree.Label != repeated.Worktree.Label ||
		first.Worktree.Label == second.Worktree.Label || first.Config.Tunnel == nil || first.Config.Tunnel.Name == nil ||
		*first.Config.Tunnel.Name != first.Worktree.Label.FullLabel {
		t.Fatalf("worktree labels = %q, %q, %q; config = %#v", first.Worktree.Label.FullLabel, repeated.Worktree.Label.FullLabel, second.Worktree.Label.FullLabel, first.Config)
	}
	publish := publishCommand{}
	if err := first.applyPublish(&publish); err != nil {
		t.Fatal(err)
	}
	if publish.Name != first.Worktree.Label.FullLabel {
		t.Fatalf("publish name = %q, worktree label = %q", publish.Name, first.Worktree.Label.FullLabel)
	}
}

func TestBarePublishUsesStableDirectoryNameWithoutConfiguration(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	stateRoot := filepath.Join(t.TempDir(), "state")
	previous := ""
	for range 2 {
		project, err := loadProjectConfiguration(t.Context(), cli{}, stateRoot)
		if err != nil {
			t.Fatal(err)
		}
		flags := publishCommand{Target: "3000"}
		if err := project.applyPublish(&flags); err != nil {
			t.Fatal(err)
		}
		if flags.Name != project.Worktree.Label.FullLabel || flags.Name == "" || previous != "" && flags.Name != previous {
			t.Fatalf("bare publish name = %q, worktree name = %q", flags.Name, project.Worktree.Label.FullLabel)
		}
		previous = flags.Name
	}
}

func TestCredentialPublishDoesNotInheritProjectVisitorPolicy(t *testing.T) {
	name := "project-url"
	allowAllIPs := true
	ephemeral := true
	limit := 20
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Tunnel:   &config.Tunnel{Name: &name, AllowAllIPs: &allowAllIPs, Ephemeral: &ephemeral, Limits: &config.Limits{Concurrency: &limit}},
		Services: config.Services{"api": {}, "web": {}},
	}}}
	flags := publishCommand{PublishCredential: "tnl_url_example"}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.Service != "" || flags.Target != "" || flags.Name != "" || flags.PublicURL != "" || flags.AllowAllIPs || flags.Ephemeral || flags.Concurrency == nil || *flags.Concurrency != limit {
		t.Fatalf("credential publish inherited a project URL or visitor policy: %#v", flags)
	}
}

func TestProjectConfigurationAppliesPrecedenceUnits(t *testing.T) {
	t.Setenv("TNL_SERVER", "https://environment.example")
	t.Setenv("TNL_NAME", "environment-name")
	t.Setenv("TNL_TEAM", "environment-team")
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
		flags.Publish.selectedTeam != "environment-team" ||
		flags.Publish.PublicURL != "" || flags.Publish.Target != "3000" || flags.Publish.AllowAllIPs ||
		!reflect.DeepEqual(flags.Publish.AllowIP, []string{"198.51.100.0/24"}) {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestRequestInspectionServiceAndFlagPrecedence(t *testing.T) {
	rootMode, serviceMode := config.RequestInspectionDetailed, config.RequestInspectionSummary
	target := config.Target("3000")
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		RequestInspection: &rootMode, Services: config.Services{"web": {
			RequestInspection: &serviceMode, Publish: &config.Publish{Target: &target},
		}},
	}}}
	for _, tc := range []struct {
		args []string
		want config.RequestInspectionMode
	}{
		{[]string{"publish", "web"}, "summary"},
		{[]string{"publish", "web", "--request-inspection=detailed"}, "detailed"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.Parse(tc.args)
		if err != nil {
			t.Fatal(err)
		}
		applyTunnelCLIUnits(parsed, &flags)
		if err := project.applyPublish(&flags.Publish); err != nil {
			t.Fatal(err)
		}
		if flags.Publish.RequestInspection != tc.want {
			t.Fatalf("%v: capture = %q", tc.args, flags.Publish.RequestInspection)
		}
	}
}

func TestProjectConfigurationResolvesNamedServiceAndBuiltInHostname(t *testing.T) {
	root := t.TempDir()
	worktree := namedTestWorktree(root, "feature")
	rootServer := "https://root.example"
	serviceTeam := "frontend-team"
	target := config.Target("4173")
	project := projectConfiguration{
		Project: projectconfig.Project{
			Root:     root,
			Worktree: worktree,
			Config: config.TNL{
				Server: &rootServer, Team: &serviceTeam,
				Services: map[string]config.Service{
					"web": {Publish: &config.Publish{Target: &target}},
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
	if flags.Service != "" || flags.Target != "3000" || flags.Name != worktree.Label.FullLabel {
		t.Fatalf("publish flags = %#v", flags)
	}
}

func TestProjectConfigurationRequiresServiceWhenAmbiguous(t *testing.T) {
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Services: map[string]config.Service{
		"api": {}, "web": {},
	}}}}
	if err := project.applyPublish(&publishCommand{}); err == nil || err.Error() != "service is required; configured services: api, web" {
		t.Fatalf("ambiguous service error = %v", err)
	} else if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.ServiceAmbiguous {
		t.Fatalf("ambiguous service diagnostic = %q, %t", code, ok)
	} else {
		var output bytes.Buffer
		writeCommandError(&output, err)
		if !strings.Contains(output.String(), "configured services: api, web") {
			t.Fatalf("ambiguous service output omitted names: %s", output.String())
		}
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
		Id: "domain_2", Kind: authorityv1.Custom, CanonicalDomain: claimed, State: authorityv1.DomainStateReady,
	})
	service, err = configuredProjectService("api", worktree, config.TNL{Tunnel: &config.Tunnel{Domain: &claimed}}, current)
	if err != nil {
		t.Fatal(err)
	}
	want = projectconfig.ServiceWorktreeLabel("api", worktree) + ".chase.studio.example.test"
	if service.Namespace != "chase.studio.example.test" || service.Hostname != want || service.URL != "https://"+want {
		t.Fatalf("custom-domain metadata = %#v", service)
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
	target := config.Target("3000")
	project.Config.Services["web"] = config.Service{Tunnel: project.Config.Services["web"].Tunnel, Publish: &config.Publish{Target: &target}}
	project.Config.Services["api"] = config.Service{Publish: &config.Publish{Target: &target}}
	for _, test := range []struct {
		service, wantDomain, wantName string
	}{
		{"web", serviceDomain, name},
		{"api", rootDomain, projectconfig.ServiceWorktreeLabel("api", project.Worktree)},
	} {
		flags := publishCommand{Target: test.service, openOptions: openOptions{Open: cliOpen}}
		if err := project.applyPublish(&flags); err != nil {
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
	parsed, err := parser.Parse([]string{"publish", "web", "--open=false", "--domain=override.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	applyTunnelCLIUnits(parsed, &cliFlags)
	if err := project.applyPublish(&cliFlags.Publish); err != nil {
		t.Fatal(err)
	}
	if cliFlags.Publish.Open || cliFlags.Publish.Domain != "override.example.test" || cliFlags.Publish.Name != name {
		t.Fatalf("explicit overrides = %#v", cliFlags.Publish)
	}
}

func TestEphemeralTunnelDoesNotReceiveWorktreeSubdomain(t *testing.T) {
	flags := tunnelFlags{Ephemeral: true}
	applyBuiltInHostname(&flags, "api", projectconfig.Worktree{Label: projectconfig.WorktreeLabel{Project: "tnl", ID: "bb4eff12", FullLabel: "tnl-bb4eff12"}})
	if flags.PublicURL != "" || flags.Name != "" {
		t.Fatalf("ephemeral hostname flags = %#v", flags)
	}
}

func namedTestWorktree(root, name string) projectconfig.Worktree {
	return projectconfig.ApplyWorktreeHashSalt(projectconfig.Worktree{Root: root, Name: name}, root, [32]byte{1})
}

func TestProjectCommandContextUsesRootAndPreservesExplicitServer(t *testing.T) {
	server, team := "https://project.example", "project-team"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Server: &server, Team: &team}}}
	flags := cli{}
	if err := applyProjectCommandContext("url list", project, &flags); err != nil {
		t.Fatal(err)
	}
	if flags.URL.List.ServerURL != server || flags.URL.List.ProjectTeam != team {
		t.Fatalf("url flags = %#v", flags.URL.List)
	}
	if !projectSensitiveCommand("feedback inspect <feedback-id>") || applyProjectCommandContext("feedback inspect <feedback-id>", project, &flags) != nil ||
		flags.Feedback.Inspect.ServerURL != server || flags.Feedback.Inspect.ProjectTeam != team {
		t.Fatalf("feedback flags = %#v", flags.Feedback.Inspect)
	}
	flags.Domain.List.ServerURL = "https://explicit.example"
	if err := applyProjectCommandContext("domain list", project, &flags); err != nil {
		t.Fatal(err)
	}
	if flags.Domain.List.ServerURL != "https://explicit.example" || flags.Domain.List.ProjectTeam != "" {
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
	if flags.URL.Delete.ProjectTeam != "" {
		t.Fatalf("cross-server url delete kept project team: %#v", flags.URL.Delete)
	}
	if err := applyProjectCommandContext("auth login", project, &flags); err != nil || flags.Auth.Login.ServerURL != server {
		t.Fatalf("login server = %q, %v", flags.Auth.Login.ServerURL, err)
	}
	if err := applyProjectCommandContext("admin maintenance block <name>", project, &flags); err != nil || flags.Admin.Maintenance.Block.ServerURL != server {
		t.Fatalf("admin server = %q, %v", flags.Admin.Maintenance.Block.ServerURL, err)
	}
}

func TestCrossServerTeamPrecedence(t *testing.T) {
	projectServer, projectTeam := "https://control.staging.example", "staging-team"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Server: &projectServer, Team: &projectTeam,
	}}}
	flags := cli{}
	flags.Domain.List.ServerURL = "https://control.production.example"
	flags.Domain.List.Team = "production-team"
	if err := applyProjectCommandContext("domain list", project, &flags); err != nil {
		t.Fatal(err)
	}
	selected := flags.Domain.List.selection()
	if selected.ProjectTeam != "" || selected.SelectedTeam != "production-team" {
		t.Fatalf("cross-server selection = %#v", selected)
	}
	publish := publishCommand{Target: "3000", remoteFlags: remoteFlags{ServerURL: "https://control.production.example"}}
	if err := project.applyPublish(&publish); err != nil || publish.selectedTeam != "" {
		t.Fatalf("publish selection = %q, %v", publish.selectedTeam, err)
	}
}

func TestServicesInheritProjectServerAndTeam(t *testing.T) {
	rootServer, otherServer := "https://root.example", "https://other.example"
	rootTeam := "root-team"
	target := config.Target("3000")
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Server: &rootServer, Team: &rootTeam,
		Services: config.Services{
			"api": {Publish: &config.Publish{Target: &target}},
			"web": {},
		},
	}}}
	publish := publishCommand{Target: "api"}
	if err := project.applyPublish(&publish); err != nil || publish.selectedTeam != rootTeam || publish.ServerURL != rootServer {
		t.Fatalf("publish api = %#v, %v", publish, err)
	}
	other := publishCommand{Target: "api", remoteFlags: remoteFlags{ServerURL: otherServer}}
	if err := project.applyPublish(&other); err != nil || other.selectedTeam != "" {
		t.Fatalf("cross-server publish selection = %#v, %v", other, err)
	}
	effective, err := project.EffectiveService("api")
	if err != nil || effective.Server == nil || *effective.Server != rootServer || effective.Team == nil || *effective.Team != rootTeam {
		t.Fatalf("api project context = %#v, %v", effective, err)
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

func TestPublishRejectsProjectSelectedExplicitToken(t *testing.T) {
	server := "https://project.example"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Server: &server}}}
	for _, selected := range []string{"", "https://explicit.example"} {
		remote := remoteFlags{ServerURL: selected, AccessToken: "explicit-token"}
		publish := publishCommand{Target: "3000", remoteFlags: remote}
		if err := project.applyPublish(&publish); (err != nil) != (selected == "") {
			t.Fatalf("selected=%q: %v", selected, err)
		}
	}
}

func TestTargetCAIsBoundToConfiguredTarget(t *testing.T) {
	target := config.Target("https://api.internal:443")
	caFile := "/run/secrets/target_ca"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Publish: &config.Publish{Target: &target, CAFile: &caFile},
	}}}
	configured := publishCommand{tunnelFlags: tunnelFlags{PublicURL: "https://app.example"}}
	if err := project.applyPublish(&configured); err != nil || configured.Target != string(target) || configured.TargetCAFile != caFile {
		t.Fatalf("configured target trust = %#v, %v", configured, err)
	}
	override := publishCommand{Target: "http://other:3000", tunnelFlags: tunnelFlags{PublicURL: "https://app.example"}}
	if err := project.applyPublish(&override); err != nil || override.TargetCAFile != "" {
		t.Fatalf("explicit target inherited trust = %#v, %v", override, err)
	}
}
