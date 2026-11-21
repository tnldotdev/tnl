package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/httpjson"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublicationInputsRejectApplicationAuthSettings(t *testing.T) {
	for _, extension := range []string{"json", "yaml", "ts"} {
		t.Run(extension, func(t *testing.T) {
			root := t.TempDir()
			name := "tnl." + extension
			if extension == "ts" {
				name = "tnl.config.ts"
			}
			path := filepath.Join(root, name)
			for _, extra := range []string{"", `,"auth":{}`} {
				source := `{"services":{"api":{}},"deployments":{"local":{"targets":{"api":{"address":"https://api.example","tls":{}` + extra + `}}}}}`
				if extension == "ts" {
					source = "export default " + source
				} else {
					source = `{"version":1,"tnl":` + source + `}`
				}
				if err := os.WriteFile(path, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				_, err := clientproject.Resolve(t.Context(), clientproject.Selection{Path: path}, root, [32]byte{})
				if (err != nil) != (extra != "") {
					t.Fatalf("application auth must fail strict project loading: %v", err)
				}
			}
		})
	}
	for _, input := range []struct {
		body string
		out  any
	}{
		{`{"target":"https://api.example","target_auth":{}}`, new(controlv1.ProjectServiceConfiguration)},
		{`{"target":"https://api.example","target_auth":{}}`, new(installedjobs.Job)},
		{`{"secrets":[]}`, new(installedjobs.DeploymentBinding)},
	} {
		if err := httpjson.Decode(json.NewDecoder(strings.NewReader(input.body)), input.out); err == nil {
			t.Fatal("retired settings were silently ignored", input.body)
		}
	}
}

func TestCheckEvaluatesConfigurationWithoutStateOrTelemetry(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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
	r := recordTelemetry(t)
	if err := run(t.Context(), []string{"check"}, &stdout, &stderr, r.factory); err != nil {
		t.Fatal(err)
	}
	if events := r.events(); len(events) != 0 {
		t.Fatalf("check opened telemetry = %+v", events)
	}
	want, err := clioutput.Render(clioutput.Frame{
		Command: "tnl check", State: "valid", Blocks: []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "path", Value: configPath})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != want+"\n" {
		t.Fatalf("config path output = %q, want %q", got, want+"\n")
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("check did not evaluate tnl.config.ts: %v", err)
	}
	if _, err := os.Stat(stateRoot); !os.IsNotExist(err) {
		t.Fatalf("config path created client state: %v", err)
	}
}

func TestProjectConfigurationUsesStateSpecificWorktreeLabelEverywhere(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "tnl.config.ts")
	source := `export default ({worktree}: any) => ({
  services: {web: {}},
  deployments: {local: {targets: {web: {
    public: true, hostname: worktree.label.fullLabel + ".example.test",
    address: 3000,
  }}}},
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
		first.Worktree.Label == second.Worktree.Label || first.Config.Services["web"].Hostname == nil ||
		*first.Config.Services["web"].Hostname != first.Worktree.Label.FullLabel+".example.test" {
		t.Fatalf("worktree labels = %q, %q, %q; config = %#v", first.Worktree.Label.FullLabel, repeated.Worktree.Label.FullLabel, second.Worktree.Label.FullLabel, first.Config)
	}
	publish := publishCommand{}
	if err := first.applyPublish(&publish); err != nil {
		t.Fatal(err)
	}
	if publish.PublicURL != first.Worktree.Label.FullLabel+".example.test" {
		t.Fatalf("publish URL = %q, worktree label = %q", publish.PublicURL, first.Worktree.Label.FullLabel)
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

func TestPublishRootNameDoesNotOverrideNamedServiceHostname(t *testing.T) {
	for _, test := range []struct {
		name, source, target, override, publicURL, wantName, wantURL string
	}{
		{name: "root default", source: `{"name":"review"}`, target: "3000", wantName: "review"},
		{name: "CLI name", source: `{"name":"review"}`, target: "3000", override: "cli-review", wantName: "cli-review"},
		{name: "CLI URL", source: `{"name":"review"}`, target: "3000", publicURL: "exact.example", wantURL: "exact.example"},
		{name: "worktree default", source: `{}`, target: "3000", wantName: "worktree"},
		{name: "saved service name", source: `{"name":"root","services":{"web":{}},"deployments":{"local":{"targets":{"web":{"address":3000,"public":true,"name":"saved"}}}}}`, target: "web", wantName: "web-worktree"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "tnl.json")
			if err := os.WriteFile(path, []byte(`{"version":1,"tnl":`+test.source+`}`), 0600); err != nil {
				t.Fatal(err)
			}
			document, err := config.LoadDocument(path)
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := config.ResolveDeployment(*document.TNL, "local")
			if err != nil {
				t.Fatal(err)
			}
			project := projectConfiguration{Project: clientproject.Project{Config: resolved, Root: root, Worktree: namedTestWorktree(root, "worktree")}}
			flags := publishCommand{Target: test.target, tunnelFlags: tunnelFlags{Name: test.override, PublicURL: test.publicURL}}
			if err := project.applyPublish(&flags); err != nil {
				t.Fatal(err)
			}
			wantName := test.wantName
			if wantName == "worktree" {
				wantName = project.Worktree.Label.FullLabel
			} else if wantName == "web-worktree" {
				wantName = clientproject.ServiceWorktreeLabel("web", project.Worktree)
			}
			if flags.Name != wantName || flags.PublicURL != test.wantURL {
				t.Fatalf("name=%q URL=%q, want name=%q URL=%q", flags.Name, flags.PublicURL, wantName, test.wantURL)
			}
		})
	}
}

func TestEnrolledPublishDoesNotInheritProjectVisitorPolicy(t *testing.T) {
	name := "project-service"
	access := &config.Access{Mode: "anonymous"}
	ephemeral := true
	limit := 20
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{
		Services: config.Services{"api": {}, "web": {Name: &name, Public: new(true), Ephemeral: &ephemeral, HTTP: &config.HTTPService{Access: access, Limits: &config.WorkLimits{Concurrency: &limit}}}},
	}}}
	flags := publishCommand{PublisherIdentityID: "pub_0123456789abcdefghijkl", Protocol: "http"}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.Service != "" || flags.Target != "" || flags.Name != "" || flags.PublicURL != "" || flags.access != nil || flags.Ephemeral || flags.Concurrency != nil {
		t.Fatalf("enrolled publish inherited another service's visitor policy: %#v", flags)
	}
}

func TestProjectConfigurationAppliesPrecedenceUnits(t *testing.T) {
	t.Setenv("TNL_SERVER", "https://environment.example")
	t.Setenv("TNL_NAME", "environment-name")
	t.Setenv("TNL_TEAM", "environment-team")
	var flags cli
	parser := commandForTest(&flags, io.Discard)
	if _, err := parser([]string{"publish", "--ip", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	projectServer := "https://project.example"
	projectName := "project"
	access := &config.Access{Mode: "anonymous"}
	target := config.Target("3000")
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{
		Server:   &projectServer,
		Services: config.Services{"web": {Name: &projectName, Public: new(true), HTTP: &config.HTTPService{Access: access}, Target: &config.ServiceTarget{Type: "address", Address: &target}}},
	}}}
	if err := project.applyPublish(&flags.Publish); err != nil {
		t.Fatal(err)
	}
	if flags.Publish.ServerURL != "https://environment.example" || flags.Publish.Name != "environment-name" ||
		flags.Publish.selectedTeam != "environment-team" ||
		flags.Publish.PublicURL != "" || flags.Publish.Target != "3000" || !reflect.DeepEqual(flags.Publish.access, access) ||
		len(flags.Publish.IP) != 1 || flags.Publish.IP[0] != "198.51.100.0/24" {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestInspectionServiceAndFlagPrecedence(t *testing.T) {
	rootMode, serviceMode := config.InspectionNone, config.InspectionSummary
	target := config.Target("3000")
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{
		Inspection: &config.Inspection{Mode: &rootMode}, Services: config.Services{"web": {
			Inspection: &config.Inspection{Mode: &serviceMode}, Target: &config.ServiceTarget{Type: "address", Address: &target},
		}},
	}}}
	for _, tc := range []struct {
		args []string
		want config.InspectionMode
	}{
		{[]string{"publish", "web"}, "summary"},
		{[]string{"publish", "web", "--inspection-mode=none"}, "none"},
	} {
		var flags cli
		parser := commandForTest(&flags, io.Discard)
		parsed, err := parser(tc.args)
		if err != nil {
			t.Fatal(err)
		}
		applyTunnelCLIUnits(parsed, &flags)
		if err := project.applyPublish(&flags.Publish); err != nil {
			t.Fatal(err)
		}
		if flags.Publish.InspectionMode != tc.want {
			t.Fatalf("%v: inspection mode = %q", tc.args, flags.Publish.InspectionMode)
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
		Project: clientproject.Project{
			Root:     root,
			Worktree: worktree,
			Config: config.TNL{
				Server: &rootServer, Team: &serviceTeam,
				Services: map[string]config.Service{
					"web": {Public: new(true), Target: &config.ServiceTarget{Type: "address", Address: &target}},
				},
			},
		},
	}
	flags := publishCommand{Target: "web"}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.Service != "web" || flags.Target != "4173" || flags.ServerURL != rootServer ||
		flags.selectedTeam != serviceTeam || flags.projectRoot != root || flags.Name != clientproject.ServiceWorktreeLabel("web", worktree) {
		t.Fatalf("publish flags = %#v", flags)
	}
}

func TestPublishArgumentThatIsNotAServiceRemainsTarget(t *testing.T) {
	root := t.TempDir()
	worktree := namedTestWorktree(root, "project")
	project := projectConfiguration{
		Project: clientproject.Project{
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
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: map[string]config.Service{
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

func TestPrivateTCPProjectPublishDoesNotSelectAPublicURL(t *testing.T) {
	protocol := "tcp"
	target := config.Target("127.0.0.1:5432")
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{
		"orders": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &target}},
	}}}}
	for _, install := range []bool{false, true} {
		flags := publishCommand{Target: "orders"}
		var err error
		if install {
			err = project.applyInstalledService(&flags)
		} else {
			err = project.applyPublish(&flags)
		}
		if err != nil || flags.PublicURL != "" || flags.Name != "" || flags.Domain != "" || flags.Service != "orders" || flags.Protocol != "tcp" || flags.Target != string(target) || install && flags.ServiceName != "orders" {
			t.Fatalf("private TCP service fell through public URL publication: install=%t flags=%+v err=%v", install, flags, err)
		}
	}
}

func TestProjectOpenAndDomainUseSelectedServiceAndCLIExplicitFalse(t *testing.T) {
	serviceDomain := "service.example.test"
	configuredOpen, cliOpen := true, false
	project := projectConfiguration{Project: clientproject.Project{
		Worktree: namedTestWorktree(t.TempDir(), "shop"),
		Config: config.TNL{
			Services: config.Services{
				"web": {Public: new(true), Domain: &serviceDomain, HTTP: &config.HTTPService{Open: &configuredOpen}},
				"api": {Public: new(true), HTTP: &config.HTTPService{Open: &configuredOpen}},
			},
		},
	}}
	target := config.Target("3000")
	web := project.Config.Services["web"]
	web.Target = &config.ServiceTarget{Type: "address", Address: &target}
	project.Config.Services["web"] = web
	api := project.Config.Services["api"]
	api.Target = &config.ServiceTarget{Type: "address", Address: &target}
	project.Config.Services["api"] = api
	for _, test := range []struct {
		service, wantDomain, wantName string
	}{
		{"web", serviceDomain, clientproject.ServiceWorktreeLabel("web", project.Worktree)},
		{"api", "", clientproject.ServiceWorktreeLabel("api", project.Worktree)},
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
	parser := commandForTest(&cliFlags, io.Discard)
	parsed, err := parser([]string{"publish", "web", "--open=false", "--domain=override.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	applyTunnelCLIUnits(parsed, &cliFlags)
	if err := project.applyPublish(&cliFlags.Publish); err != nil {
		t.Fatal(err)
	}
	if cliFlags.Publish.Open || cliFlags.Publish.Domain != "override.example.test" || cliFlags.Publish.Name != clientproject.ServiceWorktreeLabel("web", project.Worktree) {
		t.Fatalf("explicit overrides = %#v", cliFlags.Publish)
	}
}

func TestEphemeralTunnelDoesNotReceiveWorktreeSubdomain(t *testing.T) {
	flags := tunnelFlags{Ephemeral: true}
	applyBuiltInHostname(&flags, "api", clientproject.Worktree{Label: clientproject.WorktreeLabel{Project: "tnl", ID: "bb4eff12", FullLabel: "tnl-bb4eff12"}})
	if flags.PublicURL != "" || flags.Name != "" {
		t.Fatalf("ephemeral hostname flags = %#v", flags)
	}
}

func namedTestWorktree(root, name string) clientproject.Worktree {
	return clientproject.ApplyWorktreeHashSalt(clientproject.Worktree{Root: root, Name: name}, root, [32]byte{1})
}

func TestProjectCommandContextUsesRootAndPreservesExplicitServer(t *testing.T) {
	server, team := "https://project.example", "project-team"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Server: &server, Team: &team}}}
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
	if err := applyProjectCommandContext("url delete <service-or-address>", project, &flags); err == nil {
		t.Fatal("project server accepted an explicit access token without an invocation-level server")
	}
	flags.URL.Delete.ServerURL = "https://explicit.example"
	if err := applyProjectCommandContext("url delete <service-or-address>", project, &flags); err != nil {
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
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{
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
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{
		Server: &rootServer, Team: &rootTeam,
		Services: config.Services{
			"api": {Target: &config.ServiceTarget{Type: "address", Address: &target}},
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

func TestPublishRejectsProjectSelectedExplicitToken(t *testing.T) {
	server := "https://project.example"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Server: &server}}}
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
	ca := "system"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{
		Services: config.Services{"web": {Public: new(true), Target: &config.ServiceTarget{Type: "address", Address: &target, TLS: &config.TargetTLS{CA: &ca}}}},
	}}}
	configured := publishCommand{tunnelFlags: tunnelFlags{PublicURL: "https://app.example"}}
	if err := project.applyPublish(&configured); err != nil || configured.Target != string(target) || configured.TargetCAFile != "" || *configured.project.Config.Services["web"].Target.TLS.CA != ca {
		t.Fatalf("configured target trust = %#v, %v", configured, err)
	}
	override := publishCommand{Target: "http://other:3000", tunnelFlags: tunnelFlags{PublicURL: "https://app.example"}}
	if err := project.applyPublish(&override); err != nil || override.TargetCAFile != "" {
		t.Fatalf("explicit target inherited trust = %#v, %v", override, err)
	}
}

func TestProjectServiceKeepsTargetTLSInPublisherFlags(t *testing.T) {
	protocol, name, tlsName := "postgres", "orders", "db.internal"
	target := config.Target("db.internal:5432")
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{
		"web": {}, "orders": {Name: &name,
			Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &target, TLS: &config.TargetTLS{Hostname: &tlsName}}},
	}}}}
	flags := publishCommand{Target: "orders"}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.Service != "orders" || flags.Name != "" || flags.Protocol != "postgres" || flags.Target != string(target) ||
		flags.TargetTLSName != tlsName || flags.TargetCAFile != "" || flags.TargetTLS == nil || !*flags.TargetTLS {
		t.Fatalf("database service = %#v", flags)
	}
	if err := validateTCPPublishOptions(flags, "postgres"); err != nil {
		t.Fatal(err)
	}
	fileBacked := publishCommand{Target: "orders", PublisherCredentialFile: "publisher.json", remoteFlags: remoteFlags{ServerURL: "https://control.example"}}
	if err := project.applyPublish(&fileBacked); err != nil || fileBacked.Service != "orders" || fileBacked.Target != string(target) || fileBacked.Protocol != "postgres" || fileBacked.Name != "" {
		t.Fatalf("file-backed configured service = %+v, %v", fileBacked, err)
	}
}

func TestNamedTargetTrustContradictionsFailBeforePublisherSetup(t *testing.T) {
	protocol, hostname, ca := "postgres", "db.internal", "system"
	address := config.Target("127.0.0.1:5432")
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{
		"db": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &address, TLS: &config.TargetTLS{Hostname: &hostname, CA: &ca}}},
	}}}}
	disabled := false
	for _, flags := range []publishCommand{
		{Target: "db", TargetTLS: &disabled},
		{Target: "db", TargetTLSName: "other.internal"},
		{Target: "db", tunnelFlags: tunnelFlags{TargetCAFile: "other.pem"}},
	} {
		if err := project.applyPublish(&flags); err == nil {
			t.Fatal("contradictory named target trust accepted")
		}
	}
	if err := validateTCPPublishOptions(publishCommand{Target: "https://localhost:443", TargetTLS: &disabled}, "http"); err == nil {
		t.Fatal("HTTPS target accepted an explicit TLS disable")
	}
}

func TestServicePublicationKeepsHTTPBudgetSeparateFromIngressTraffic(t *testing.T) {
	total, connections := 17, 8
	target := config.Target("http://127.0.0.1:3000")
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{
		"web": {
			Public: new(true), Target: &config.ServiceTarget{Type: "address", Address: &target},
			HTTP:    &config.HTTPService{Limits: &config.WorkLimits{Total: &total}},
			Traffic: &config.TrafficLimits{Connections: &connections},
		},
	}}}}
	for _, install := range []bool{false, true} {
		flags := publishCommand{Target: "web"}
		var err error
		if install {
			err = project.applyInstalledService(&flags)
		} else {
			err = project.applyPublish(&flags)
		}
		if err != nil {
			t.Fatal(err)
		}
		if flags.limits().Requests != total || flags.traffic == nil || flags.traffic.Connections == nil || *flags.traffic.Connections != connections {
			t.Fatal("HTTP request budget and ingress traffic selection were merged", flags.limits(), flags.traffic)
		}
		if selected := privateOptions(flags); !reflect.DeepEqual(selected.Traffic, flags.traffic) || selected.StreamCapacity != 0 {
			t.Fatal("ingress traffic replaced physical publisher stream capacity", selected.Traffic, selected.StreamCapacity)
		}
	}
}

func TestInstalledServiceProtocolCannotChangeItsDeclaration(t *testing.T) {
	target := config.Target("127.0.0.1:5432")
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{
		"db": {Protocol: new("postgres"), Public: new(true), Target: &config.ServiceTarget{Type: "address", Address: &target}},
	}}}}
	flags := publishCommand{Target: "db", Protocol: "http"}
	if err := project.applyInstalledService(&flags); err == nil {
		t.Fatal("installed publication replaced its configured protocol")
	}
}
