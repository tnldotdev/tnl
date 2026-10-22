package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
				source := `{"services":{"api":{"target":{"type":"address","address":"https://api.example","tls":{}` + extra + `}}}}`
				if extension == "ts" {
					source = "export default " + source
				} else {
					source = `{"version":1,"tnl":` + source + `}`
				}
				if err := os.WriteFile(path, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				_, err := projectconfig.Resolve(t.Context(), projectconfig.Selection{Path: path}, root, [32]byte{})
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
		{`{"target":"https://api.example","target_auth":{}}`, new(publisherjob.Job)},
		{`{"secrets":[]}`, new(publisherjob.GroupBinding)},
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
	var events []telemetryPayload
	if err := run(t.Context(), []string{"check"}, &stdout, &stderr, func(string) telemetryReporter {
		return telemetryReporterFunc(func(event telemetryPayload) { events = append(events, event) })
	}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
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
  services: {web: {
    publicURL: {hostname: worktree.label.fullLabel + ".example.test"},
    target: {type: "address", address: 3000},
  }},
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
		first.Worktree.Label == second.Worktree.Label || first.Config.Services["web"].Tunnel == nil || first.Config.Services["web"].Tunnel.PublicURL == nil ||
		*first.Config.Services["web"].Tunnel.PublicURL != "https://"+first.Worktree.Label.FullLabel+".example.test" {
		t.Fatalf("worktree labels = %q, %q, %q; config = %#v", first.Worktree.Label.FullLabel, repeated.Worktree.Label.FullLabel, second.Worktree.Label.FullLabel, first.Config)
	}
	publish := publishCommand{}
	if err := first.applyPublish(&publish); err != nil {
		t.Fatal(err)
	}
	if publish.PublicURL != "https://"+first.Worktree.Label.FullLabel+".example.test" {
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

func TestEnrolledPublishDoesNotInheritProjectVisitorPolicy(t *testing.T) {
	name := "project-url"
	access := &config.Access{Mode: "anonymous"}
	ephemeral := true
	limit := 20
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Tunnel:   &config.Tunnel{Access: access, Ephemeral: &ephemeral, Limits: &config.Limits{HTTP: &config.WorkLimits{Concurrency: &limit}}},
		Services: config.Services{"api": {}, "web": {Name: &name, Tunnel: &config.Tunnel{}}},
	}}}
	flags := publishCommand{PublisherID: "pub_0123456789abcdefghijkl", Protocol: "http"}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.Service != "" || flags.Target != "" || flags.Name != "" || flags.PublicURL != "" || flags.access != nil || flags.Ephemeral || flags.Concurrency != nil {
		t.Fatalf("enrolled publish inherited a project URL or visitor policy: %#v", flags)
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
	if _, err := parser.Parse([]string{"publish", "--ip", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	projectServer := "https://project.example"
	projectName := "project"
	access := &config.Access{Mode: "anonymous"}
	target := config.Target("3000")
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Server:   &projectServer,
		Tunnel:   &config.Tunnel{Access: access},
		Services: config.Services{"web": {Name: &projectName, Tunnel: &config.Tunnel{}, Target: &config.ServiceTarget{Type: "address", Address: &target}}},
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
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
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
		Project: projectconfig.Project{
			Root:     root,
			Worktree: worktree,
			Config: config.TNL{
				Server: &rootServer, Team: &serviceTeam,
				Services: map[string]config.Service{
					"web": {Tunnel: &config.Tunnel{}, Target: &config.ServiceTarget{Type: "address", Address: &target}},
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

func TestPrivateTCPProjectPublishDoesNotSelectAPublicURL(t *testing.T) {
	protocol := "tcp"
	target := config.Target("127.0.0.1:5432")
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Services: config.Services{
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

func TestProjectOpenAndDomainUseServiceOverridesAndCLIExplicitFalse(t *testing.T) {
	rootDomain, serviceDomain, name := "root.example.test", "service.example.test", "preview"
	configuredOpen, cliOpen := true, false
	project := projectConfiguration{Project: projectconfig.Project{
		Worktree: namedTestWorktree(t.TempDir(), "shop"),
		Config: config.TNL{
			Tunnel: &config.Tunnel{Domain: &rootDomain},
			Services: config.Services{
				"web": {Tunnel: &config.Tunnel{Domain: &serviceDomain, Name: &name}, HTTP: &config.HTTPService{Open: &configuredOpen}},
				"api": {HTTP: &config.HTTPService{Open: &configuredOpen}},
			},
		},
	}}
	target := config.Target("3000")
	project.Config.Services["web"] = config.Service{Tunnel: project.Config.Services["web"].Tunnel, HTTP: &config.HTTPService{Open: &configuredOpen}, Target: &config.ServiceTarget{Type: "address", Address: &target}}
	project.Config.Services["api"] = config.Service{Tunnel: &config.Tunnel{}, HTTP: &config.HTTPService{Open: &configuredOpen}, Target: &config.ServiceTarget{Type: "address", Address: &target}}
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
	caFile := "certs/target-ca.pem"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Services: config.Services{"web": {Tunnel: &config.Tunnel{}, Target: &config.ServiceTarget{Type: "address", Address: &target, TLS: &config.TargetTLS{CAFile: &caFile}}}},
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

func TestProjectPrivateServiceKeepsTargetTLSInPublisherFlags(t *testing.T) {
	protocol, name, tlsName := "postgres", "orders", "db.internal"
	target := config.Target("db.internal:5432")
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Services: config.Services{
		"web": {}, "orders": {Name: &name,
			Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &target, TLS: &config.TargetTLS{ServerName: &tlsName}}},
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
	fileBacked := publishCommand{Target: "orders", PublisherFile: "publisher.json", remoteFlags: remoteFlags{ServerURL: "https://control.example"}}
	if err := project.applyPublish(&fileBacked); err != nil || fileBacked.Service != "orders" || fileBacked.Target != string(target) || fileBacked.Protocol != "postgres" || fileBacked.Name != "" {
		t.Fatalf("file-backed configured private service = %+v, %v", fileBacked, err)
	}
}

func TestNamedTargetTrustContradictionsFailBeforePublisherSetup(t *testing.T) {
	protocol, hostname, ca := "postgres", "db.internal", "certs/root.pem"
	address := config.Target("127.0.0.1:5432")
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Services: config.Services{
		"db": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &address, TLS: &config.TargetTLS{ServerName: &hostname, CAFile: &ca}}},
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
