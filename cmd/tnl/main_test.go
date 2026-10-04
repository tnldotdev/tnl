package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestCLIExposesTeamDomainRouteAndFinalAdminCommands(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	commands := map[string]bool{}
	for _, command := range parser.Model.Leaves(true) {
		commands[command.Path()] = true
	}
	for _, command := range []string{
		"init", "dev", "publish", "status", "login",
		"config path", "config check", "config generate", "telemetry on", "telemetry off", "telemetry status",
		"team current", "team list", "team use", "team create", "team members", "team invite create",
		"team invite list", "team invite revoke", "team join", "team member set-role", "team member remove",
		"domain claim", "domain default", "domain list", "domain status", "domain release", "url list", "url delete",
		"admin server status", "admin relays list", "admin relays drain", "admin maintenance list",
		"admin maintenance allow", "admin maintenance block",
	} {
		if !commands[command] {
			t.Fatalf("command %q missing from help model", command)
		}
	}
	if _, err := parser.Parse([]string{"host", "list"}); err == nil {
		t.Fatal("obsolete host command was accepted")
	}
	if _, err := parser.Parse([]string{"route", "list"}); err == nil {
		t.Fatal("obsolete route command was accepted")
	}
}

func TestTeamScopedCommandsAcceptExplicitTeam(t *testing.T) {
	for _, args := range [][]string{
		{"team", "current"}, {"team", "members"},
		{"team", "invite", "list"}, {"team", "invite", "create", "--member-slug", "member"},
		{"team", "invite", "revoke", "ivt_1"},
		{"team", "member", "set-role", "mem_1", "--role", "admin"},
		{"team", "member", "remove", "mem_1"},
		{"domain", "list"}, {"domain", "claim", "example.test"},
		{"domain", "default", "example.test"}, {"domain", "status", "example.test"},
		{"domain", "release", "example.test"},
		{"url", "list"}, {"url", "delete", "url_1"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parser.Parse(append(args, "--team=studio")); err != nil {
				t.Fatal(err)
			}
			// parsing --team must also accept the value as a command-scoped flag;
			// the resolved context is tested separately for server precedence.
		})
	}
}

func TestTeamEnvironmentSelectsDomainCommand(t *testing.T) {
	t.Setenv("TNL_TEAM", "studio")
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"domain", "list"}); err != nil {
		t.Fatal(err)
	}
	if selected := flags.Domain.List.selection().SelectedTeam; selected != "studio" {
		t.Fatalf("domain list team = %q", selected)
	}
}

func TestTunnelHelpExplainsIPPolicyAndTeamSelection(t *testing.T) {
	for _, command := range []string{"dev", "publish"} {
		t.Run(command, func(t *testing.T) {
			var flags cli
			var output bytes.Buffer
			parser, err := kong.New(&flags, kong.Name("tnl"), kong.Writers(&output, io.Discard), kong.Exit(func(int) {}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parser.Parse([]string{command, "--help"}); err != nil {
				t.Fatal(err)
			}
			text := strings.Join(strings.Fields(output.String()), " ")
			for _, want := range []string{"your current IP is also allowed", "every IP", "--team", "--server"} {
				if !strings.Contains(text, want) {
					t.Fatalf("%s help missing %q:\n%s", command, want, output.String())
				}
			}
		})
	}
}

func TestUnknownFlagUsesParsedCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(t.Context(), []string{"domain", "list", "--missing"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("unknown flag was accepted")
	}
	if title, ok := clioutput.CommandOf(err); !ok || title != "tnl domain list" {
		t.Fatalf("parse error command = %q, %t", title, ok)
	}
}

func TestTeamCommandsUseMemberSlugFlag(t *testing.T) {
	var create cli
	createParser, err := kong.New(&create)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := createParser.Parse([]string{"team", "create", "studio"}); err != nil || create.Team.Create.Name != "studio" {
		t.Fatalf("team create studio: %q, %v", create.Team.Create.Name, err)
	}
	for _, test := range []struct {
		name string
		args []string
		get  func(cli) string
	}{
		{
			name: "create",
			args: []string{"team", "create", "example", "--member-slug", "alice"},
			get:  func(flags cli) string { return flags.Team.Create.MemberSlug },
		},
		{
			name: "invitation",
			args: []string{"team", "invite", "create", "--member-slug", "alice"},
			get:  func(flags cli) string { return flags.Team.Invite.Create.MemberSlug },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parser.Parse(test.args); err != nil {
				t.Fatal(err)
			}
			if got := test.get(flags); got != "alice" {
				t.Fatalf("member slug = %q", got)
			}
		})
	}

	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"team", "create", "studio", "--slug", "another"}); err == nil {
		t.Fatal("obsolete team --slug flag was accepted")
	}
}

func TestPublishHostnameOptions(t *testing.T) {
	t.Setenv("TNL_NAME", "env-name")
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"publish", "3000", "--public-url", "https://flag.example", "--name", "api"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "publish <service-or-target>" || flags.Publish.PublicURL != "https://flag.example" || flags.Publish.Name != "api" {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestTunnelCLIUnitOverridesConflictingEnvironmentUnit(t *testing.T) {
	t.Setenv("TNL_NAME", "environment-name")
	t.Setenv("TNL_ALLOW_ALL_IPS", "true")
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"publish", "3000", "--public-url", "https://api.example", "--allow-ip", "192.0.2.1"}
	parsed, err := parser.Parse(args)
	if err != nil {
		t.Fatal(err)
	}
	applyTunnelCLIUnits(parsed, &flags)
	if flags.Publish.Name != "" || flags.Publish.PublicURL != "https://api.example" || flags.Publish.AllowAllIPs ||
		len(flags.Publish.AllowIP) != 1 {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestExplicitFalseTunnelFlagsOverrideProjectConfiguration(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"publish", "3000", "--allow-all-ips=false", "--ephemeral=false"}
	parsed, err := parser.Parse(args)
	if err != nil {
		t.Fatal(err)
	}
	applyTunnelCLIUnits(parsed, &flags)
	configured := true
	applyTunnelConfiguration(&flags.Publish.tunnelFlags, &config.Tunnel{
		AllowAllIPs: &configured, Ephemeral: &configured,
	})
	if flags.Publish.AllowAllIPs || flags.Publish.Ephemeral {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestResolvePublishHostnameUsesNamespace(t *testing.T) {
	current := teamContext{
		team: authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_1", PolicyRevision: 4},
		membership: authorityv1.Membership{
			Id: "membership_1", TeamId: "team_1", Role: authorityv1.TeamRoleMember,
			MemberSlug: "chase", ManagedLabel: "chase-abc",
		},
		domains: []authorityv1.Domain{{
			Id: "domain_1", Kind: authorityv1.Managed, CanonicalDomain: "tnl.dev", State: authorityv1.DomainStateReady,
		}},
	}
	hostname, domain, scope, err := resolvePublishHostname("", "api", "", current)
	if err != nil {
		t.Fatal(err)
	}
	if hostname != "api.chase-abc.tnl.dev" || domain.Id != "domain_1" || scope != controlv1.Member {
		t.Fatalf("resolution = %q, %#v, %q", hostname, domain, scope)
	}
	if _, _, _, err := resolvePublishHostname("https://shared.tnl.dev", "", "", current); err == nil {
		t.Fatal("member was allowed to create a shared route")
	}
	generated, _, generatedScope, err := resolvePublishHostname("", "", "", current)
	if err != nil {
		t.Fatal(err)
	}
	label, found := strings.CutSuffix(generated, ".chase-abc.tnl.dev")
	if !found || strings.Count(label, "-") != 1 || generatedScope != controlv1.Member {
		t.Fatalf("generated route = %q, %q", generated, generatedScope)
	}
}

func TestParseLoginInput(t *testing.T) {
	token, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseLoginInput([]byte(token.String() + "\n"))
	if err != nil || parsed != token {
		t.Fatalf("token = %q, error = %v", parsed, err)
	}
	if _, err := parseLoginInput([]byte("invalid-token")); err == nil {
		t.Fatal("invalid login token was accepted")
	} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.LoginTokenInvalid {
		t.Fatalf("invalid login token reason = %q, %v", reason, err)
	}
}

func TestAuthenticationBrowserOpenerRequiresTTY(t *testing.T) {
	if opener := interactiveBrowserOpener(bytes.NewReader(nil)); opener != nil {
		t.Fatal("non-TTY authentication input enabled browser opening")
	}
}

func TestCanonicalCommandTitle(t *testing.T) {
	for command, want := range map[string]string{
		"publish <service-or-target>":          "tnl publish",
		"dev <service>":                        "tnl dev",
		"team member set-role <membership-id>": "tnl team member set-role",
		"status":                               "tnl status",
	} {
		if got := clioutput.CommandTitle("tnl", command); got != want {
			t.Fatalf("CommandTitle(%q) = %q, want %q", command, got, want)
		}
	}
}

func TestCanonicalParsedCommandIncludesOptionalArguments(t *testing.T) {
	for command, want := range map[string]string{
		"dev":     "dev <service>",
		"publish": "publish <service-or-target>",
		"status":  "status",
	} {
		if got := canonicalParsedCommand(command); got != want {
			t.Fatalf("canonicalParsedCommand(%q) = %q, want %q", command, got, want)
		}
	}
}

func TestBareTunnelCommandsReachCanonicalDispatch(t *testing.T) {
	for _, test := range []struct {
		command    string
		wantErr    string
		wantReason failure.Reason
	}{
		{command: "dev", wantErr: "validate control URL", wantReason: failure.InvalidControlURL},
		{command: "publish", wantErr: "local target is required as an argument or publish.target in project configuration", wantReason: failure.MissingTarget},
	} {
		t.Run(test.command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			stateDir := filepath.Join(t.TempDir(), "state")
			args := []string{"--no-config", test.command, "--state-dir", stateDir, "--server", "http://control.example"}
			err := run(t.Context(), args, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("run error = %v, want %q", err, test.wantErr)
			}
			if reason, _, ok := failure.Describe(err); !ok || reason != test.wantReason {
				t.Fatalf("run failure reason = %q, %t, want %q", reason, ok, test.wantReason)
			}
			var parseError *kong.ParseError
			if errors.As(err, &parseError) {
				t.Fatalf("bare %s returned parse error: %v", test.command, err)
			}
			wantCommand := "tnl " + test.command
			if got, ok := clioutput.CommandOf(err); !ok || got != wantCommand {
				t.Fatalf("command = %q, %t, want %q", got, ok, wantCommand)
			}
			writeCommandError(&stderr, err)
			if got := stderr.String(); !strings.HasPrefix(got, "+--[ "+wantCommand+" ]-- command failed ") {
				t.Fatalf("error output = %q", got)
			}
			if strings.Contains(stderr.String(), "clientstate: ") ||
				(test.command == "dev" && !strings.Contains(stderr.String(), "server must be an HTTPS origin")) {
				t.Fatalf("CLI exposed an internal error prefix: %q", stderr.String())
			}
		})
	}
}

func TestDemoPublishUsesFreshEphemeralURLAndSkipsProject(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"publish", "--demo", "--open=false"})
	if err != nil {
		t.Fatal(err)
	}
	applyTunnelCLIUnits(parsed, &flags)
	flags.Publish.Name = "from-environment"
	if err := prepareDemoPublish(&flags.Publish, "", true); err != nil {
		t.Fatal(err)
	}
	if flags.Publish.Target != "" || flags.Publish.Name != "" || !flags.Publish.Ephemeral || flags.Publish.Open {
		t.Fatalf("demo flags = %+v", flags.Publish)
	}
	flags.Publish.openFromCLI = false
	if err := prepareDemoPublish(&flags.Publish, "", true); err != nil || !flags.Publish.Open {
		t.Fatalf("interactive demo = %+v, error = %v", flags.Publish, err)
	}

	for _, test := range []struct {
		name   string
		args   []string
		reason failure.Reason
		action string
	}{
		{"target", []string{"publish", "--demo", "3000"}, failure.DemoTargetNotAllowed, "remove the service or target"},
		{"config", []string{"--config", "missing.yml", "publish", "--demo"}, failure.DemoConfigNotUsed, "remove --config"},
		{"name", []string{"publish", "--demo", "--name", "saved"}, failure.DemoURLManaged, "remove --name or --public-url"},
		{"public url", []string{"publish", "--demo", "--public-url", "https://saved.example"}, failure.DemoURLManaged, "remove --name or --public-url"},
		{"ephemeral", []string{"publish", "--demo", "--ephemeral=false"}, failure.DemoMustBeEphemeral, "remove --ephemeral=false"},
		{"request limit", []string{"publish", "--demo", "--request-limit", "0"}, failure.InvalidTunnelFlags, "--request-limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := run(t.Context(), test.args, &stdout, &stderr)
			reason, _, typed := failure.Describe(err)
			if !typed || reason != test.reason || stdout.Len() != 0 {
				t.Fatalf("demo options %v = reason %q, typed %t, stdout %q, error %v", test.args, reason, typed, stdout.String(), err)
			}
			writeCommandError(&stderr, err)
			if !strings.Contains(stderr.String(), test.action) || strings.Contains(stderr.String(), "tnl could not start or maintain this tunnel") {
				t.Fatalf("demo options %v = %q, want action %q", test.args, stderr.String(), test.action)
			}
		})
	}
}

func TestCLIErrorPresentationUsesTypedCopyWithoutChangingCause(t *testing.T) {
	cause := errors.New("clientstate: saved state is unavailable")
	state := failure.Wrap("open client state", failure.ClientStateUnavailable, cause)
	classified := diagnostic.WrapMessage(diagnostic.TargetInvalid, "check the target port", state)
	for _, err := range []error{state, classified} {
		var output bytes.Buffer
		writeCommandError(&output, clioutput.WrapCommand("tnl publish", err))
		if strings.Contains(output.String(), "clientstate: ") ||
			!errors.Is(err, cause) {
			t.Fatalf("CLI error = %q, cause = %v", output.String(), err)
		}
	}
}

func TestDemoPublishDoesNotLoadProjectConfiguration(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "tnl.config.ts"), []byte("this is not valid typescript"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)
	var stdout, stderr bytes.Buffer
	err := run(t.Context(), []string{
		"publish", "--demo", "--server", "http://control.example", "--state-dir", filepath.Join(directory, "state"),
	}, &stdout, &stderr)
	reason, _, typed := failure.Describe(err)
	if !typed || reason != failure.InvalidControlURL || strings.Contains(err.Error(), "typescript") {
		t.Fatalf("demo reached project configuration: %v", err)
	}
}

func TestDemoPublishRegistersTunnelWithoutProjectConfiguration(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := run(ctx, []string{
		"--no-config", "publish", "--demo", "--server", "https://127.0.0.1:1",
		"--state-dir", filepath.Join(directory, "state"),
	}, &stdout, &stderr)
	if err == nil || strings.Contains(err.Error(), "absolute tunnel project path is required") ||
		!strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("demo did not reach control discovery after registering its tunnel: %v", err)
	}
}

func TestSplitDevPassthroughRequiresSeparator(t *testing.T) {
	parsed, command, err := splitDevPassthrough([]string{"dev", "web", "--", "pnpm", "dev", "--host"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(parsed, " ") != "dev web" || strings.Join(command, " ") != "pnpm dev --host" {
		t.Fatalf("parsed = %v, command = %v", parsed, command)
	}
	if _, _, err := splitDevPassthrough([]string{"dev", "--"}); err == nil {
		t.Fatal("empty development command was accepted")
	}
}

func TestSplitDevPassthroughAllowsGlobalOptionsBeforeDev(t *testing.T) {
	parsed, command, err := splitDevPassthrough([]string{
		"--config", "project/tnl.config.ts", "--no-telemetry", "dev", "api", "--", "pnpm", "dev", "--host", "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(parsed, " ") != "--config project/tnl.config.ts --no-telemetry dev api" ||
		strings.Join(command, " ") != "pnpm dev --host 127.0.0.1" {
		t.Fatalf("parsed = %v, command = %v", parsed, command)
	}
}

func TestSplitDevPassthroughAllowsExplicitGlobalBooleanValues(t *testing.T) {
	parsed, command, err := splitDevPassthrough([]string{
		"--no-telemetry=false", "--no-config=true", "dev", "api", "--", "node", "server.js",
	})
	if err != nil || strings.Join(parsed, " ") != "--no-telemetry=false --no-config=true dev api" ||
		strings.Join(command, " ") != "node server.js" {
		t.Fatalf("parsed = %v, command = %v, error = %v", parsed, command, err)
	}
}

func TestDevRejectsExplicitZeroPortAndStartupTimeout(t *testing.T) {
	for _, test := range []struct {
		flag, want string
	}{
		{"--port=0", "port must be between 1 and 65535"},
		{"--startup-timeout=0s", "startup timeout must be greater than zero"},
	} {
		t.Run(test.flag, func(t *testing.T) {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parser.Parse([]string{"dev", test.flag})
			if err != nil {
				t.Fatal(err)
			}
			applyTunnelCLIUnits(parsed, &flags)
			if err := (projectConfiguration{}).applyDev(&flags.Dev); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("explicit %s: %v", test.flag, err)
			}
		})
	}
}

func TestWriteCommandErrorUsesContextAndSharedFrame(t *testing.T) {
	var output bytes.Buffer
	writeCommandError(&output, clioutput.WrapCommand("tnl team use", failure.Wrap("select team", failure.TeamNotFound, errors.New("team not found"))))
	if got := output.String(); !strings.HasPrefix(got, "+--[ tnl team use ]-- command failed ") ||
		!strings.Contains(got, "team not found") || !strings.HasSuffix(got, "\n\n") {
		t.Fatalf("error output = %q", got)
	}
	output.Reset()
	writeCommandError(&output, clioutput.WrapCommand("tnl publish", diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("connection refused"))))
	if got := output.String(); !strings.HasPrefix(got, "+--[ tnl publish ]-- local service unavailable ") ||
		!strings.HasSuffix(got, "\n\n") {
		t.Fatalf("classified error output = %q", got)
	}
}

func TestTerminalResultUsesErrorLeaves(t *testing.T) {
	failure := errors.New("cleanup failed")
	for _, test := range []struct {
		name       string
		err        error
		wantCode   int
		wantRender bool
	}{
		{
			name: "pure cancellation",
			err: errors.Join(
				context.Canceled,
				fmt.Errorf("wrapped cancellation: %w", context.Canceled),
			),
		},
		{name: "cancellation with failure", err: errors.Join(context.Canceled, failure), wantCode: 1, wantRender: true},
		{name: "child exit", err: fmt.Errorf("child: %w", &childExitError{code: 23}), wantCode: 23},
		{name: "child exit with failure", err: errors.Join(&childExitError{code: 23}, failure), wantCode: 1, wantRender: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, render := terminalResult(test.err)
			if code != test.wantCode || (render != nil) != test.wantRender {
				t.Fatalf("terminalResult() = %d, %v", code, render)
			}
		})
	}
}

func TestClassifyCommandErrorMapsAuthenticationTimeout(t *testing.T) {
	err := classifyCommandError(fmt.Errorf("login: %w", clientauth.ErrAuthenticationTimeout))
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.AuthenticationTimeout ||
		!errors.Is(err, clientauth.ErrAuthenticationTimeout) {
		t.Fatalf("classified error = %v, code = %q", err, code)
	}
	if canceled := classifyCommandError(context.Canceled); canceled != context.Canceled {
		t.Fatalf("cancellation was classified: %v", canceled)
	}
}

func TestClassifyCommandErrorMapsCommonServerFailures(t *testing.T) {
	for _, test := range []struct {
		cause error
		code  diagnostic.Code
	}{
		{controlclient.ErrUnavailable, diagnostic.ServerUnavailable},
		{authorityclient.ErrRateLimited, diagnostic.RateLimited},
		{controlclient.ErrDNSProofPending, diagnostic.DNSSetupPending},
		{authorityclient.ErrUnauthenticated, diagnostic.AuthenticationRequired},
	} {
		classified := classifyCommandError(fmt.Errorf("request: %w", test.cause))
		if code, ok := diagnostic.CodeOf(classified); !ok || code != test.code || !errors.Is(classified, test.cause) {
			t.Fatalf("classified %v as %q, %t", test.cause, code, ok)
		}
	}
}

func TestVersionOutputRemainsRaw(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if want := buildinfo.Line("tnl") + "\n"; stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
