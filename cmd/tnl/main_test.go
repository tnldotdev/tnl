package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/diagnostic"
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
		"config path", "config check", "config generate",
		"team current", "team list", "team use", "team create", "team members", "team invite create",
		"team invite list", "team invite revoke", "team join", "team member set-role", "team member remove",
		"domain claim", "domain default", "domain list", "domain release", "route list", "route delete",
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
}

func TestTeamCommandsUseMemberSlugFlag(t *testing.T) {
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
	if _, err := parser.Parse([]string{"team", "create", "example", "--slug", "alice"}); err == nil {
		t.Fatal("obsolete --slug flag was accepted")
	}
}

func TestPublishHostnameOptions(t *testing.T) {
	t.Setenv("TNL_HOST", "env.example")
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"publish", "3000", "--host", "flag.example", "--subdomain", "api"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "publish <service-or-target>" || flags.Publish.Host != "flag.example" || flags.Publish.Subdomain != "api" {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestTunnelCLIUnitOverridesConflictingEnvironmentUnit(t *testing.T) {
	t.Setenv("TNL_HOST", "environment.example")
	t.Setenv("TNL_ALLOW_ALL_IPS", "true")
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"publish", "3000", "--subdomain", "api", "--allow-ip", "192.0.2.1"}
	parsed, err := parser.Parse(args)
	if err != nil {
		t.Fatal(err)
	}
	applyTunnelCLIUnits(args, parsed.Command(), &flags)
	if flags.Publish.Host != "" || flags.Publish.Subdomain != "api" || flags.Publish.AllowAllIPs ||
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
	applyTunnelCLIUnits(args, parsed.Command(), &flags)
	configured := true
	applyTunnelConfiguration(&flags.Publish.tunnelFlags, &config.Tunnel{
		AllowAllIPs: &configured, Ephemeral: &configured,
	})
	if flags.Publish.AllowAllIPs || flags.Publish.Ephemeral {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestResolvePublishHostnameUsesMemberNamespace(t *testing.T) {
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
	hostname, domain, scope, err := resolvePublishHostname("", "api", current)
	if err != nil {
		t.Fatal(err)
	}
	if hostname != "api.chase-abc.tnl.dev" || domain.Id != "domain_1" || scope != controlv1.Member {
		t.Fatalf("resolution = %q, %#v, %q", hostname, domain, scope)
	}
	if _, _, _, err := resolvePublishHostname("shared.tnl.dev", "", current); err == nil {
		t.Fatal("member was allowed to create a shared route")
	}
	generated, _, generatedScope, err := resolvePublishHostname("", "", current)
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
		command string
		wantErr string
	}{
		{command: "dev", wantErr: "clientstate: server must be an HTTPS origin"},
		{command: "publish", wantErr: "local target is required as an argument or publish.target in project configuration"},
	} {
		t.Run(test.command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			stateDir := filepath.Join(t.TempDir(), "state")
			args := []string{"--no-config", test.command, "--state-dir", stateDir, "--server", "http://control.example"}
			err := run(t.Context(), args, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("run error = %v, want %q", err, test.wantErr)
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
		})
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

func TestWriteCommandErrorUsesContextAndSharedFrame(t *testing.T) {
	var output bytes.Buffer
	writeCommandError(&output, clioutput.WrapCommand("tnl team use", errors.New("team not found")))
	if got := output.String(); !strings.HasPrefix(got, "+--[ tnl team use ]-- command failed ") ||
		!strings.Contains(got, "team not found") {
		t.Fatalf("error output = %q", got)
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
