package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestCLIExposesTeamDomainRouteAndFinalAdminCommands(t *testing.T) {
	var flags cli
	parser := commandForTest(&flags, io.Discard)
	commands := map[string]bool{}
	var visit func(*cobra.Command)
	visit = func(cmd *cobra.Command) {
		commands[strings.TrimPrefix(cmd.CommandPath(), "tnl ")] = true
		for _, sub := range cmd.Commands() {
			visit(sub)
		}
	}
	visit((&commandApp{flags: &flags, out: io.Discard, errOut: io.Discard}).root())
	for _, command := range []string{
		"init", "publish", "status", "wait", "watch", "ping", "auth status", "auth login start", "auth login wait", "auth login inspect", "auth login cancel", "auth logout",
		"check", "generate", "telemetry on", "telemetry off", "telemetry status",
		"team current", "team list", "team use", "team create", "team members", "team invite create",
		"team invite list", "team invite revoke", "team join", "team member set-role", "team member remove",
		"domain claim", "domain default", "domain list", "domain status", "domain release", "domain transfer", "url list", "url inventory", "url available", "url delete",
		"url access show", "url access set", "auth browser", "team feedback get", "team feedback set",
		"share invite create", "share invite accept", "share invite list", "share invite revoke",
		"publisher enroll", "publisher setup", "publisher provision", "publisher current", "publisher list", "publisher revoke", "publisher grant add", "publisher grant revoke",
		"service install", "service start", "service stop", "service remove", "service list", "detached list", "detached stop",
		"admin server status", "admin relays list", "admin relays drain", "admin maintenance list",
		"admin maintenance allow", "admin maintenance block",
	} {
		if !commands[command] {
			t.Fatalf("command %q missing from help model", command)
		}
	}
	// service serve and runtime commands are implementation interfaces, not public help.
	for _, args := range [][]string{{"service", "serve"}, {"runtime", "serve", "--directory", t.TempDir()}, {"runtime", "owner-endpoint", "--directory", t.TempDir()}} {
		if _, err := parser(args); err != nil {
			t.Fatalf("hidden %v command cannot be invoked: %v", args, err)
		}
	}
	if _, err := parser([]string{"host", "list"}); err == nil {
		t.Fatal("obsolete host command was accepted")
	}
	if _, err := parser([]string{"route", "list"}); err == nil {
		t.Fatal("obsolete route command was accepted")
	}
	if _, err := parser([]string{"compose", "up"}); err == nil {
		t.Fatal("compose lifecycle command was accepted")
	}
	if _, err := parser([]string{"publish", "3000", "--bg"}); err == nil {
		t.Fatal("obsolete --bg flag was accepted")
	}
}

func TestInstallRequiresASavedPublicURLSelectorBeforeProjectState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "user-state")
	service := filepath.Join(t.TempDir(), "service-state")
	var output, diagnostics bytes.Buffer
	err := run(t.Context(), []string{"publish", "orders", "--install", "--state-dir", state, "--system-state-dir", service}, &output, &diagnostics)
	if reason, ok := failure.Of(err); !ok || reason.Reason() != failure.PublisherInstallOptions {
		t.Fatalf("project state opened before service preflight: %v", err)
	}
	for _, path := range []string{state, service} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("install preflight created %s: %v", path, err)
		}
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
		{"url", "list"}, {"url", "delete", "svc_0123456789abcdefghijkl"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var flags cli
			parser := commandForTest(&flags, io.Discard)
			if _, err := parser(append(args, "--team=studio")); err != nil {
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
	parser := commandForTest(&flags, io.Discard)
	if _, err := parser([]string{"domain", "list"}); err != nil {
		t.Fatal(err)
	}
	if selected := flags.Domain.List.selection().SelectedTeam; selected != "studio" {
		t.Fatalf("domain list team = %q", selected)
	}
}

func TestTunnelHelpExplainsIPPolicyAndTeamSelection(t *testing.T) {
	var output bytes.Buffer
	if err := run(t.Context(), []string{"help", "publish"}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(output.String()), " ")
	for _, want := range []string{"--anonymous", "--ip", "--team", "--server", "Defaults to 1024 for HTTP and 24 for TCP."} {
		if !strings.Contains(text, want) {
			t.Fatalf("publish help missing %q:\n%s", want, output.String())
		}
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

func TestHumanFlagErrorsShowOnlyBoundedFlagNames(t *testing.T) {
	const secret = "private-value"
	identity := string(failure.InvalidCommand) + "  " + failure.HelpURL(failure.InvalidCommand, "")
	for _, tc := range []struct{ arg, message string }{
		{"--lll=" + secret, "Unknown flag: --lll"},
		{"-z" + secret, "Unknown flag: -z"},
		{"--timeout=" + secret, "Invalid value for --timeout"},
		{"--server", "Missing value for --server"},
		{"---" + secret, "Invalid flag syntax."},
		{"--bad\n\x1b[31m" + secret, "Unknown flag."},
		{"--" + strings.Repeat("x", 65) + secret, "Unknown flag."},
	} {
		var out, diag bytes.Buffer
		err := run(t.Context(), []string{"auth", "login", tc.arg}, &out, &diag)
		if err == nil {
			t.Fatal("expected a parser error")
		}
		writeCommandError(&diag, err)
		text := diag.String()
		if text != "Error: "+tc.message+"\ntnl auth login --help\n"+identity+"\n" || out.Len() != 0 {
			t.Errorf("flag diagnostic = %q; stdout = %q", text, &out)
		}
	}
}

func TestMachineUnknownLoginFlagUsesInputClassification(t *testing.T) {
	var out, diag bytes.Buffer
	err := run(t.Context(), []string{"auth", "login", "--lll=private-value", "--output=json"}, &out, &diag)
	if err == nil {
		t.Fatal("unknown flag was accepted")
	}
	writeCommandError(&diag, err)
	var result commandDiagnostic
	if json.Unmarshal(diag.Bytes(), &result) != nil || result.Reason != string(failure.InvalidCommand) || result.Code != result.Reason || result.HelpURL != failure.HelpURL(failure.InvalidCommand, "") ||
		result.Message != "Unknown flag: --lll" || !slices.Equal(result.Command, []string{"tnl", "auth", "login", "--help"}) || strings.Contains(diag.String(), "private-value") || out.Len() != 0 {
		t.Fatalf("machine diagnostic = %s; stdout = %q", &diag, &out)
	}
}

func TestTeamCommandsUseMemberSlugFlag(t *testing.T) {
	var create cli
	createParser := commandForTest(&create, io.Discard)
	if _, err := createParser([]string{"team", "create", "studio"}); err != nil || create.Team.Create.Name != "studio" {
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
			parser := commandForTest(&flags, io.Discard)
			if _, err := parser(test.args); err != nil {
				t.Fatal(err)
			}
			if got := test.get(flags); got != "alice" {
				t.Fatalf("member slug = %q", got)
			}
		})
	}

	var flags cli
	parser := commandForTest(&flags, io.Discard)
	if _, err := parser([]string{"team", "create", "studio", "--slug", "another"}); err == nil {
		t.Fatal("obsolete team --slug flag was accepted")
	}
}

func TestPublishHostnameOptions(t *testing.T) {
	t.Setenv("TNL_NAME", "env-name")
	var flags cli
	parser := commandForTest(&flags, io.Discard)
	parsed, err := parser([]string{"publish", "3000", "--hostname", "https://flag.example", "--name", "api"})
	if err != nil {
		t.Fatal(err)
	}
	if commandID(parsed) != "publish <service-or-target>" || flags.Publish.PublicURL != "https://flag.example" || flags.Publish.Name != "api" {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestPublishRejectsRetiredPublicURLFlag(t *testing.T) {
	t.Setenv("TNL_HOSTNAME", "")
	t.Setenv("TNL_PUBLIC_URL", "old.example.test")
	var flags cli
	parser := commandForTest(&flags, io.Discard)
	if _, err := parser([]string{"publish", "3000"}); err != nil || flags.Publish.PublicURL != "" {
		t.Fatalf("retired TNL_PUBLIC_URL was read: %q, %v", flags.Publish.PublicURL, err)
	}
	if _, err := parser([]string{"publish", "3000", "--public-url", "https://flag.example"}); err == nil {
		t.Fatal("retired --public-url flag was accepted")
	}
}

func TestPublishResumePrintsHostnameFlag(t *testing.T) {
	t.Setenv("TNL_SERVER", "")
	var stderr bytes.Buffer
	output, err := newPublishOutput(publishOutputHuman, "tnl publish", io.Discard, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	flags := publishCommand{Target: "3000"}
	flags.StateDir = filepath.Join(t.TempDir(), "state")
	if err := publicationPresentation(t.Context(), flags, output).Resume("https://app.example.test", "", defaultServerURL); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://app.example.test", 1); err != nil {
		t.Fatal(err)
	}
	if code, render := terminalResult(output.finish(t.Context(), context.Canceled)); code != 0 || render != nil {
		t.Fatalf("stopping after readiness = %d, %v", code, render)
	}
	if !strings.HasPrefix(stderr.String(), "https://app.example.test\n") || strings.Count(stderr.String(), "tnl --no-config publish 3000 --hostname https://app.example.test --state-dir ") != 1 || strings.Contains(stderr.String(), "--server") {
		t.Fatal("expected the URL first, then a reusable command", stderr.String())
	}
	if _, err := os.Stat(flags.StateDir); !os.IsNotExist(err) {
		t.Fatalf("formatting the command created state: %v", err)
	}
}

func TestPublishFromEnrollmentEnvironmentWithoutProjectConfig(t *testing.T) {
	t.Setenv("TNL_TARGET", "")
	t.Setenv("TNL_HOSTNAME", "")
	t.Setenv("TNL_ENROLL_KEY", "pen_0123456789abcdefghijkl.example")
	var flags cli
	parser := commandForTest(&flags, io.Discard)
	parsed, err := parser([]string{"publish"})
	if err != nil {
		t.Fatal(err)
	}
	if commandID(parsed) != "publish <service-or-target>" || flags.Publish.Target != "" ||
		flags.Publish.PublicURL != "" || flags.Publish.EnrollmentKey != "pen_0123456789abcdefghijkl.example" {
		t.Fatalf("environment publish command %q = %#v", commandID(parsed), flags.Publish)
	}
	if err := (projectConfiguration{}).applyPublish(&flags.Publish); err != nil || flags.Publish.Name != "" {
		t.Fatalf("publish without project configuration = %#v, %v", flags.Publish, err)
	}
}

func TestFinalPublisherVisitorAndRuntimeCommandArguments(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"publisher", "enroll", "--namespace"}, "publisher enroll <service-or-address>"},
		{[]string{"publisher", "enroll", "svc_0123456789abcdefghijkl"}, "publisher enroll <service-or-address>"},
		{[]string{"publisher", "list"}, "publisher list"},
		{[]string{"publisher", "revoke", "pub_0123456789abcdefghijkl"}, "publisher revoke <publisher-identity-id>"},
		{[]string{"publisher", "grant", "add", "pub_0123456789abcdefghijkl", "--namespace"}, "publisher grant add <publisher-identity-id>"},
		{[]string{"publisher", "grant", "revoke", "pub_0123456789abcdefghijkl", "pgr_0123456789abcdefghijkl"}, "publisher grant revoke <publisher-identity-id> <grant-id>"},
		{[]string{"url", "access", "show", "orders.example"}, "url access show <url>"},
		{[]string{"url", "access", "set", "orders.example", "restricted", "--ip", "192.0.2.1"}, "url access set <url> <mode>"},
		{[]string{"auth", "browser", "app.example"}, "auth browser <url>"},
		{[]string{"team", "feedback", "set", "signed_in"}, "team feedback set <authors>"},
		{[]string{"share", "invite", "create", "app.example", "--email", "reviewer@example.com"}, "share invite create <url>"},
		{[]string{"share", "invite", "accept", "secret"}, "share invite accept <secret>"},
		{[]string{"share", "invite", "list", "app.example"}, "share invite list <url>"},
		{[]string{"share", "invite", "revoke", "app.example", "inv_1"}, "share invite revoke <url> <invitation-id>"},
		{[]string{"service", "start", "orders"}, "service start <job>"},
		{[]string{"service", "stop", "orders"}, "service stop <job>"},
		{[]string{"runtime", "endpoint", "--directory", "/tmp/project", "--service", "web"}, "runtime endpoint"},
		{[]string{"runtime", "owner-endpoint", "--directory", "/tmp/project"}, "runtime owner-endpoint"},
	} {
		var flags cli
		parser := commandForTest(&flags, io.Discard)
		parsed, err := parser(test.args)
		if err != nil {
			t.Fatalf("parse command %v: %v", test.args, err)
		}
		if got := commandID(parsed); got != test.want {
			t.Fatalf("command %v = %q, want %q", test.args, got, test.want)
		}
	}
}

func TestTunnelCLIUnitOverridesConflictingEnvironmentUnit(t *testing.T) {
	t.Setenv("TNL_NAME", "environment-name")
	var flags cli
	parser := commandForTest(&flags, io.Discard)
	args := []string{"publish", "3000", "--hostname", "https://api.example", "--ip", "current"}
	parsed, err := parser(args)
	if err != nil {
		t.Fatal(err)
	}
	applyTunnelCLIUnits(parsed, &flags)
	if flags.Publish.Name != "" || flags.Publish.PublicURL != "https://api.example" ||
		len(flags.Publish.IP) != 1 || flags.Publish.IP[0] != "current" {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestExplicitFalseTunnelFlagsOverrideProjectConfiguration(t *testing.T) {
	var flags cli
	parser := commandForTest(&flags, io.Discard)
	args := []string{"publish", "3000", "--ephemeral=false"}
	parsed, err := parser(args)
	if err != nil {
		t.Fatal(err)
	}
	applyTunnelCLIUnits(parsed, &flags)
	configured := true
	applyServiceConfiguration(&flags.Publish.tunnelFlags, config.Service{
		Ephemeral: &configured,
	})
	if flags.Publish.Ephemeral {
		t.Fatalf("publish flags = %#v", flags.Publish)
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
		"publish": "publish <service-or-target>",
		"status":  "status",
	} {
		if got := canonicalParsedCommand(command); got != want {
			t.Fatalf("canonicalParsedCommand(%q) = %q, want %q", command, got, want)
		}
	}
}

func TestBarePublishReachesCanonicalDispatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stateDir := filepath.Join(t.TempDir(), "state")
	err := run(t.Context(), []string{"--no-config", "publish", "--state-dir", stateDir, "--server", "http://control.example"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "pass a target or select a configured service") {
		t.Fatalf("run error = %v", err)
	}
	if reason, _, ok := failure.Describe(err); !ok || reason != failure.MissingTarget {
		t.Fatalf("run failure reason = %q, %t", reason, ok)
	}
	if got, ok := clioutput.CommandOf(err); !ok || got != "tnl publish" {
		t.Fatalf("command = %q, %t", got, ok)
	}
	writeCommandError(&stderr, err)
	if got := stderr.String(); !strings.HasPrefix(got, "Error: ") || strings.Contains(got, "clientstate: ") {
		t.Fatalf("error output = %q", got)
	}
}

func TestDemoPublishUsesFreshEphemeralURLAndSkipsProject(t *testing.T) {
	var flags cli
	parser := commandForTest(&flags, io.Discard)
	parsed, err := parser([]string{"publish", "--demo", "--open=false"})
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
	if flags.Publish.Anonymous || flags.Publish.access != nil {
		t.Fatal("the demo flag alone must leave guest access selection to the server")
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
		{"name", []string{"publish", "--demo", "--name", "saved"}, failure.DemoURLManaged, "remove --name or --hostname"},
		{"hostname", []string{"publish", "--demo", "--hostname", "https://saved.example"}, failure.DemoURLManaged, "remove --name or --hostname"},
		{"ephemeral", []string{"publish", "--demo", "--ephemeral=false"}, failure.DemoMustBeEphemeral, "remove --ephemeral=false"},
		{"concurrency", []string{"publish", "--demo", "--concurrency", "0"}, failure.InvalidTunnelFlags, "--concurrency"},
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

func TestDemoPublishHonorsExplicitRestrictedAccess(t *testing.T) {
	var flags cli
	parsed, err := commandForTest(&flags, io.Discard)([]string{"publish", "--demo", "--anonymous=false"})
	if err != nil {
		t.Fatal(err)
	}
	applyTunnelCLIUnits(parsed, &flags)
	if flags.Publish.Anonymous || flags.Publish.access == nil || flags.Publish.access.VisitorMode() != "restricted" {
		t.Fatal("explicit --anonymous=false did not preserve restricted demo access")
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

func TestCLIKeychainGuidanceKeepsCausePrivate(t *testing.T) {
	cause := errors.New("private command echo: -w stored-credential")
	for _, kind := range []failure.KeychainFailure{
		failure.KeychainAccess, failure.KeychainTimeout, failure.KeychainCanceled,
		failure.KeychainMissing, failure.KeychainUnavailable,
	} {
		err := failure.Wrap("open client state", failure.ClientStateUnavailable, &failure.ClientKeychainError{Kind: kind, Cause: cause})
		var output bytes.Buffer
		writeCommandError(&output, clioutput.WrapCommand("tnl auth login start", err))
		text := output.String()
		if !strings.Contains(text, "Keychain") || !strings.Contains(text, "TNL_CLIENT_STATE_UNAVAILABLE") ||
			!strings.Contains(text, "https://tnl.dev/c/state-unavailable?case=") ||
			strings.Contains(text, cause.Error()) || strings.Contains(text, "stored-credential") || !errors.Is(err, cause) {
			t.Fatalf("unsafe or generic Keychain diagnostic = %q", text)
		}
		output.Reset()
		writeMachineCommandError(&output, err)
		var machine struct {
			SchemaVersion int    `json:"schema_version"`
			Type          string `json:"type"`
			commandDiagnostic
		}
		if decodeErr := json.Unmarshal(output.Bytes(), &machine); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		variant := failure.CaseFor(failure.ClientStateUnavailable, failure.KnownCase(err))
		if machine.SchemaVersion != 1 || machine.Type != "error" || machine.Code != string(failure.ClientStateUnavailable) ||
			machine.Action != variant.Action || machine.Retryable || strings.Contains(output.String(), "stored-credential") {
			t.Fatalf("machine Keychain guidance or contract = %s", output.String())
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

func TestGuestCommandExplainsSignInAndDemoWithoutPrompting(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	database, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGuestSession(t.Context(), clientstate.GuestSession{
		GuestID: "gst_0123456789abcdefghijkl", AccessToken: token.String(),
		ExpiresAt: time.Now().UTC().Add(72 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err = run(t.Context(), []string{"--no-config", "team", "current", "--server=https://control.example", "--state-dir", root}, &stdout, &stderr)
	if err == nil {
		t.Fatal("guest was prompted for team access")
	}
	if reason, _, typed := failure.Describe(err); !typed || reason != failure.GuestSignInRequired {
		t.Fatalf("guest sign-in reason = %q, typed = %t", reason, typed)
	}
	writeCommandError(&stderr, err)
	if !strings.Contains(stderr.String(), "tnl auth login") || !strings.Contains(stderr.String(), "tnl publish") || !strings.Contains(stderr.String(), "--demo") ||
		strings.Contains(stderr.String(), "authentication required") || stdout.Len() != 0 {
		t.Fatalf("guest command output = %q, stdout = %q", stderr.String(), stdout.String())
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

func TestWriteCommandErrorShowsActionCodeAndHelp(t *testing.T) {
	var output bytes.Buffer
	writeCommandError(&output, clioutput.WrapCommand("tnl team use", failure.Wrap("select team", failure.TeamNotFound, errors.New("team not found"))))
	if got := output.String(); !strings.HasPrefix(got, "Error: ") ||
		!strings.Contains(got, "team not found") || !strings.Contains(got, "TNL_CLIENT_TEAM_NOT_FOUND") ||
		!strings.Contains(got, "https://tnl.dev/c/team-not-found") || strings.Contains(got, "\n\n") {
		t.Fatalf("error output = %q", got)
	}
	output.Reset()
	writeCommandError(&output, clioutput.WrapCommand("tnl publish", diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("connection refused"))))
	if got := output.String(); !strings.HasPrefix(got, "tnl could not reach") ||
		!strings.Contains(got, "TNL_TARGET_UNAVAILABLE") {
		t.Fatalf("classified error output = %q", got)
	}
}

func TestClientErrorsHaveCopyableHelpAndStableCodes(t *testing.T) {
	for _, entry := range failure.ClientReasons() {
		var output bytes.Buffer
		writeCommandError(&output, failure.Wrap("test client failure", entry.Code, errors.New("secret-token")))
		text := output.String()
		if !strings.Contains(text, failure.HelpURL(entry.Code, "")) {
			// each client error must be reachable even when its internal cause is not.
			t.Fatalf("missing help for %s: %q", entry.Code, text)
		}
		if !strings.Contains(text, string(entry.Code)) || strings.Contains(text, "secret-token") {
			t.Fatalf("unsafe output for %s: %q", entry.Code, text)
		}
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
	err := classifyCommandError(fmt.Errorf("login: %w", auth.ErrAuthenticationTimeout))
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.AuthenticationTimeout ||
		!errors.Is(err, auth.ErrAuthenticationTimeout) {
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
		{clientcontrol.ErrUnavailable, diagnostic.ServerUnavailable},
		{clientauthority.ErrRateLimited, diagnostic.RateLimited},
		{clientcontrol.ErrDNSProofPending, diagnostic.DNSSetupPending},
		{clientauthority.ErrUnauthenticated, diagnostic.AuthenticationRequired},
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
