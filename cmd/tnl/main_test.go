package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/credentials"
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
		"team current", "team list", "team use", "team create", "team members", "team invite create",
		"team invite list", "team invite revoke", "team join", "team member set-role", "team member remove",
		"domain claim", "domain default", "domain list", "domain release", "route list", "route delete",
		"admin server status", "admin relays list", "admin relays drain", "admin maintenance list",
		"admin maintenance enable", "admin maintenance disable",
	} {
		if !commands[command] {
			t.Fatalf("command %q missing from help model", command)
		}
	}
	if _, err := parser.Parse([]string{"host", "list"}); err == nil {
		t.Fatal("obsolete host command was accepted")
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
	if parsed.Command() != "publish <target>" || flags.Publish.Host != "flag.example" || flags.Publish.Subdomain != "api" {
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
	hostname, domain, scope, plan, err := resolvePublishHostname("", "api", current, controlv1.ControlDiscovery{DnsAutomation: true})
	if err != nil {
		t.Fatal(err)
	}
	if hostname != "api.chase-abc.tnl.dev" || domain.Id != "domain_1" || scope != controlv1.Member ||
		plan.Scope != "chase-abc.tnl.dev" || len(plan.Identifiers) != 2 || plan.ChallengeMethod != controlv1.Dns01 {
		t.Fatalf("resolution = %q, %#v, %q, %#v", hostname, domain, scope, plan)
	}
	if _, _, _, _, err := resolvePublishHostname("shared.tnl.dev", "", current, controlv1.ControlDiscovery{}); err == nil {
		t.Fatal("member was allowed to create a shared route")
	}
	generated, _, generatedScope, _, err := resolvePublishHostname("", "", current, controlv1.ControlDiscovery{})
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

func TestCanonicalCommandTitle(t *testing.T) {
	for command, want := range map[string]string{
		"publish <target>":                     "tnl publish",
		"dev <command>":                        "tnl dev",
		"team member set-role <membership-id>": "tnl team member set-role",
		"status":                               "tnl status",
	} {
		if got := clioutput.CommandTitle("tnl", command); got != want {
			t.Fatalf("CommandTitle(%q) = %q, want %q", command, got, want)
		}
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
