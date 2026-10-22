package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestNestedAliasDiagnosticNamesDomainPolicyAndAvailableCustomDomain(t *testing.T) {
	for _, custom := range []bool{false, true} {
		policy := invocation.AliasHostnamePolicy{Hostname: "api.shop.member.tnl.dev", Namespace: "member.tnl.dev", DomainKind: authorityv1.Managed, Scope: controlv1.Member, CustomDomainAvailable: custom, MaxMemberChildLabels: 1}
		err := invocation.CheckAliasHostnamePolicy(policy)
		if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.MemberHostnameDepthExceeded {
			t.Fatal("nested name did not have its own policy diagnostic")
		}
		var output bytes.Buffer
		writeCommandError(&output, err)
		text := output.String()
		if !strings.Contains(text, "api.shop") || !strings.Contains(text, "2 labels") || !strings.Contains(text, "allows 1") || strings.Contains(text, "claimed") || strings.Contains(text, "certificate") {
			t.Fatalf("unclear nested-alias error: %s", text)
		}
		if strings.Contains(text, "custom domain") != custom {
			t.Fatalf("custom-domain advice does not match availability: %s", text)
		}
		policy.Hostname = "review.member.tnl.dev"
		if err := invocation.CheckAliasHostnamePolicy(policy); err != nil {
			t.Fatal("one-label alias rejected")
		}
		policy.Hostname, policy.DomainKind = "api.shop.member.custom.example", authorityv1.Custom
		policy.Namespace = "member.custom.example"
		if err := invocation.CheckAliasHostnamePolicy(policy); err != nil {
			t.Fatal("hosted managed-domain limit applied to a custom domain")
		}
	}
}

func TestAliasCommandPreflightDoesNotCreateClientStateWithoutConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	root := filepath.Join(t.TempDir(), "state")
	var output bytes.Buffer
	err := run(t.Context(), []string{"--no-telemetry", "alias", "use", "review", "--state-dir", root}, &output, &output)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ProjectConfigMissing {
		t.Fatalf("alias preflight = %v", err)
	}
	if _, err := os.Stat(clientstate.DatabasePath(root)); !os.IsNotExist(err) {
		t.Fatal("alias preflight created client state")
	}
}
