package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestNestedAliasDiagnosticNamesDomainPolicyAndAvailableCustomDomain(t *testing.T) {
	for _, custom := range []bool{false, true} {
		services := publisherServices{hostname: "api.shop.member.tnl.dev", namespace: "member.tnl.dev", domainKind: authorityv1.Managed, publicURLScope: controlv1.Member,
			customDomainAvailable: custom, authenticated: &clientauth.Client{Discovery: controlv1.ControlDiscovery{ManagedDomain: "tnl.dev", ManagedDomainMaxMemberChildLabels: 1}}}
		err := checkAliasHostnamePolicy(services)
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
		services.hostname = "review.member.tnl.dev"
		if err := checkAliasHostnamePolicy(services); err != nil {
			t.Fatal("one-label alias rejected")
		}
		services.hostname, services.domainKind = "api.shop.member.custom.example", authorityv1.Custom
		services.namespace = "member.custom.example"
		if err := checkAliasHostnamePolicy(services); err != nil {
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
