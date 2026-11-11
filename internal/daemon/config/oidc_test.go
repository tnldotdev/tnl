package config

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestOIDCRequiredAndExplicitIdentitySeeds(t *testing.T) {
	t.Setenv("TNLD_ROUTE53_SERVER_ZONE_ID", "ZSERVER")
	config, err := Parse([]string{"--role", "standalone", "--database-url", "postgres://tnl:secret@database.example/tnl", "--server-domain", "tnl.example.com", "--managed-domain", "tunnels.example.com", "--acme-email", "operator@example.com", "--acme-accept-terms", "--oidc-issuer", testOIDCIssuer, "--oidc-client-id", "server", "--storage-key", testStorageKey, "--initial-administrator", "operator-subject", "--initial-team-owner", "studio=owner-subject", "--default-team", "studio", "--default-team-member", "member-subject"})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.InitialAdministrators) != 1 || config.InitialAdministrators[0] != "operator-subject" || config.InitialTeamOwners["studio"] != "owner-subject" || config.DefaultTeam != "studio" || len(config.DefaultTeamMembers) != 1 {
		t.Fatalf("seed parsing: %#v", config)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.OIDCIssuer = "" }, func(c *Config) { c.OIDCClientID = "" }, func(c *Config) { c.InitialAdministrators = []string{"bad\nsubject"} }, func(c *Config) { c.DefaultTeam = "" }, func(c *Config) { c.OIDCScopes = []string{"email"} }} {
		invalid := config
		mutate(&invalid)
		if err := invalid.Validate(); err == nil {
			t.Fatal("invalid OIDC settings accepted")
		} else if reason, _ := failure.ReasonOf(err); reason != failure.ServerOIDCInvalid {
			t.Fatalf("OIDC failure: %v", err)
		}
	}
}

func TestHTTPIdentityProviderRequiresLocalStandalone(t *testing.T) {
	local := Config{Role: RoleStandalone, ControlURL: "http://localhost:8445", OIDCIssuer: "http://localhost:8444", OIDCClientID: "local"}
	if err := local.validateOIDC(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Role = RoleControl },
		func(c *Config) { c.ControlURL = "https://control.example" },
		func(c *Config) { c.OIDCIssuer = "http://identity:8444" },
		func(c *Config) { c.OIDCIssuer = "http://identity.127.0.0.1.nip.io:8444" },
	} {
		invalid := local
		mutate(&invalid)
		if invalid.validateOIDC() == nil {
			t.Fatal("nonlocal HTTP OIDC accepted")
		}
	}
}
