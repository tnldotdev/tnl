package tnldconfig

import (
	"strings"
	"testing"
)

func TestHostedAuthorityConfiguration(t *testing.T) {
	valid := Config{
		Mode:              RoleControl,
		AuthorityEndpoint: "https://authority.example",
		HostedSecret:      "hosted-service-secret-012345678901",
		OIDCIssuer:        "https://identity.example/realms/company",
		OIDCClientID:      "tnl-cli",
		OIDCLoginFlow:     OIDCLoginFlowDeviceCode,
	}
	if err := valid.validateHostedAuthority(); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*Config){
		"missing secret": func(config *Config) { config.HostedSecret = "" },
		"missing OIDC":   func(config *Config) { config.OIDCIssuer = "" },
		"endpoint path":  func(config *Config) { config.AuthorityEndpoint += "/v1" },
		"endpoint slash": func(config *Config) { config.AuthorityEndpoint += "/" },
		"default port":   func(config *Config) { config.AuthorityEndpoint = "https://authority.example:443" },
		"short secret":   func(config *Config) { config.HostedSecret = "short" },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if err := config.validateHostedAuthority(); err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatal("invalid hosted authority configuration was accepted")
			}
		})
	}
}

func TestControlAuthorityModesAreExclusive(t *testing.T) {
	builtin := validCertificateConfig(t, RoleControl)
	builtin.OIDCIssuer = "https://identity.example/realms/company"
	builtin.OIDCClientID = "tnl-cli"
	builtin.OIDCLoginFlow = OIDCLoginFlowAuthorizationCodePKCE
	builtin.OIDCScopes = []string{"openid", "profile", "email"}
	if err := builtin.Validate(); err != nil {
		t.Fatalf("built-in authority with OIDC: %v", err)
	}

	external := builtin
	external.LoginToken = ""
	external.AuthorityEndpoint = "https://authority.example"
	external.HostedSecret = "hosted-service-secret-012345678901"
	if err := external.Validate(); err != nil {
		t.Fatalf("external authority: %v", err)
	}
	external.LoginToken = testLoginToken
	if err := external.Validate(); err == nil || !strings.Contains(err.Error(), "login token") {
		t.Fatalf("external authority with login token = %v", err)
	}
}
