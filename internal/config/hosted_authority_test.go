package config

import (
	"strings"
	"testing"
)

func TestHostedAuthorityConfiguration(t *testing.T) {
	valid := TNLD{
		Mode:              TNLDModeControl,
		AuthorityEndpoint: "https://authority.example",
		HostedSecret:      "hosted-service-secret-012345678901",
	}
	if err := valid.validateHostedAuthority(); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*TNLD){
		"missing secret": func(config *TNLD) { config.HostedSecret = "" },
		"endpoint path":  func(config *TNLD) { config.AuthorityEndpoint += "/v1" },
		"endpoint slash": func(config *TNLD) { config.AuthorityEndpoint += "/" },
		"default port":   func(config *TNLD) { config.AuthorityEndpoint = "https://authority.example:443" },
		"short secret":   func(config *TNLD) { config.HostedSecret = "short" },
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
