package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestAuthorizationConfiguration(t *testing.T) {
	valid := TNLD{
		Mode:                           TNLDModeStandalone,
		AuthorizationAuthorityEndpoint: "https://authority.example",
		AuthorizationIssuer:            "https://authority.example/issuer",
		AuthorizationReceiver:          "https://server.example",
		AuthorizationKeyID:             "key-1",
		AuthorizationPublicKey:         base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
	}
	if err := valid.validateAuthorization(); err != nil {
		t.Fatal(err)
	}
	if !valid.SignedAuthorizationEnabled() || len(valid.AuthorizationConfig().PublicKey) != ed25519.PublicKeySize {
		t.Fatal("valid authorization configuration was not exposed")
	}

	for name, mutate := range map[string]func(*TNLD){
		"incomplete":     func(config *TNLD) { config.AuthorizationKeyID = "" },
		"endpoint path":  func(config *TNLD) { config.AuthorizationAuthorityEndpoint += "/v1" },
		"endpoint slash": func(config *TNLD) { config.AuthorizationAuthorityEndpoint += "/" },
		"default port":   func(config *TNLD) { config.AuthorizationAuthorityEndpoint = "https://authority.example:443" },
		"padded key":     func(config *TNLD) { config.AuthorizationPublicKey += "=" },
		"worker mode":    func(config *TNLD) { config.Mode = TNLDModeWorker },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if err := config.validateAuthorization(); err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatal("invalid authorization configuration was accepted")
			}
		})
	}
}
