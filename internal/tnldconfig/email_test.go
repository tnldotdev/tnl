package tnldconfig

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestEmailAndWebsiteFailuresNameTheirSettings(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*Config)
		reason    failure.Reason
		setting   failure.Setting
	}{
		{"missing_receiver", func(c *Config) { c.WebhookSecret = testClusterSecret }, failure.ServerEmailConfigInvalid, failure.SettingEmailURL},
		{"missing_secret", func(c *Config) { c.EmailURL = "https://mail.example.test" }, failure.ServerEmailConfigInvalid, failure.SettingWebhookSecret},
		{"invalid_receiver", func(c *Config) { c.EmailURL, c.WebhookSecret = "http://mail.example.test", testClusterSecret }, failure.ServerEmailConfigInvalid, failure.SettingEmailURL},
		{"invalid_secret", func(c *Config) { c.EmailURL, c.WebhookSecret = "https://mail.example.test", "short" }, failure.ServerEmailConfigInvalid, failure.SettingWebhookSecret},
		{"website_without_issuer", func(c *Config) { c.WebServiceSecret = testClusterSecret }, failure.ServerWebsiteConfigInvalid, failure.SettingOIDCIssuer},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validCertificateConfig(t, RoleControl)
			test.configure(&cfg)
			err := cfg.Validate()
			classified, ok := failure.Of(err)
			if !ok || classified.Reason() != test.reason || classified.Setting() != test.setting {
				t.Fatalf("configuration failure = %v; want %s for %s", err, test.reason, test.setting)
			}
		})
	}
}

func TestWebhookSecretEnvironmentAndFlag(t *testing.T) {
	args := []string{"--role", "standalone", "--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "infra.example.test", "--managed-deployment-domain", "routes.example.test",
		"--login-token", testLoginToken, "--storage-key", testStorageKey,
		"--acme-email", "operator@example.test", "--acme-accept-terms",
		"--email-url", "https://mail.example.test"}
	t.Setenv("TNLD_WEBHOOK_SECRET", testClusterSecret)
	for _, flags := range [][]string{nil, {"--webhook-secret", "abcdef0123456789abcdef0123456789"}} {
		cfg, err := Parse(append(args, flags...))
		if err != nil {
			t.Fatal(err)
		}
		want := testClusterSecret
		if len(flags) != 0 {
			want = flags[1]
		}
		if cfg.WebhookSecret != want {
			t.Fatal("webhook secret was not selected from environment or flag")
		}
	}
}
