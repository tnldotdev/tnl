package config

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestExplicitSettingsRejectUnusedRolesFromEverySource(t *testing.T) {
	base := []string{"--role=ingress", "--control-hostname=control.example.test", "--ingress-control-credential", testClusterSecret, "--forwarding-credential", testForwarding, "--ingress-id=ingress-1"}
	for _, flag := range []string{"relay-stream-capacity=10", "traffic-default-connections=1024", "ingress-lease-duration=30s", "service-certificate-workers=8"} {
		if _, err := Parse(append(append([]string{}, base...), "--"+flag)); err == nil {
			t.Fatal("accepted unused flag", flag)
		}
	}
	t.Setenv("TNLD_RELAY_STREAM_CAPACITY", "4096")
	if _, err := Parse(base); err == nil {
		t.Fatal("accepted an unused environment value equal to its default")
	}
}

func TestInspectRedactsSecretsAndExplainsSources(t *testing.T) {
	c := Config{Role: RoleControl, DatabaseURL: "postgres://secret", StorageKey: "private-key",
		OIDCClientSecret: "private-oidc", InitialAdministrators: []string{"private-subject"}}
	t.Setenv("TNLD_METRICS_LISTEN", "127.0.0.1:9091")
	values := Inspect(c, map[string]string{"database_url": "file", "metrics_listen": "flag"})
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"postgres://secret", "private-key", "private-oidc", "private-subject"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("inspection disclosed private configuration")
		}
	}
	if values["database_url"].Source != "file" || values["metrics_listen"].Source != "flag" {
		t.Fatal("inspection lost precedence", values)
	}
	if _, ok := values["relay_stream_capacity"]; ok {
		t.Fatal("inspection included an unused setting")
	}
}

func TestFlyMachineIdentityUsesExactMachineAndApp(t *testing.T) {
	t.Setenv("FLY_MACHINE_ID", "abc123")
	t.Setenv("FLY_APP_NAME", "actual-relay-app")
	c := Config{Role: RoleRelay, FlyMachineIdentity: true, RelayServiceID: "relay-iad-1", RelayIDPrefix: "iad-1", InternalRelayListen: "[::]:9445"}
	if err := c.resolveFlyIdentity(); err != nil {
		t.Fatal(err)
	}
	if c.RelayID != "iad-1-abc123" || c.InternalRelayAddress != "abc123.vm.actual-relay-app.internal:9445" {
		t.Fatal("Fly identity did not select the exact Machine", c.RelayID, c.InternalRelayAddress)
	}
	c.InternalRelayAddress = "app-wide.internal:9445"
	if err := c.resolveFlyIdentity(); err == nil {
		t.Fatal("explicit app-wide forwarding overrode Machine identity")
	}
	ingress := Config{Role: RoleIngress, FlyMachineIdentity: true}
	if err := ingress.resolveFlyIdentity(); err != nil || ingress.IngressID != "ingress-abc123" {
		t.Fatal("ingress identity", ingress.IngressID, err)
	}
}

func TestSlotCredentialsOnlyAppearRedactedOnTheirRole(t *testing.T) {
	for name, owner := range map[string]Role{
		"relay_slots_file": RoleControl, "relay_slot_credential": RoleRelay, "forwarding_credential": RoleIngress,
	} {
		for _, role := range []Role{RoleControl, RoleRelay, RoleIngress, RoleStandalone} {
			values := Inspect(Config{Role: role, RelaySlotsFile: "private", RelaySlotCredential: "private", ForwardingCredential: "private"}, nil)
			v, found := values[name]
			if found != (role == owner || name == "forwarding_credential" && role == RoleRelay) || found && v.Value != "[redacted]" {
				t.Fatalf("incorrect role or redaction for %s on %s", name, role)
			}
		}
	}
}

func TestSplitCredentialsRequiredAndDistinct(t *testing.T) {
	for _, tc := range []struct {
		name   string
		role   Role
		change func(*Config)
		reason failure.Reason
	}{
		{"missing inventory", RoleControl, func(c *Config) { c.RelaySlotsFile = "" }, failure.ServerConfigInvalid},
		{"missing ingress credential", RoleControl, func(c *Config) { c.IngressControlCredential = "" }, failure.ServerClusterSecretInvalid},
		{"missing slot credential", RoleRelay, func(c *Config) { c.RelaySlotCredential = "" }, failure.ServerClusterSecretInvalid},
		{"missing forwarding credential", RoleIngress, func(c *Config) { c.ForwardingCredential = "" }, failure.ServerClusterSecretInvalid},
		{"shared forwarding and slot credential", RoleRelay, func(c *Config) { c.ForwardingCredential = c.RelaySlotCredential }, failure.ServerClusterSecretInvalid},
		{"previous forwarding matches slot", RoleRelay, func(c *Config) { c.ForwardingCredentialPrevious = c.RelaySlotCredential }, failure.ServerClusterSecretInvalid},
		{"shared forwarding and ingress credential", RoleIngress, func(c *Config) { c.ForwardingCredential = c.IngressControlCredential }, failure.ServerClusterSecretInvalid},
		{"ingress control credential on relay", RoleRelay, func(c *Config) { c.IngressControlCredential = testClusterSecret }, failure.ServerClusterSecretInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validCertificateConfig(t, tc.role)
			tc.change(&c)
			err := c.Validate()
			reason, def, ok := failure.Describe(err)
			if !ok || reason != tc.reason || def.Retry != failure.RetryAfterChange || errors.Unwrap(err) == nil {
				t.Fatalf("unexpected failure: %v", err)
			}
			message := failure.SafeMessage(err, failure.Unexpected)
			for _, token := range []string{testSlot, testForwarding, testClusterSecret} {
				if strings.Contains(message, token) {
					t.Fatal("diagnostic included a credential")
				}
			}
		})
	}
}

func TestPublisherConnectionStreamLimit(t *testing.T) {
	base := []string{"--role=relay", "--control-hostname=control.example.test", "--relay-slot-credential", testSlot, "--forwarding-credential", testForwarding,
		"--relay-service-id=relay-a", "--relay-id=relay-a-1", "--relay-address=relay.example.test:443", "--internal-relay-address=relay.internal:9445"}
	c, err := Parse(append(append([]string{}, base...), "--publisher-connection-stream-limit=123"))
	if err != nil || c.PublisherConnectionStreamLimit != 123 || c.RelayQUICConfig().Config.MaxIncomingStreams != 123 {
		t.Fatal("transport limit", c.PublisherConnectionStreamLimit, err)
	}
	if _, err := Parse(append(append([]string{}, base...), "--quic-max-incoming-streams=123")); err == nil {
		t.Fatal("accepted the removed QUIC-named stream setting")
	}
	for _, value := range []string{"0", "-2"} {
		if _, err := Parse(append(append([]string{}, base...), "--publisher-connection-stream-limit="+value)); err == nil {
			t.Fatal("accepted an invalid stream limit", value)
		}
	}
	t.Setenv("TNLD_PUBLISHER_CONNECTION_STREAM_LIMIT", "321")
	fromEnvironment, err := Parse(base)
	if err != nil || fromEnvironment.PublisherConnectionStreamLimit != 321 {
		t.Fatal("stream limit environment override", fromEnvironment.PublisherConnectionStreamLimit, err)
	}
	if inspected := Inspect(fromEnvironment, nil)["publisher_connection_stream_limit"]; inspected.Value != int64(321) || inspected.Source != "environment" {
		t.Fatal("stream limit inspection lost its environment source", inspected)
	}
	fromFlag, err := Parse(append(append([]string{}, base...), "--publisher-connection-stream-limit=456"))
	if err != nil || fromFlag.PublisherConnectionStreamLimit != 456 {
		t.Fatal("stream limit flag precedence", fromFlag.PublisherConnectionStreamLimit, err)
	}
	if inspected := Inspect(fromFlag, map[string]string{"publisher_connection_stream_limit": "flag"})["publisher_connection_stream_limit"]; inspected.Value != int64(456) || inspected.Source != "flag" {
		t.Fatal("stream limit inspection lost its flag source", inspected)
	}
}
