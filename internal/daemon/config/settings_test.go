package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExplicitSettingsRejectUnusedRolesFromEverySource(t *testing.T) {
	base := []string{"--role=ingress", "--control-hostname=control.example.test", "--cluster-secret=" + testClusterSecret, "--ingress-id=ingress-1"}
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

func TestPublisherStreamLimitAppliesToBothTransportsAndKeepsLegacyOverride(t *testing.T) {
	base := []string{"--role=relay", "--control-hostname=control.example.test", "--cluster-secret=" + testClusterSecret,
		"--relay-service-id=relay-a", "--relay-id=relay-a-1", "--relay-address=relay.example.test:443", "--internal-relay-address=relay.internal:9445"}
	for _, flag := range []string{"publisher-connection-stream-limit", "quic-max-incoming-streams"} {
		c, err := Parse(append(append([]string{}, base...), "--"+flag+"=123"))
		if err != nil || c.RelayQUICConfig().Config.MaxIncomingStreams != 123 {
			t.Fatal("transport limit", flag, err)
		}
	}
	if _, err := Parse(append(base, "--publisher-connection-stream-limit=123", "--quic-max-incoming-streams=456")); err == nil {
		t.Fatal("accepted conflicting transport limits")
	}
	for _, value := range []string{"0", "-2"} {
		if _, err := Parse(append(append([]string{}, base...), "--publisher-connection-stream-limit="+value)); err == nil {
			t.Fatal("accepted an invalid stream limit", value)
		}
	}
}
