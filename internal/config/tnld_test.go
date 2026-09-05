package config

import (
	"testing"
	"time"
)

const testLoginToken = "tnl_login_AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"
const testClusterSecret = "0123456789abcdef0123456789abcdef"
const testStorageKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestParseTNLDStandaloneDerivesAddresses(t *testing.T) {
	config, err := ParseTNLD([]string{
		"--mode", "standalone",
		"--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "tnl.example.com",
		"--managed-deployment-domain", "tunnels.example.com",
		"--acme-email", "operator@example.com",
		"--acme-accept-terms",
		"--login-token", testLoginToken,
		"--storage-key", testStorageKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.ServerHostname() != "control.tnl.example.com" || config.IngressHostname() != "ingress.tnl.example.com" ||
		config.StandaloneRelayHostname() != "relay.tnl.example.com" || config.ManagedDomain() != "tunnels.example.com" {
		t.Fatalf("derived hostnames = %q, %q, %q, %q", config.ServerHostname(), config.IngressHostname(), config.StandaloneRelayHostname(), config.ManagedDomain())
	}
	if config.ControlListen != ":443" || config.PrivateControlListen != ":9443" ||
		config.IngressListen != ":443" || config.RelayTCPListen != ":443" || config.RelayUDPListen != ":443" {
		t.Fatalf("standalone listeners = %#v", config)
	}
}

func TestParseTNLDRequiresValidStorageKey(t *testing.T) {
	base := []string{
		"--mode", "standalone",
		"--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "tnl.example.com",
		"--managed-deployment-domain", "tunnels.example.com",
		"--acme-email", "operator@example.com",
		"--acme-accept-terms",
		"--login-token", testLoginToken,
	}
	if _, err := ParseTNLD(base); err == nil {
		t.Fatal("missing storage key was accepted")
	}
	if _, err := ParseTNLD(append(base,
		"--storage-key", testStorageKey,
		"--storage-key-previous", testStorageKey,
	)); err == nil {
		t.Fatal("repeated current and previous storage keys were accepted")
	}
}

func TestParseTNLDSplitRoles(t *testing.T) {
	control, err := ParseTNLD([]string{
		"--mode", "control", "--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "tnl.example.com", "--managed-deployment-domain", "tunnels.example.com",
		"--acme-email", "operator@example.com", "--acme-accept-terms", "--login-token", testLoginToken,
		"--cluster-secret", testClusterSecret, "--storage-key", testStorageKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if control.ControlListen != ":443" || control.PrivateControlListen != ":9443" {
		t.Fatalf("control listeners = %#v", control)
	}
	if control.RelayServiceHostname("relay-a") != "relay-a.tnl.example.com" ||
		control.RelayServiceHostname("Relay-A") != "" ||
		control.PrivateControlEndpoint() != "https://control.tnl.example.com:9443" {
		t.Fatalf("derived service endpoint = %q, %q", control.RelayServiceHostname("relay-a"), control.PrivateControlEndpoint())
	}

	ingress, err := ParseTNLD([]string{
		"--mode", "ingress", "--control-hostname", "control.tnl.example.com",
		"--cluster-secret", testClusterSecret, "--ingress-id", "ingress-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ingress.IngressListen != ":443" || ingress.DatabaseURL != "" {
		t.Fatalf("ingress configuration = %#v", ingress)
	}

	relay, err := ParseTNLD([]string{
		"--mode", "relay", "--control-hostname", "control.tnl.example.com",
		"--cluster-secret", testClusterSecret, "--relay-service-id", "relay-a", "--relay-id", "relay-1",
		"--relay-address", "relay-a.tnl.example.com:443",
		"--internal-relay-address", "relay-1.internal:9445",
	})
	if err != nil {
		t.Fatal(err)
	}
	if relay.RelayTCPListen != ":443" || relay.RelayUDPListen != ":443" || relay.InternalRelayListen != ":9445" {
		t.Fatalf("relay configuration = %#v", relay)
	}
}

func TestParseTNLDDNSAutomation(t *testing.T) {
	config, err := ParseTNLD([]string{
		"--mode", "control", "--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "tnl.example.com", "--managed-deployment-domain", "tunnels.example.com",
		"--acme-email", "operator@example.com", "--acme-accept-terms", "--login-token", testLoginToken,
		"--cluster-secret", testClusterSecret, "--storage-key", testStorageKey,
		"--route53-managed-zone-id", "Z0123456789ABC", "--ingress-ipv4-address", "192.0.2.10",
		"--ingress-ipv6-address", "2001:db8::10", "--route53-server-zone-id", "ZSERVER123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !config.DNSAutomationEnabled() || !config.DNSProviderEnabled() || !config.RelayCertificateAutomationEnabled() ||
		config.Route53Region != "us-east-1" || len(config.IngressIPv4Addresses) != 1 ||
		len(config.IngressIPv6Addresses) != 1 {
		t.Fatalf("DNS automation configuration = %#v", config)
	}
	for _, args := range [][]string{
		{"--route53-managed-zone-id", "/hostedzone/Z0123456789ABC", "--ingress-ipv4-address", "192.0.2.10"},
		{"--route53-managed-zone-id", "Z0123456789ABC"},
		{"--route53-managed-zone-id", "Z0123456789ABC", "--ingress-ipv4-address", "192.0.2.010"},
		{"--route53-managed-zone-id", "Z0123456789ABC", "--ingress-ipv6-address", "2001:0db8::10"},
	} {
		base := []string{
			"--mode", "control", "--database-url", "postgres://tnl:secret@database.example/tnl",
			"--server-domain", "tnl.example.com", "--managed-deployment-domain", "tunnels.example.com",
			"--acme-email", "operator@example.com", "--acme-accept-terms", "--login-token", testLoginToken,
			"--cluster-secret", testClusterSecret, "--storage-key", testStorageKey,
		}
		if _, err := ParseTNLD(append(base, args...)); err == nil {
			t.Fatalf("invalid DNS automation configuration %q was accepted", args)
		}
	}
}

func TestTNLDControlHostnameRejectsURLAndPort(t *testing.T) {
	base := TNLD{
		Mode: TNLDModeIngress, ControlHostname: "control.tnl.example.com",
		ClusterSecret: testClusterSecret, IngressID: "ingress-1",
		IngressListen: ":443", MetricsListen: "127.0.0.1:9090",
		PublicConnectionLimit: 1, RouteConnectionLimit: 1, PublisherConnectionLimit: 1,
		RelayStreamCapacity: 1, QUICMaxIncomingStreams: 1,
		IngressLeaseDuration: 30 * time.Second, RelayLeaseDuration: 30 * time.Second,
		LeaseRenewalInterval: 10 * time.Second, ControlRetryInterval: time.Second,
		RoutingTableWait: time.Second, DrainTimeout: time.Second,
		TunnelFallbackDelay: time.Second, QUICIdleTimeout: time.Second,
	}
	for _, value := range []string{"https://control.tnl.example.com", "control.tnl.example.com:443", "control.tnl.example.com/path", "Control.tnl.example.com"} {
		config := base
		config.ControlHostname = value
		if err := config.Validate(); err == nil {
			t.Fatalf("control hostname %q was accepted", value)
		}
	}
}

func TestTNLDRejectsGatewayConfiguration(t *testing.T) {
	for _, args := range [][]string{{"--mode", "gateway"}, {"--gateway-id", "gateway-1"}, {"--domain", "example.com"}} {
		if _, err := ParseTNLD(args); err == nil {
			t.Fatalf("retired configuration %q was accepted", args)
		}
	}
}

func TestEffectiveReservedRouteNames(t *testing.T) {
	config := TNLD{
		Mode: TNLDModeStandalone, ServerDomain: "example.com", ManagedDeploymentDomain: "example.com",
		ReservedRouteNames: []string{"custom"},
	}
	got := config.EffectiveReservedRouteNames()
	for _, want := range []string{"custom", "domains", "control", "ingress", "relay"} {
		if !contains(got, want) {
			t.Fatalf("reserved route names %v do not contain %q", got, want)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
