package config

import (
	"strings"
	"testing"
	"time"
)

const testLoginToken = "tnl_login_AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"

func TestParseTNLDStandaloneDerivesAddresses(t *testing.T) {
	config, err := ParseTNLD([]string{
		"--mode", "standalone",
		"--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "tnl.example.com",
		"--managed-deployment-domain", "tunnels.example.com",
		"--acme-email", "operator@example.com",
		"--acme-accept-terms",
		"--login-token", testLoginToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.ServerHostname() != "control.tnl.example.com" || config.IngressHostname() != "ingress.tnl.example.com" ||
		config.StandaloneRelayHostname() != "relay.tnl.example.com" || config.ManagedDomain() != "tunnels.example.com" {
		t.Fatalf("derived hostnames = %q, %q, %q, %q", config.ServerHostname(), config.IngressHostname(), config.StandaloneRelayHostname(), config.ManagedDomain())
	}
	if config.ControlListen != ":443" || config.IngressControlListen != ":9443" || config.RelayControlListen != ":9444" ||
		config.IngressListen != ":443" || config.RelayTCPListen != ":443" || config.RelayUDPListen != ":443" {
		t.Fatalf("standalone listeners = %#v", config)
	}
}

func TestParseTNLDSplitRoles(t *testing.T) {
	control, err := ParseTNLD([]string{
		"--mode", "control", "--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "tnl.example.com", "--managed-deployment-domain", "tunnels.example.com",
		"--acme-email", "operator@example.com", "--acme-accept-terms", "--login-token", testLoginToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if control.ControlListen != ":443" || control.IngressControlListen != ":9443" || control.RelayControlListen != ":9444" {
		t.Fatalf("control listeners = %#v", control)
	}
	if control.RelayServiceHostname("relay-a") != "relay-a.tnl.example.com" ||
		control.RelayServiceHostname("Relay-A") != "" ||
		control.IngressControlEndpoint() != "https://control.tnl.example.com:9443" ||
		control.RelayControlEndpoint() != "https://control.tnl.example.com:9444" {
		t.Fatalf("derived service endpoints = %q, %q, %q", control.RelayServiceHostname("relay-a"), control.IngressControlEndpoint(), control.RelayControlEndpoint())
	}

	ingress, err := ParseTNLD([]string{
		"--mode", "ingress", "--control-hostname", "control.tnl.example.com",
		"--service-enrollment-token", strings.Repeat("tnl_enrollment_a", 3), "--ingress-id", "ingress-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ingress.IngressListen != ":443" || ingress.DatabaseURL != "" {
		t.Fatalf("ingress configuration = %#v", ingress)
	}

	relay, err := ParseTNLD([]string{
		"--mode", "relay", "--control-hostname", "control.tnl.example.com",
		"--service-enrollment-token", strings.Repeat("tnl_enrollment_a", 3), "--relay-id", "relay-1",
		"--internal-relay-address", "relay-1.internal:9445",
	})
	if err != nil {
		t.Fatal(err)
	}
	if relay.RelayTCPListen != ":443" || relay.RelayUDPListen != ":443" || relay.InternalRelayListen != ":9445" {
		t.Fatalf("relay configuration = %#v", relay)
	}
}

func TestTNLDControlHostnameRejectsURLAndPort(t *testing.T) {
	base := TNLD{
		Mode: TNLDModeIngress, ControlHostname: "control.tnl.example.com",
		ServiceEnrollmentToken: strings.Repeat("tnl_enrollment_a", 3), IngressID: "ingress-1",
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
