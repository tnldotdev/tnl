package tnldconfig

import (
	"testing"
	"time"
)

const testLoginToken = "tnl_login_AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"
const testClusterSecret = "0123456789abcdef0123456789abcdef"
const testStorageKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestParseStandaloneDerivesAddresses(t *testing.T) {
	config, err := Parse([]string{
		"--role", "standalone",
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
	if config.PublicURLCertificateWorkers != 8 {
		t.Fatalf("public URL certificate workers = %d, want 8", config.PublicURLCertificateWorkers)
	}
	if config.PublisherConnectionLimit < 1 {
		t.Fatalf("publisher connection limit = %d", config.PublisherConnectionLimit)
	}
}

func TestParsePublicURLCertificateWorkers(t *testing.T) {
	base := []string{
		"--role", "standalone",
		"--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "tnl.example.com",
		"--managed-deployment-domain", "tunnels.example.com",
		"--acme-email", "operator@example.com",
		"--acme-accept-terms",
		"--login-token", testLoginToken,
		"--storage-key", testStorageKey,
	}
	for _, value := range []string{"0", "9"} {
		if _, err := Parse(append(base, "--public-url-certificate-workers", value)); err == nil {
			t.Fatalf("public URL certificate worker count %s was accepted", value)
		}
	}
}

func TestParseRequiresValidStorageKey(t *testing.T) {
	base := []string{
		"--role", "standalone",
		"--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "tnl.example.com",
		"--managed-deployment-domain", "tunnels.example.com",
		"--acme-email", "operator@example.com",
		"--acme-accept-terms",
		"--login-token", testLoginToken,
	}
	if _, err := Parse(base); err == nil {
		t.Fatal("missing storage key was accepted")
	}
	if _, err := Parse(append(base,
		"--storage-key", testStorageKey,
		"--storage-key-previous", testStorageKey,
	)); err == nil {
		t.Fatal("repeated current and previous storage keys were accepted")
	}
}

func TestParseSplitRoles(t *testing.T) {
	control, err := Parse([]string{
		"--role", "control", "--database-url", "postgres://tnl:secret@database.example/tnl",
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

	ingress, err := Parse([]string{
		"--role", "ingress", "--control-hostname", "control.tnl.example.com",
		"--private-control-address", "control.internal:9443",
		"--cluster-secret", testClusterSecret, "--ingress-id", "ingress-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ingress.IngressListen != ":443" || ingress.DatabaseURL != "" || ingress.PrivateControlAddress != "control.internal:9443" {
		t.Fatalf("ingress configuration = %#v", ingress)
	}

	relay, err := Parse([]string{
		"--role", "relay", "--control-hostname", "control.tnl.example.com",
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

func TestConfigPrivateControlAddressRequiresSplitDialAddress(t *testing.T) {
	for _, value := range []string{"control.internal", ":9443", "control.internal:0", "Control.internal:9443"} {
		if _, err := Parse([]string{
			"--role", "ingress", "--control-hostname", "control.tnl.example.com",
			"--private-control-address", value,
			"--cluster-secret", testClusterSecret, "--ingress-id", "ingress-1",
		}); err == nil {
			t.Fatalf("private control address %q was accepted", value)
		}
	}
	if _, err := Parse([]string{
		"--role", "control", "--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "tnl.example.com", "--managed-deployment-domain", "tunnels.example.com",
		"--acme-email", "operator@example.com", "--acme-accept-terms", "--login-token", testLoginToken,
		"--cluster-secret", testClusterSecret, "--storage-key", testStorageKey,
		"--private-control-address", "control.internal:9443",
	}); err == nil {
		t.Fatal("private control address was accepted by control")
	}
}

func TestParseDNSAutomation(t *testing.T) {
	config, err := Parse([]string{
		"--role", "control", "--database-url", "postgres://tnl:secret@database.example/tnl",
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
			"--role", "control", "--database-url", "postgres://tnl:secret@database.example/tnl",
			"--server-domain", "tnl.example.com", "--managed-deployment-domain", "tunnels.example.com",
			"--acme-email", "operator@example.com", "--acme-accept-terms", "--login-token", testLoginToken,
			"--cluster-secret", testClusterSecret, "--storage-key", testStorageKey,
		}
		if _, err := Parse(append(base, args...)); err == nil {
			t.Fatalf("invalid DNS automation configuration %q was accepted", args)
		}
	}
}

func TestConfigControlHostnameRejectsURLAndPort(t *testing.T) {
	base := Config{
		Role: RoleIngress, ControlHostname: "control.tnl.example.com",
		ClusterSecret: testClusterSecret, IngressID: "ingress-1",
		IngressListen: ":443", MetricsListen: "127.0.0.1:9090",
		VisitorConnectionLimit: 1, PublisherConnectionLimit: 1,
		ClientHelloConnectionLimit: 1024, ChallengeConnectionLimit: 1024, ChallengeHostnameConnectionLimit: 8,
		StandaloneControlConnectionLimit: 1024, StandaloneRelayConnectionLimit: 4096,
		RelayStreamCapacity: 1, QUICMaxIncomingStreams: 1,
		IngressLeaseDuration: 30 * time.Second, RelayLeaseDuration: 30 * time.Second,
		LeaseRenewalInterval: 10 * time.Second, ControlRetryInterval: time.Second,
		RoutingTableWait: time.Second, DrainTimeout: time.Second,
		QUICIdleTimeout: time.Second,
	}
	for _, value := range []string{"https://control.tnl.example.com", "control.tnl.example.com:443", "control.tnl.example.com/path", "Control.tnl.example.com"} {
		config := base
		config.ControlHostname = value
		if err := config.Validate(); err == nil {
			t.Fatalf("control hostname %q was accepted", value)
		}
	}
}

func TestConfigRejectsGatewayConfiguration(t *testing.T) {
	for _, args := range [][]string{{"--role", "gateway"}, {"--gateway-id", "gateway-1"}, {"--domain", "example.com"}} {
		if _, err := Parse(args); err == nil {
			t.Fatalf("retired configuration %q was accepted", args)
		}
	}
}

func TestConfigRouteAndRelayDNSMatrix(t *testing.T) {
	for _, test := range []struct {
		name, managedZone, serverZone string
		ipv4, ipv6                    []string
		routes, relay, provider       bool
	}{
		{"no_zones", "", "", nil, nil, false, false, false},
		{"managed_ipv4", "ZMANAGED", "", []string{"192.0.2.10"}, nil, true, false, true},
		{"managed_ipv6", "ZMANAGED", "", nil, []string{"2001:db8::10"}, true, false, true},
		{"server_only", "", "ZSERVER", nil, nil, false, true, true},
		{"both_dual_stack", "ZMANAGED", "ZSERVER", []string{"192.0.2.10"}, []string{"2001:db8::10"}, true, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validCertificateConfig(t, RoleControl)
			cfg.Route53ManagedZoneID, cfg.Route53ServerZoneID = test.managedZone, test.serverZone
			cfg.IngressIPv4Addresses, cfg.IngressIPv6Addresses = test.ipv4, test.ipv6
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			if cfg.DNSAutomationEnabled() != test.routes || cfg.RelayCertificateAutomationEnabled() != test.relay || cfg.DNSProviderEnabled() != test.provider {
				t.Fatalf("route/relay/provider DNS = %v/%v/%v; want %v/%v/%v", cfg.DNSAutomationEnabled(), cfg.RelayCertificateAutomationEnabled(), cfg.DNSProviderEnabled(), test.routes, test.relay, test.provider)
			}
			if cfg.ServerHostname() != "control.infra.example.test" || cfg.IngressHostname() != "ingress.infra.example.test" ||
				cfg.RelayServiceHostname("relay-a") != "relay-a.infra.example.test" || cfg.ManagedDomain() != "routes.other.test" {
				t.Fatal("server and managed deployment domains were conflated")
			}
		})
	}
}

func TestConfigStaticCertificateRoleMatrix(t *testing.T) {
	for _, test := range []struct {
		name                      string
		role                      Role
		control, relay, serverDNS bool
		wantError                 bool
	}{
		{"standalone_automatic", RoleStandalone, false, false, false, false},
		{"standalone_static_control_only", RoleStandalone, true, false, false, true},
		{"standalone_static_both", RoleStandalone, true, true, false, false},
		{"standalone_static_control_server_dns", RoleStandalone, true, false, true, false},
		{"standalone_static_relay", RoleStandalone, false, true, false, false},
		{"split_control_static", RoleControl, true, false, false, false},
		{"split_control_relay_override_rejected", RoleControl, false, true, false, true},
		{"split_relay_static", RoleRelay, false, true, false, false},
		{"split_relay_automatic", RoleRelay, false, false, false, false},
		{"split_relay_control_override_rejected", RoleRelay, true, false, false, true},
		{"ingress_no_certificates", RoleIngress, false, false, false, false},
		{"ingress_control_override_rejected", RoleIngress, true, false, false, true},
		{"ingress_relay_override_rejected", RoleIngress, false, true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validCertificateConfig(t, test.role)
			if test.control {
				cfg.ControlTLSCertificateFile, cfg.ControlTLSPrivateKeyFile = "control.pem", "control.key"
			}
			if test.relay {
				cfg.RelayTLSCertificateFile, cfg.RelayTLSPrivateKeyFile = "relay.pem", "relay.key"
			}
			if test.serverDNS {
				cfg.Route53ServerZoneID = "ZSERVER"
			}
			if err := cfg.Validate(); (err != nil) != test.wantError {
				t.Fatalf("Validate() = %v; want error %v", err, test.wantError)
			}
		})
	}
	for _, field := range []string{"control_certificate", "control_key", "relay_certificate", "relay_key"} {
		t.Run("unpaired_"+field, func(t *testing.T) {
			cfg := validCertificateConfig(t, RoleStandalone)
			switch field {
			case "control_certificate":
				cfg.ControlTLSCertificateFile = "control.pem"
			case "control_key":
				cfg.ControlTLSPrivateKeyFile = "control.key"
			case "relay_certificate":
				cfg.RelayTLSCertificateFile = "relay.pem"
			case "relay_key":
				cfg.RelayTLSPrivateKeyFile = "relay.key"
			}
			if err := cfg.Validate(); err == nil {
				t.Fatal("unpaired static TLS override was accepted")
			}
		})
	}
}

func TestConfigStatelessRoleSecretIsolation(t *testing.T) {
	for _, role := range []Role{RoleIngress, RoleRelay} {
		for name, mutate := range map[string]func(*Config){
			"database":         func(c *Config) { c.DatabaseURL = "postgres://postgres:secret@localhost/tnl" },
			"storage":          func(c *Config) { c.StorageKey = testStorageKey },
			"previous_storage": func(c *Config) { c.StorageKeyPrevious = testStorageKey },
			"hosted":           func(c *Config) { c.HostedSecret = testClusterSecret },
			"previous_hosted":  func(c *Config) { c.HostedSecretPrevious = testClusterSecret },
			"login_token":      func(c *Config) { c.LoginToken = testLoginToken },
			"managed_zone":     func(c *Config) { c.Route53ManagedZoneID = "ZMANAGED" },
			"server_zone":      func(c *Config) { c.Route53ServerZoneID = "ZSERVER" },
			"ingress_ipv4":     func(c *Config) { c.IngressIPv4Addresses = []string{"192.0.2.10"} },
			"ingress_ipv6":     func(c *Config) { c.IngressIPv6Addresses = []string{"2001:db8::10"} },
		} {
			t.Run(string(role)+"/"+name, func(t *testing.T) {
				cfg := validCertificateConfig(t, role)
				mutate(&cfg)
				if err := cfg.Validate(); err == nil {
					t.Fatal("control-only configuration was accepted by a stateless role")
				}
			})
		}
	}
}

func TestConfigDNSIngressAddressValidation(t *testing.T) {
	for _, test := range []struct {
		name, managedZone, serverZone string
		ipv4, ipv6                    []string
	}{
		{"missing", "ZMANAGED", "", nil, nil},
		{"duplicate_ipv4", "ZMANAGED", "", []string{"192.0.2.10", "192.0.2.10"}, nil},
		{"duplicate_ipv6", "ZMANAGED", "", nil, []string{"2001:db8::10", "2001:db8::10"}},
		{"ipv6_in_ipv4", "ZMANAGED", "", []string{"2001:db8::10"}, nil},
		{"ipv4_in_ipv6", "ZMANAGED", "", nil, []string{"192.0.2.10"}},
		{"no_zones_ipv4", "", "", []string{"192.0.2.10"}, nil},
		{"no_zones_ipv6", "", "", nil, []string{"2001:db8::10"}},
		{"server_only_ipv4", "", "ZSERVER", []string{"192.0.2.10"}, nil},
		{"server_only_ipv6", "", "ZSERVER", nil, []string{"2001:db8::10"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := validCertificateConfig(t, RoleControl)
			cfg.Route53ManagedZoneID, cfg.Route53ServerZoneID = test.managedZone, test.serverZone
			cfg.IngressIPv4Addresses, cfg.IngressIPv6Addresses = test.ipv4, test.ipv6
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid ingress IP configuration was accepted")
			}
		})
	}
}

func validCertificateConfig(t *testing.T, role Role) Config {
	t.Helper()
	args := []string{"--role", string(role)}
	if role.RunsControl() {
		args = append(args, "--database-url", "postgres://tnl:secret@database.example/tnl",
			"--server-domain", "infra.example.test", "--managed-deployment-domain", "routes.other.test",
			"--acme-email", "operator@example.test", "--acme-accept-terms", "--login-token", testLoginToken, "--storage-key", testStorageKey)
	} else {
		args = append(args, "--control-hostname", "control.infra.example.test")
	}
	if role != RoleStandalone {
		args = append(args, "--cluster-secret", testClusterSecret)
	}
	if role == RoleIngress {
		args = append(args, "--ingress-id", "ingress-1")
	}
	if role == RoleRelay {
		args = append(args, "--relay-service-id", "relay-a", "--relay-id", "relay-1", "--relay-address", "relay-a.infra.example.test:443", "--internal-relay-address", "relay-1.internal:9445")
	}
	cfg, err := Parse(args)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
