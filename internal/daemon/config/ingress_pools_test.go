package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

const testIngressPools = `{"pools":[
 {"id":"ingress-a","ipv4_address":"192.0.2.10","service_port_ranges":["20000-20015"]},
 {"id":"ingress-b","ipv6_address":"2001:db8::20","service_port_ranges":["20000-20255"],"draining":true}
]}`

func ingressPoolsFile(t *testing.T, content string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "ingress-pools.json")
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestIngressPoolsConfiguration(t *testing.T) {
	file := ingressPoolsFile(t, testIngressPools)
	c := validCertificateConfig(t, RoleControl)
	c.IngressPoolsFile = file
	c.Route53ManagedZoneID = "ZMANAGED"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	pools, err := c.IngressPools()
	if err != nil || len(pools) != 2 || len(pools[0].Ports.Ports()) != 16 || len(pools[1].Ports.Ports()) != 256 || !pools[1].Draining {
		t.Fatal(pools, err)
	}
	parsed, err := Parse([]string{
		"--role", "control", "--ingress-pools-file", file,
		"--database-url", c.DatabaseURL, "--server-domain", c.ServerDomain, "--managed-domain", c.ManagedDomain,
		"--acme-email", c.ACMEEmail, "--acme-accept-terms", "--oidc-issuer", c.OIDCIssuer, "--oidc-client-id", c.OIDCClientID,
		"--cluster-secret", c.ClusterSecret, "--storage-key", c.StorageKey,
		"--private-control-tls-certificate-file", c.ControlTLSCertificateFile, "--private-control-tls-private-key-file", c.ControlTLSPrivateKeyFile,
		"--route53-managed-zone-id", "ZMANAGED",
	})
	if err != nil || parsed.IngressPoolsFile != file {
		t.Fatal(err)
	}
	for _, role := range []Role{RoleStandalone, RoleIngress, RoleRelay} {
		other := c
		other.Role = role
		if err := other.Validate(); err == nil {
			t.Fatalf("%s accepted control pool inventory", role)
		}
	}
	c.IngressIPv4Addresses = []string{"192.0.2.10"}
	if err := c.Validate(); err == nil {
		t.Fatal("accepted competing address sources")
	}
}

func TestIngressPoolsRejectInvalidConfiguration(t *testing.T) {
	for name, content := range map[string]string{
		"empty":             `{"pools":[]}`,
		"missing-primary":   strings.ReplaceAll(testIngressPools, "ingress-a", "ingress-c"),
		"duplicate-id":      strings.ReplaceAll(testIngressPools, "ingress-b", "ingress-a"),
		"invalid-id":        strings.ReplaceAll(testIngressPools, "ingress-b", "../ingress-b"),
		"duplicate-address": strings.ReplaceAll(testIngressPools, `"ipv6_address":"2001:db8::20"`, `"ipv4_address":"192.0.2.10"`),
		"family":            strings.ReplaceAll(testIngressPools, "192.0.2.10", "2001:db8::10"),
		"missing-address":   strings.ReplaceAll(testIngressPools, `"ipv4_address":"192.0.2.10",`, ""),
		"zone":              strings.ReplaceAll(testIngressPools, "2001:db8::20", "fe80::1%en0"),
		"ports":             strings.ReplaceAll(testIngressPools, "20000-20255", "20000-20256"),
		"missing-ports":     strings.ReplaceAll(testIngressPools, `"20000-20015"`, ""),
		"unknown":           strings.Replace(testIngressPools, `"id":`, `"typo":true,"id":`, 1),
		"trailing":          testIngressPools + `{}`,
		"oversized":         strings.Repeat(" ", (1<<20)+1) + testIngressPools,
	} {
		t.Run(name, func(t *testing.T) {
			c := Config{Role: RoleControl, IngressPoolsFile: ingressPoolsFile(t, content)}
			if err := c.Validate(); err == nil {
				t.Fatal("accepted invalid pools")
			} else if problem, ok := failure.Of(err); !ok || problem.Reason() != failure.ServerConfigInvalid {
				t.Fatal("lost configuration classification", err)
			}
		})
	}
}
