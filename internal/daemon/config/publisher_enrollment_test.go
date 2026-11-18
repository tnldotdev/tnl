package config

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/publisherenrollment"
)

func TestPublisherEnrollmentLimits(t *testing.T) {
	base := []string{"--role", "standalone", "--route53-server-zone-id", "ZSERVER",
		"--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "tnl.example.com", "--managed-domain", "tunnels.example.com",
		"--acme-email", "operator@example.com", "--acme-accept-terms",
		"--oidc-issuer", testOIDCIssuer, "--oidc-client-id", "server", "--storage-key", testStorageKey}
	cfg, err := Parse(base)
	if err != nil || cfg.PublisherEnrollmentLimits() != publisherenrollment.Default() ||
		(Config{}).PublisherEnrollmentLimits() != publisherenrollment.Default() {
		t.Fatal("parsed and embedded defaults disagree", err)
	}
	t.Setenv("TNLD_PUBLISHER_ENROLLMENT_MAX_MEMBERS", "100000")
	t.Setenv("TNLD_PUBLISHER_ENROLLMENT_MAX_LIFETIME", "2160h")
	t.Setenv("TNLD_PROJECT_MAX_PUBLISHERS", "500")
	cfg, err = Parse(base)
	if err != nil || cfg.PublisherEnrollmentLimits() != (publisherenrollment.Limits{Members: 100000, Lifetime: 2160 * time.Hour, ProjectPublishers: 500}) {
		t.Fatal("environment ceilings were not selected", err)
	}
	for _, args := range [][]string{
		{"--publisher-enrollment-max-members", "0"}, {"--publisher-enrollment-max-members", "2147483648"},
		{"--publisher-enrollment-max-lifetime", "59s"}, {"--publisher-enrollment-max-lifetime", "60.1s"},
		{"--publisher-enrollment-max-lifetime", "8761h"}, {"--project-max-publishers", "-1"},
		{"--project-max-publishers", "2147483648"},
	} {
		if _, err = Parse(append(base, args...)); err == nil {
			t.Fatal("invalid enrollment ceiling accepted", args[0])
		}
	}
	for _, role := range []string{"ingress", "relay"} {
		if _, err := Parse([]string{"--role", role, "--server-domain", "tnl.example.com", "--cluster-secret", testClusterSecret}); err == nil {
			t.Fatal("non-control role accepted configured enrollment ceilings", role)
		}
	}
}
