package config

import (
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/controloutage"
)

func controlOutageArguments() []string {
	return []string{
		"--role", "standalone", "--route53-server-zone-id", "ZSERVER",
		"--database-url", "postgres://tnl:secret@database.example/tnl",
		"--server-domain", "tnl.example.com", "--managed-domain", "tunnels.example.com",
		"--control-proxy-provider", "single-xff",
		"--acme-email", "operator@example.com", "--acme-accept-terms",
		"--oidc-issuer", testOIDCIssuer, "--oidc-client-id", "server", "--storage-key", testStorageKey,
	}
}

func TestControlOutageToleranceDefaultEnvironmentAndFlag(t *testing.T) {
	args := controlOutageArguments()
	got, err := Parse(args)
	if err != nil || got.ControlOutageTolerance != controloutage.DefaultTolerance {
		t.Fatalf("default tolerance = %v, %v", got.ControlOutageTolerance, err)
	}
	t.Setenv("TNLD_CONTROL_OUTAGE_TOLERANCE", "90s")
	got, err = Parse(args)
	if err != nil || got.ControlOutageTolerance != 90*time.Second {
		t.Fatalf("environment tolerance = %v, %v", got.ControlOutageTolerance, err)
	}
	got, err = Parse(append(args, "--control-outage-tolerance", "7m"))
	if err != nil || got.ControlOutageTolerance != 7*time.Minute {
		t.Fatalf("flag tolerance = %v, %v", got.ControlOutageTolerance, err)
	}
}

func TestServiceRunLeaseSettings(t *testing.T) {
	args := controlOutageArguments()
	want := func(args []string, lease time.Duration) {
		t.Helper()
		cfg, err := Parse(args)
		if err != nil || cfg.ServiceRunLeaseDuration != lease || cfg.ControlOutageTolerance != controloutage.DefaultTolerance {
			t.Fatalf("run lease %v, serving allowance %v, error %v", cfg.ServiceRunLeaseDuration, cfg.ControlOutageTolerance, err)
		}
	}
	want(args, 90*time.Second)
	t.Setenv("TNLD_SERVICE_RUN_LEASE_DURATION", "60s")
	want(args, time.Minute)
	want(append(args, "--service-run-lease-duration", "30s"), 30*time.Second)
	for _, invalid := range []string{"0s", "-1s", "999ms", "none"} {
		if _, err := Parse(append(args, "--service-run-lease-duration", invalid)); err == nil {
			t.Errorf("accepted lease %s", invalid)
		}
	}
	for _, role := range []Role{RoleRelay, RoleIngress} {
		if _, err := ResolveExplicit(Config{Role: role}, nil); err == nil || !strings.Contains(err.Error(), "service_run_lease_duration") {
			t.Fatalf("explicit environment on %s: %v", role, err)
		}
	}
}

func TestControlOutageToleranceRejectsInvalidDurations(t *testing.T) {
	for _, value := range []string{"0", "0s", "-1s", "not-a-duration", "999999999999999999999h"} {
		t.Run(value, func(t *testing.T) {
			if _, err := Parse(append(controlOutageArguments(), "--control-outage-tolerance", value)); err == nil {
				t.Fatal("invalid tolerance accepted")
			}
		})
	}
}

func TestControlOutageToleranceControlAndStandaloneUseSameDurationRules(t *testing.T) {
	for _, role := range []string{"control", "standalone"} {
		t.Run(role, func(t *testing.T) {
			args := append(controlOutageArguments(), "--role", role)
			if role == "control" {
				args = append(args, "--cluster-secret", testClusterSecret,
					"--private-control-tls-certificate-file", "control.pem", "--private-control-tls-private-key-file", "control.key")
			}
			for _, value := range []string{"1ns", "250ms", "1m", "24h", "2562047h47m16.854775807s"} {
				want, err := time.ParseDuration(value)
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := Parse(append(args, "--control-outage-tolerance", value))
				if err != nil || cfg.ControlOutageTolerance != want {
					t.Fatalf("positive duration %s: %v, %v", value, cfg.ControlOutageTolerance, err)
				}
			}
		})
	}
}

func TestControlOutageToleranceCannotBeSelectedByServingRoles(t *testing.T) {
	cfg, err := Parse(controlOutageArguments())
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []Role{RoleIngress, RoleRelay} {
		t.Run(string(role), func(t *testing.T) {
			cfg.Role, cfg.ControlOutageTolerance = role, time.Minute
			err := cfg.Validate()
			if typed, ok := failure.Of(err); !ok || typed.Setting() != failure.SettingControlOutageTolerance {
				t.Fatalf("serving role selected tolerance: %v", err)
			}
		})
	}
}
