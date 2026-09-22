package tnldconfig

import (
	"strconv"
	"testing"

	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/sourcelimiter"
)

func TestSourceConnectionLimits(t *testing.T) {
	for _, role := range []Role{RoleStandalone, RoleIngress} {
		t.Run(string(role)+"/defaults", func(t *testing.T) {
			cfg := validCertificateConfig(t, role)
			if cfg.SourceConnectionRate != sourcelimiter.DefaultRate || cfg.SourceConnectionBurst != sourcelimiter.DefaultBurst {
				t.Fatalf("source limits = %g/%d", cfg.SourceConnectionRate, cfg.SourceConnectionBurst)
			}
		})
	}
	base := []string{"--role", "ingress", "--control-hostname", "control.example.test",
		"--cluster-secret", testClusterSecret, "--ingress-id", "ingress-1"}
	for _, test := range []struct {
		name, rate, burst string
	}{
		{"zero_rate", "0", "1"}, {"negative_rate", "-1", "1"},
		{"nan_rate", "NaN", "1"}, {"infinite_rate", "+Inf", "1"},
		{"negative_infinite_rate", "-Inf", "1"}, {"overflow_rate", "1e400", "1"},
		{"zero_burst", "50", "0"}, {"negative_burst", "50", "-1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append(append([]string{}, base...), "--source-connection-rate="+test.rate, "--source-connection-burst="+test.burst)
			if _, err := Parse(args); err == nil {
				t.Fatal("invalid source limits accepted")
			}
		})
	}
	t.Run("environment_and_flag_precedence", func(t *testing.T) {
		t.Setenv("TNLD_SOURCE_CONNECTION_RATE", "75.5")
		t.Setenv("TNLD_SOURCE_CONNECTION_BURST", "300")
		cfg, err := Parse(base)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SourceConnectionRate != 75.5 || cfg.SourceConnectionBurst != 300 {
			t.Fatalf("environment source limits = %g/%d", cfg.SourceConnectionRate, cfg.SourceConnectionBurst)
		}
		cfg, err = Parse(append(base, "--source-connection-rate=400.5", "--source-connection-burst=250"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SourceConnectionRate != 400.5 || cfg.SourceConnectionBurst != 250 {
			t.Fatalf("flag source limits = %g/%d", cfg.SourceConnectionRate, cfg.SourceConnectionBurst)
		}
	})
}

func TestIndependentAdmissionLimits(t *testing.T) {
	base := []string{"--role", "ingress", "--control-hostname", "control.example.test",
		"--cluster-secret", testClusterSecret, "--ingress-id", "ingress-1"}
	for _, test := range []struct {
		flag     string
		value    func(Config) int
		fallback int
	}{
		{"client-hello-connection-limit", func(c Config) int { return c.ClientHelloConnectionLimit }, ingress.DefaultClientHelloConnectionLimit},
		{"challenge-connection-limit", func(c Config) int { return c.ChallengeConnectionLimit }, ingress.DefaultChallengeConnectionLimit},
		{"challenge-hostname-connection-limit", func(c Config) int { return c.ChallengeHostnameConnectionLimit }, ingress.DefaultChallengeHostnameConnectionLimit},
		{"standalone-control-connection-limit", func(c Config) int { return c.StandaloneControlConnectionLimit }, ingress.DefaultControlConnectionLimit},
		{"standalone-relay-connection-limit", func(c Config) int { return c.StandaloneRelayConnectionLimit }, ingress.DefaultRelayConnectionLimit},
	} {
		t.Run(test.flag, func(t *testing.T) {
			cfg, err := Parse(base)
			if err != nil || test.value(cfg) != test.fallback {
				t.Fatalf("default=%d error=%v", test.value(cfg), err)
			}
			for _, value := range []int{-1, 0, 7} {
				cfg, err := Parse(append(append([]string{}, base...), "--"+test.flag+"="+strconv.Itoa(value)))
				if value <= 0 && err == nil || value > 0 && (err != nil || test.value(cfg) != value) {
					t.Fatalf("input=%d parsed=%d error=%v", value, test.value(cfg), err)
				}
			}
		})
	}
}
