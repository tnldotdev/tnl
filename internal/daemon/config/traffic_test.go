package tnldconfig

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestTrafficValidationRejectsUnsafeOperatorSettings(t *testing.T) {
	defaults, ceiling := trafficlimits.Default(), trafficlimits.Ceiling()
	if err := ValidateTraffic(defaults, ceiling); err != nil {
		t.Fatal(err)
	}
	defaults.RatePer = time.Millisecond
	if err := ValidateTraffic(defaults, ceiling); err == nil {
		t.Fatal("equivalent rate exceeded ceiling")
	}
	for _, p := range []ingress.PendingConfig{{Timeout: -time.Second}, {UploadBytes: -1}, {DownloadBytes: 2 << 20}, {Connections: 1, SourceConnections: 2}, {SourceRate: -1}} {
		if _, _, err := ValidateIngressTraffic(ingress.TrafficConfig{}, p); err == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
	if _, _, err := ValidateIngressTraffic(ingress.TrafficConfig{ProcessUpload: -1}, ingress.PendingConfig{}); err == nil {
		t.Fatal("negative process bandwidth")
	}
	traffic, pending, err := ValidateIngressTraffic(ingress.TrafficConfig{}, ingress.PendingConfig{})
	if err != nil || !traffic.Default.Within(traffic.Ceiling) || pending.Connections <= 0 {
		t.Fatalf("default validation: %+v %+v %v", traffic, pending, err)
	}
}

func TestOperatorTrafficDefaultsAndEnvironment(t *testing.T) {
	c := validCertificateConfig(t, RoleControl)
	if c.TrafficDefaults() != trafficlimits.Default() || c.TrafficCeiling() != trafficlimits.Ceiling() {
		t.Fatalf("operator defaults: %+v %+v", c.TrafficDefaults(), c.TrafficCeiling())
	}
	traffic, pending, err := ValidateIngressTraffic(c.IngressTraffic(), c.IngressPending())
	if err != nil || traffic.SourceConnections != 64 || traffic.SourceRate != 30 || traffic.SourceBurst != 60 || traffic.ProcessRate != 200 || traffic.ProcessBurst != 400 || traffic.ProcessUpload != 256<<20 || traffic.ProcessDownload != 256<<20 ||
		pending.Connections != 64 || pending.PublicURLConnections != 8 || pending.SourceConnections != 4 || pending.Timeout != 10*time.Second || pending.UploadBytes != 64<<10 || pending.DownloadBytes != 128<<10 || pending.PublicURLRate != 5 || pending.PublicURLBurst != 10 || pending.SourceRate != 3 || pending.SourceBurst != 6 {
		t.Fatalf("process defaults: %+v %+v %v", traffic, pending, err)
	}
	t.Setenv("TNLD_TRAFFIC_DEFAULT_RATE", "40")
	t.Setenv("TNLD_TRAFFIC_DEFAULT_RATE_PER", "2s")
	t.Setenv("TNLD_TRAFFIC_MAX_UPLOAD_BYTES", "33554432")
	t.Setenv("TNLD_TRAFFIC_PROCESS_UPLOAD_BYTES", "134217728")
	t.Setenv("TNLD_PENDING_URL_RATE", "7")
	c = validCertificateConfig(t, RoleControl)
	if c.TrafficDefaults().Rate != 40 || c.TrafficDefaults().RatePer != 2*time.Second || c.TrafficCeiling().UploadBytes != 32<<20 || c.IngressTraffic().ProcessUpload != 128<<20 || c.IngressPending().PublicURLRate != 7 {
		t.Fatalf("environment mapping: %+v", c)
	}
}

func TestOperatorTrafficValidation(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"default connections": func(c *Config) { c.TrafficDefaultConnections = 129 },
		"default period":      func(c *Config) { c.TrafficDefaultRatePer = time.Millisecond },
		"maximum period":      func(c *Config) { c.TrafficMaxRatePer = 25 * time.Hour },
		"default upload":      func(c *Config) { c.TrafficDefaultUploadBytes = 1 },
		"bounded total":       func(c *Config) { c.TrafficMaxTotalConnections = 1 },
		"source":              func(c *Config) { c.TrafficSourceConnections = -1 },
		"process":             func(c *Config) { c.TrafficProcessDownloadBytes = -1 },
		"pending connections": func(c *Config) { c.PendingConnectionLimit = 2 },
		"pending timeout":     func(c *Config) { c.PendingTimeout = 2 * time.Minute },
		"pending bytes":       func(c *Config) { c.PendingUploadBytes = 2 << 20 },
		"pending rate":        func(c *Config) { c.PendingSourceRate = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := validCertificateConfig(t, RoleControl)
			change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("accepted unsafe traffic settings")
			}
		})
	}
}
