package config

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestTrafficValidationRejectsUnsafeOperatorSettings(t *testing.T) {
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
	fallbackTraffic, fallbackPending, fallbackErr := ValidateIngressTraffic(ingress.TrafficConfig{}, ingress.PendingConfig{})
	if err != nil || fallbackErr != nil || traffic != fallbackTraffic || pending != fallbackPending ||
		traffic.SourceConnections != 4096 || traffic.SourceRate != 2000 || traffic.SourceBurst != 4000 || traffic.ProcessRate != 10000 || traffic.ProcessBurst != 20000 || traffic.ProcessUpload != 2<<30 || traffic.ProcessDownload != 2<<30 ||
		pending.Connections != 4096 || pending.ServiceConnections != 256 || pending.SourceConnections != 128 || pending.Timeout != 10*time.Second || pending.UploadBytes != 64<<10 || pending.DownloadBytes != 128<<10 || pending.ServiceRate != 1000 || pending.ServiceBurst != 2000 || pending.SourceRate != 2000 || pending.SourceBurst != 4000 {
		t.Fatalf("process defaults: %+v %+v %v", traffic, pending, err)
	}
	t.Setenv("TNLD_TRAFFIC_DEFAULT_RATE", "40")
	t.Setenv("TNLD_TRAFFIC_DEFAULT_RATE_PER", "2s")
	t.Setenv("TNLD_TRAFFIC_MAX_UPLOAD_BYTES", "536870912")
	t.Setenv("TNLD_TRAFFIC_PROCESS_UPLOAD_BYTES", "134217728")
	t.Setenv("TNLD_PENDING_SERVICE_RATE", "7")
	c = validCertificateConfig(t, RoleStandalone)
	if c.TrafficDefaults().Rate != 40 || c.TrafficDefaults().RatePer != 2*time.Second || c.TrafficCeiling().UploadBytes != 512<<20 || c.IngressTraffic().ProcessUpload != 128<<20 || c.IngressPending().ServiceRate != 7 {
		t.Fatalf("environment mapping: %+v", c)
	}
}

func TestOperatorTrafficValidation(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"default connections": func(c *Config) { c.TrafficDefaultConnections = c.TrafficMaxConnections + 1 },
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
			c := validCertificateConfig(t, RoleStandalone)
			change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("accepted unsafe traffic settings")
			}
		})
	}
}
