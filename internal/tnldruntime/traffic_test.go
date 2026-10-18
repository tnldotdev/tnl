package tnldruntime

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

func TestTrafficAndVisitorIssuerRuntimePlumbing(t *testing.T) {
	c := tnldconfig.Config{VisitorIssuerSeed: "issuer-seed", TrafficDefaultConnections: 48,
		TrafficDefaultRate: 30, TrafficDefaultRatePer: 2 * time.Second, TrafficDefaultBurst: 50,
		TrafficDefaultUploadBytes: 4 << 20, TrafficDefaultDownloadBytes: 8 << 20,
		TrafficSourceConnections: 12, TrafficProcessRate: 123, PendingConnectionLimit: 50, PendingURLConnectionLimit: 7,
		PendingTimeout: 8 * time.Second, PendingUploadBytes: 32 << 10}
	s := ingressSettingsFrom(c)
	if s.traffic.Default != c.TrafficDefaults() || s.traffic.Ceiling != c.TrafficCeiling() || s.traffic.SourceConnections != 12 || s.traffic.ProcessRate != 123 || s.pending.Connections != 50 || s.pending.PublicURLConnections != 7 || s.pending.Timeout != 8*time.Second || s.pending.UploadBytes != 32<<10 {
		t.Fatal("ingress settings lost configured traffic budgets")
	}
	api := controlAPIConfigFrom(c, nil, c.VisitorIssuerSeed)
	if api.TrafficDefaults != c.TrafficDefaults() || api.TrafficCeiling != c.TrafficCeiling() || api.VisitorIssuerSeed != c.VisitorIssuerSeed {
		t.Fatal("control settings lost traffic limits or issuer seed")
	}
	c.ServerDomain = "infra.example.test"
	c.Role = tnldconfig.RoleControl
	api = controlAPIConfigFrom(c, nil, c.VisitorIssuerSeed)
	authority := authorityAPIConfigFrom(c, nil, nil)
	if api.ControlURL != "https://control.infra.example.test" || authority.ControlURL != api.ControlURL {
		t.Fatal("publisher assertion audiences differ")
	}
}
