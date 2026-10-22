package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

func loadTNLDYAML(t *testing.T, contents string) (Document, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tnl.yml")
	if err := os.WriteFile(path, []byte("version: 1\ntnld:\n"+contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadDocument(path)
}

func TestTNLDYAMLRejectsWrongScalarAndCollectionTypes(t *testing.T) {
	for _, contents := range []string{
		"  role: 1\n", "  metrics_listen: false\n", "  metrics_listen: 2026-10-21\n",
		"  custom_domains_enabled: \"false\"\n", "  custom_domains_enabled: 0\n", "  custom_domains_enabled: yes\n",
		"  relay_stream_capacity: \"0\"\n", "  relay_stream_capacity: 1.5\n", "  relay_stream_capacity: false\n",
		"  quic_idle_timeout: 0\n", "  quic_idle_timeout: false\n", "  quic_idle_timeout: [1s]\n", "  quic_idle_timeout: bad\n",
		"  service_port_ranges: 20000-20015\n", "  service_port_ranges: [20000]\n", "  service_port_ranges: [false]\n", "  service_port_ranges: {}\n",
		"  initial_team_owner: []\n", "  initial_team_owner: {team: 1}\n", "  initial_team_owner: {1: subject}\n",
		"  initial_administrator: [null]\n", "  metrics_listen: null\n", "  unknown: value\n", "  metrics_listen: one\n  metrics_listen: two\n",
	} {
		t.Run(contents, func(t *testing.T) {
			if _, err := loadTNLDYAML(t, contents); err == nil {
				t.Fatal("invalid YAML type accepted")
			}
		})
	}
}

func TestTNLDYAMLPresenceDefaultsAndPrecedence(t *testing.T) {
	document, err := loadTNLDYAML(t, "  metrics_listen: \"\"\n  custom_domains_enabled: false\n  relay_stream_capacity: 0\n  initial_administrator: []\n  initial_team_owner: {}\n  service_port_ranges: []\n  quic_idle_timeout: \"-1.5s\"\n")
	if err != nil {
		t.Fatal(err)
	}
	value := tnldconfig.Config{MetricsListen: "default", CustomDomainsEnabled: true, RelayStreamCapacity: 99, InitialAdministrators: []string{"subject"}, InitialTeamOwners: map[string]string{"team": "subject"}, ServicePortRanges: []string{"20000-20015"}, DrainTimeout: time.Minute}
	document.TNLD.Apply(&value)
	if value.MetricsListen != "" || value.CustomDomainsEnabled || value.RelayStreamCapacity != 0 || len(value.InitialAdministrators) != 0 || len(value.InitialTeamOwners) != 0 || value.ServicePortRanges == nil || value.QUICIdleTimeout != -1500*time.Millisecond || value.DrainTimeout != time.Minute {
		t.Fatal("presence was lost", value)
	}
	if _, err := value.ServicePortInventory(); err == nil {
		t.Fatal("explicit empty inventory fell back to defaults")
	}
	omitted, err := loadTNLDYAML(t, "  metrics_listen: \"\"\n")
	if err != nil {
		t.Fatal(err)
	}
	var defaults tnldconfig.Config
	omitted.TNLD.Apply(&defaults)
	if inventory, err := defaults.ServicePortInventory(); err != nil || !inventory.Contains(20000) || !inventory.Contains(20015) || inventory.Contains(20016) {
		t.Fatal("omitted inventory default", inventory, err)
	}
	t.Setenv("TNLD_METRICS_LISTEN", "")
	base := tnldconfig.Config{MetricsListen: "environment", RelayStreamCapacity: 99}
	applied := document.TNLD.ApplyLowerPrecedence(&base, map[string]bool{"relay_stream_capacity": true})
	if base.MetricsListen != "environment" || base.RelayStreamCapacity != 99 || applied["metrics_listen"] || applied["relay_stream_capacity"] {
		t.Fatal("higher precedence was overwritten", base, applied)
	}
	for _, duration := range []string{"0", "+1h", "1.s", "1µs", "1μs"} {
		if _, err := loadTNLDYAML(t, "  quic_idle_timeout: \""+duration+"\"\n"); err != nil {
			t.Fatalf("time.ParseDuration syntax %q: %v", duration, err)
		}
	}
}
