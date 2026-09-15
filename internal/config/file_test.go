package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

func TestLoadDocumentRequiresVersionAndStrictFields(t *testing.T) {
	directory := t.TempDir()
	for name, contents := range map[string]string{
		"missing.yml":   "tnl: {}\n",
		"future.yml":    "version: 2\n",
		"unknown.yml":   "version: 1\ntnl:\n  unknown: true\n",
		"duplicate.yml": "version: 1\nversion: 1\n",
		"tagged.yml":    "version: 1\ntnl: !include config.yml\n",
		"trailing.json": "{\"version\":1} {}",
	} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDocument(path); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	invalidUTF8 := filepath.Join(directory, "invalid.yml")
	if err := os.WriteFile(invalidUTF8, []byte{'v', 'e', 'r', 's', 'i', 'o', 'n', ':', ' ', 0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDocument(invalidUTF8); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
}

func TestLoadDocumentPreservesClientValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tnl.yml")
	contents := `version: 1
tnl:
  server: https://control.example.com
  tunnel:
    allow_ip: [192.0.2.1]
    public: false
  publish:
    target: 3000
  dev:
    command: [pnpm, dev]
    port: 4000
    startup_timeout: 90s
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if document.TNL == nil || document.TNL.Server == nil || *document.TNL.Server != "https://control.example.com" ||
		document.TNL.Publish == nil || document.TNL.Publish.Target == nil || string(*document.TNL.Publish.Target) != "3000" ||
		document.TNL.Dev == nil || document.TNL.Dev.StartupTimeout == nil || document.TNL.Dev.StartupTimeout.Value() != 90*time.Second ||
		document.TNL.Tunnel == nil || document.TNL.Tunnel.Public == nil || *document.TNL.Tunnel.Public {
		t.Fatalf("document = %#v", document)
	}
}

func TestTNLDSectionUsesTNLDFieldMetadata(t *testing.T) {
	for extension, contents := range map[string]string{
		"json": `{"version":1,"tnld":{"mode":"relay","metrics_listen":"","relay_stream_capacity":12,"quic_idle_timeout":"30s"}}`,
		"yml":  "version: 1\ntnld:\n  mode: relay\n  metrics_listen: \"\"\n  relay_stream_capacity: 12\n  quic_idle_timeout: 30s\n",
	} {
		t.Run(extension, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tnl."+extension)
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			document, err := LoadDocument(path)
			if err != nil {
				t.Fatal(err)
			}
			value := tnldconfig.Config{MetricsListen: "default", RelayStreamCapacity: 99}
			document.TNLD.Apply(&value)
			if value.Mode != tnldconfig.RoleRelay || value.MetricsListen != "" || value.RelayStreamCapacity != 12 || value.QUICIdleTimeout != 30*time.Second {
				t.Fatalf("tnld = %#v", value)
			}
		})
	}
}

func TestValidateTNLRejectsInvalidServiceNames(t *testing.T) {
	for _, name := range []string{"", "Web", "1web", "web.example", "web-"} {
		if err := ValidateTNL(TNL{Services: map[string]Service{name: {}}}); err == nil {
			t.Fatalf("service name %q was accepted", name)
		}
	}
}

func TestValidateTNLRejectsInvalidTargetsAndCanonicalIPDuplicates(t *testing.T) {
	invalidTarget := Target("https://example.com")
	for name, value := range map[string]TNL{
		"target":            {Publish: &Publish{Target: &invalidTarget}},
		"masked prefix":     {Tunnel: &Tunnel{AllowIP: []string{"192.0.2.7/24"}}},
		"duplicate address": {Tunnel: &Tunnel{AllowIP: []string{"192.0.2.1", "192.0.2.1/32"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateTNL(value); err == nil {
				t.Fatalf("invalid configuration was accepted: %#v", value)
			}
		})
	}
}

func TestStaticFormatsShareTargetIPAndDurationValidation(t *testing.T) {
	for extension, valid := range map[string]string{
		"json": `{"version":1,"tnl":{"tunnel":{"allow_ip":["192.0.2.1"]},"publish":{"target":3000},"dev":{"startup_timeout":"1.5s"}}}`,
		"yml":  "version: 1\ntnl:\n  tunnel:\n    allow_ip: [192.0.2.1]\n  publish:\n    target: 3000\n  dev:\n    startup_timeout: 1.5s\n",
	} {
		t.Run(extension, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tnl."+extension)
			if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadDocument(path); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, invalid := range map[string]string{
		"duration": "version: 1\ntnl:\n  dev:\n    startup_timeout: +1s\n",
		"target":   "version: 1\ntnl:\n  publish:\n    target: https://example.com\n",
		"ip":       "version: 1\ntnl:\n  tunnel:\n    allow_ip: [192.0.2.7/24]\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tnl.yml")
			if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadDocument(path); err == nil {
				t.Fatal("invalid static configuration was accepted")
			}
		})
	}
}
