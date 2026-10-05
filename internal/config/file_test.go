package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

func TestLoadDocumentRequiresVersionAndStrictFields(t *testing.T) {
	directory := t.TempDir()
	for name, test := range map[string]struct{ contents, category string }{
		"missing.yml":    {"tnl: {}\n", "version is required"},
		"missing.json":   {`{"tnl":{}}`, "version is required"},
		"future.yml":     {"version: 2\n", "unsupported configuration version 2"},
		"future.json":    {`{"version":2}`, "unsupported configuration version 2"},
		"unknown.yml":    {"version: 1\ntnl:\n  unexpected_key: true\n", "field unexpected_key not found"},
		"unknown.json":   {`{"version":1,"tnl":{"unexpected_key":true}}`, `unknown object member name "unexpected_key"`},
		"duplicate.yml":  {"version: 1\nversion: 1\n", "already defined"},
		"duplicate.json": {`{"version":1,"version":1}`, "duplicate object member name"},
		"tagged.yml":     {"version: 1\ntnl: !include config.yml\n", "custom YAML tag"},
		"trailing.json":  {"{\"version\":1} {}", "after top-level value"},
		"trailing.yml":   {"version: 1\n---\nversion: 1\n", "more than one YAML document"},
	} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDocument(path); err == nil || !strings.Contains(err.Error(), test.category) {
			t.Fatalf("%s error = %v, want %q", name, err, test.category)
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
  feedback: true
  tunnel:
    allow_ip: [192.0.2.1]
    allow_all_ips: false
    request_limit: 750
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
		document.TNL.Feedback == nil || !*document.TNL.Feedback ||
		document.TNL.Publish == nil || document.TNL.Publish.Target == nil || string(*document.TNL.Publish.Target) != "3000" ||
		document.TNL.Dev == nil || document.TNL.Dev.StartupTimeout == nil || document.TNL.Dev.StartupTimeout.Value() != 90*time.Second ||
		document.TNL.Tunnel == nil || document.TNL.Tunnel.AllowAllIPs == nil || *document.TNL.Tunnel.AllowAllIPs ||
		document.TNL.Tunnel.RequestLimit == nil || *document.TNL.Tunnel.RequestLimit != 750 {
		t.Fatalf("document = %#v", document)
	}
}

func TestTNLDSectionUsesTNLDFieldMetadata(t *testing.T) {
	for extension, contents := range map[string]string{
		"json": `{"version":1,"tnld":{"role":"relay","metrics_listen":"","relay_stream_capacity":12,"quic_idle_timeout":"30s"}}`,
		"yml":  "version: 1\ntnld:\n  role: relay\n  metrics_listen: \"\"\n  relay_stream_capacity: 12\n  quic_idle_timeout: 30s\n",
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
			if value.Role != tnldconfig.RoleRelay || value.MetricsListen != "" || value.RelayStreamCapacity != 12 || value.QUICIdleTimeout != 30*time.Second {
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

func TestPathMountsUseConfiguredServicesAndCleanPrefixes(t *testing.T) {
	for name, contents := range map[string]string{
		"json": `{"version":1,"tnl":{"services":{"web":{"paths":{"/api":"api","/v1":{"service":"api","strip_prefix":true}}},"api":{}}}}`,
		"yml":  "version: 1\ntnl:\n  services:\n    web:\n      paths:\n        /api: api\n        /v1:\n          service: api\n          strip_prefix: true\n    api: {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			filename := "tnl." + name
			if name == "yml" {
				filename = "tnl.yml"
			}
			path := filepath.Join(t.TempDir(), filename)
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			parsed, err := LoadDocument(path)
			if err != nil || parsed.TNL.Services["web"].Paths["/api"].Service != "api" ||
				parsed.TNL.Services["web"].Paths["/v1"].Service != "api" || !parsed.TNL.Services["web"].Paths["/v1"].StripPrefix {
				t.Fatalf("paths = %+v, %v", parsed.TNL, err)
			}
		})
	}
	for _, prefix := range []string{"/", "/api/", "/api//v1", "/api/../admin", "/api%2Fv1", "/__tnl", "/__tnl/share"} {
		if err := ValidateTNL(TNL{Services: Services{"web": {Paths: map[string]PathMount{prefix: {Service: "api"}}}, "api": {}}}); err == nil {
			t.Fatalf("invalid mount prefix %q was accepted", prefix)
		}
	}
	for _, destination := range []string{"missing", "web", ""} {
		if err := ValidateTNL(TNL{Services: Services{"web": {Paths: map[string]PathMount{"/api": {Service: destination}}}, "api": {}}}); err == nil {
			t.Fatalf("mount destination %q was accepted", destination)
		}
	}
}

func TestValidateTNLScopesFixedAddressesToOneService(t *testing.T) {
	name, publicURL, domain, open := "preview", "https://preview.example.test", "example.test", true
	for _, tunnel := range []*Tunnel{{Name: &name}, {PublicURL: &publicURL}} {
		if err := ValidateTNL(TNL{Tunnel: tunnel, Services: Services{"web": {}}}); err == nil ||
			!strings.Contains(err.Error(), "belong under services.NAME.tunnel") {
			t.Fatalf("root fixed address with named services: %v", err)
		}
		if err := ValidateTNL(TNL{Tunnel: tunnel}); err != nil {
			t.Fatalf("unnamed service fixed address: %v", err)
		}
	}
	if err := ValidateTNL(TNL{Tunnel: &Tunnel{Domain: &domain, Open: &open}, Services: Services{
		"web": {Tunnel: &Tunnel{Name: &name}}, "api": {},
	}}); err != nil {
		t.Fatalf("per-service fixed address: %v", err)
	}
	if err := ValidateTNL(TNL{Services: Services{"web": {Tunnel: &Tunnel{Name: &name, PublicURL: &publicURL}}}}); err == nil {
		t.Fatal("name and exact public URL were accepted together")
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
	for name, test := range map[string]struct{ json, yaml, category string }{
		"zero request limit":     {`{"version":1,"tnl":{"tunnel":{"request_limit":0}}}`, "version: 1\ntnl:\n  tunnel:\n    request_limit: 0\n", "tunnel.request_limit must be greater than zero"},
		"negative request limit": {`{"version":1,"tnl":{"services":{"web":{"tunnel":{"request_limit":-1}}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      tunnel:\n        request_limit: -1\n", "services.web: tunnel.request_limit must be greater than zero"},
		"duration":               {`{"version":1,"tnl":{"dev":{"startup_timeout":"+1s"}}}`, "version: 1\ntnl:\n  dev:\n    startup_timeout: +1s\n", "invalid duration syntax"},
		"server URL":             {`{"version":1,"tnl":{"server":"http://control.example"}}`, "version: 1\ntnl:\n  server: http://control.example\n", "server must be an HTTPS origin"},
		"uppercase domain":       {`{"version":1,"tnl":{"tunnel":{"domain":"API.EXAMPLE.TEST"}}}`, "version: 1\ntnl:\n  tunnel:\n    domain: API.EXAMPLE.TEST\n", "tunnel.domain must be a canonical domain name"},
		"multi-label name":       {`{"version":1,"tnl":{"tunnel":{"name":"api.example"}}}`, "version: 1\ntnl:\n  tunnel:\n    name: api.example\n", "tunnel.name must be one lowercase ASCII DNS label"},
		"public URL path":        {`{"version":1,"tnl":{"tunnel":{"public_url":"https://api.example.test/path"}}}`, "version: 1\ntnl:\n  tunnel:\n    public_url: https://api.example.test/path\n", "tunnel.public_url must be an HTTPS public URL"},
		"root name with service": {`{"version":1,"tnl":{"tunnel":{"name":"api"},"services":{"api":{}}}}`, "version: 1\ntnl:\n  tunnel:\n    name: api\n  services:\n    api: {}\n", "tunnel.name and tunnel.public_url belong under services.NAME.tunnel"},
		"service server":         {`{"version":1,"tnl":{"services":{"web":{"server":"https://control.example"}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      server: https://control.example\n", "server"},
		"service team":           {`{"version":1,"tnl":{"services":{"web":{"team":"studio"}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      team: studio\n", "team"},
		"service feedback":       {`{"version":1,"tnl":{"services":{"web":{"feedback":true}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      feedback: true\n", "feedback"},
		"obsolete subdomain":     {`{"version":1,"tnl":{"tunnel":{"subdomain":"api"}}}`, "version: 1\ntnl:\n  tunnel:\n    subdomain: api\n", "subdomain"},
		"target":                 {`{"version":1,"tnl":{"publish":{"target":"https://example.com"}}}`, "version: 1\ntnl:\n  publish:\n    target: https://example.com\n", "publish.target:"},
		"ip":                     {`{"version":1,"tnl":{"tunnel":{"allow_ip":["192.0.2.7/24"]}}}`, "version: 1\ntnl:\n  tunnel:\n    allow_ip: [192.0.2.7/24]\n", "must be a canonical IP address or prefix"},
		"duplicate":              {`{"version":1,"tnl":{"tunnel":{"allow_ip":["192.0.2.1","192.0.2.1/32"]}}}`, "version: 1\ntnl:\n  tunnel:\n    allow_ip: [192.0.2.1, 192.0.2.1/32]\n", "is duplicated"},
		"unknown provider":       {`{"version":1,"tnl":{"tunnel":{"allow_providers":["other"]}}}`, "version: 1\ntnl:\n  tunnel:\n    allow_providers: [other]\n", "not a supported webhook IP provider"},
		"duplicate provider":     {`{"version":1,"tnl":{"tunnel":{"allow_providers":["github","github"]}}}`, "version: 1\ntnl:\n  tunnel:\n    allow_providers: [github, github]\n", "is duplicated"},
		"public with providers":  {`{"version":1,"tnl":{"tunnel":{"allow_all_ips":true,"allow_providers":["stripe"]}}}`, "version: 1\ntnl:\n  tunnel:\n    allow_all_ips: true\n    allow_providers: [stripe]\n", "cannot be combined"},
	} {
		for extension, invalid := range map[string]string{"json": test.json, "yml": test.yaml} {
			t.Run(name+"/"+extension, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "tnl."+extension)
				if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := LoadDocument(path); err == nil || !strings.Contains(err.Error(), test.category) {
					t.Fatalf("invalid static configuration error = %v, want %q", err, test.category)
				}
			})
		}
	}
}

func TestTNLDFilePrecedenceDistinguishesAbsentAndEmptyEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tnl.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"tnld":{"metrics_listen":"file:1234","relay_stream_capacity":12}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		present     bool
		environment string
		flag        bool
		want        string
	}{
		{"absent", false, "", false, "file:1234"},
		{"explicit_empty", true, "", false, ""},
		{"environment", true, "env:4321", false, "env:4321"},
		{"flag", false, "", true, "flag:5678"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("TNLD_METRICS_LISTEN", test.environment)
			if !test.present {
				if err := os.Unsetenv("TNLD_METRICS_LISTEN"); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("TNLD_RELAY_STREAM_CAPACITY", "")
			if err := os.Unsetenv("TNLD_RELAY_STREAM_CAPACITY"); err != nil {
				t.Fatal(err)
			}
			base := tnldconfig.Config{MetricsListen: test.environment, RelayStreamCapacity: 99}
			if test.flag {
				base.MetricsListen = "flag:5678"
			}
			applied := document.TNLD.ApplyLowerPrecedence(&base, map[string]bool{"metrics_listen": test.flag})
			if base.MetricsListen != test.want || base.RelayStreamCapacity != 12 || applied["metrics_listen"] != (!test.present && !test.flag) {
				t.Fatalf("resolved = %#v, applied = %v", base, applied)
			}
		})
	}
}
