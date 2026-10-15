package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

func TestLoadDocumentNormalizesBareExactPublicURLs(t *testing.T) {
	for name, contents := range map[string]string{
		"tnl.yml":  "version: 1\ntnl:\n  services:\n    api:\n      tunnel:\n        public_url: api.example.test\n  aliases:\n    review:\n      service: api\n      public_url: review.example.test\n",
		"tnl.json": `{"version":1,"tnl":{"services":{"api":{"tunnel":{"public_url":"api.example.test"}}},"aliases":{"review":{"service":"api","public_url":"review.example.test"}}}}`,
	} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		document, err := LoadDocument(path)
		if err != nil {
			t.Fatal(err)
		}
		service := document.TNL.Services["api"]
		alias := document.TNL.Aliases["review"]
		if service.Tunnel == nil || service.Tunnel.PublicURL == nil || *service.Tunnel.PublicURL != "https://api.example.test" || alias.PublicURL == nil || *alias.PublicURL != "https://review.example.test" {
			t.Fatalf("%s exact public URLs were not normalized: %#v", name, document.TNL)
		}
	}
}

func TestLoadDocumentRequiresVersionAndStrictFields(t *testing.T) {
	directory := t.TempDir()
	for name, test := range map[string]struct{ contents, category string }{
		"missing.yml":        {"tnl: {}\n", "version is required"},
		"missing.json":       {`{"tnl":{}}`, "version is required"},
		"future.yml":         {"version: 2\n", "unsupported configuration version 2"},
		"future.json":        {`{"version":2}`, "unsupported configuration version 2"},
		"unknown.yml":        {"version: 1\ntnl:\n  unexpected_key: true\n", "field unexpected_key not found"},
		"unknown.json":       {`{"version":1,"tnl":{"unexpected_key":true}}`, `unknown object member name "unexpected_key"`},
		"service-oauth.json": {`{"version":1,"tnl":{"services":{"api":{"oauth":true}}}}`, `unknown object member name "oauth"`},
		"retired-ca.yml":     {"version: 1\ntnl:\n  publish:\n    ca_file: ca.pem\n", "field publish not found"},
		"retired-ca.json":    {`{"version":1,"tnl":{"publish":{"ca_file":"ca.pem"}}}`, `unknown object member name "publish"`},
		"duplicate.yml":      {"version: 1\nversion: 1\n", "already defined"},
		"duplicate.json":     {`{"version":1,"version":1}`, "duplicate object member name"},
		"tagged.yml":         {"version: 1\ntnl: !include config.yml\n", "custom YAML tag"},
		"trailing.json":      {"{\"version\":1} {}", "after top-level value"},
		"trailing.yml":       {"version: 1\n---\nversion: 1\n", "more than one YAML document"},
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
  oauth: true
  tunnel:
    allow_ip: [192.0.2.1]
    allow_all_ips: false
    limits:
      http:
        total: 20
        rate: {count: 5, per: 1m}
        concurrency: 750
  services:
    web:
      target: {type: address, address: 3000}
      http:
        readiness: {path: /health}
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if document.TNL == nil || document.TNL.Server == nil || *document.TNL.Server != "https://control.example.com" ||
		document.TNL.Feedback == nil || !*document.TNL.Feedback || !document.TNL.OAuth ||
		document.TNL.Services["web"].Target == nil || string(*document.TNL.Services["web"].Target.Address) != "3000" ||
		document.TNL.Services["web"].HTTP.Readiness.Path != "/health" ||
		document.TNL.Tunnel == nil || document.TNL.Tunnel.AllowAllIPs == nil || *document.TNL.Tunnel.AllowAllIPs ||
		document.TNL.Tunnel.Limits == nil || document.TNL.Tunnel.Limits.HTTP.Concurrency == nil || *document.TNL.Tunnel.Limits.HTTP.Concurrency != 750 ||
		document.TNL.Tunnel.Limits.HTTP.Total == nil || *document.TNL.Tunnel.Limits.HTTP.Total != 20 ||
		document.TNL.Tunnel.Limits.HTTP.Rate == nil || document.TNL.Tunnel.Limits.HTTP.Rate.Count == nil || *document.TNL.Tunnel.Limits.HTTP.Rate.Count != 5 ||
		document.TNL.Tunnel.Limits.HTTP.Rate.Per == nil || document.TNL.Tunnel.Limits.HTTP.Rate.Per.Value() != time.Minute {
		t.Fatalf("document = %#v", document)
	}
}

func TestWebhookProviderAndSourceOverrideInStaticFiles(t *testing.T) {
	for name, contents := range map[string]string{
		"restricted.json":   `{"version":1,"tnl":{"services":{"api":{}},"webhooks":{"payments":{"service":"api","path":"/hooks/payments","provider":"stripe","source_ips":["198.51.100.0/24"]}}}}`,
		"unrestricted.json": `{"version":1,"tnl":{"services":{"api":{}},"webhooks":{"payments":{"service":"api","path":"/hooks/payments","provider":"custom"}}}}`,
		"restricted.yml":    "version: 1\ntnl:\n  services:\n    api: {}\n  webhooks:\n    payments:\n      service: api\n      path: /hooks/payments\n      provider: stripe\n      source_ips: [198.51.100.0/24]\n",
		"unrestricted.yml":  "version: 1\ntnl:\n  services:\n    api: {}\n  webhooks:\n    payments:\n      service: api\n      path: /hooks/payments\n      provider: custom\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			document, err := LoadDocument(path)
			if err != nil {
				t.Fatal(err)
			}
			policy := document.TNL.Webhooks["payments"]
			if strings.HasPrefix(name, "unrestricted") {
				if policy.Provider != "custom" || policy.SourceIPs != nil {
					t.Fatal("custom provider gained an unexpected override")
				}
			} else if policy.Provider != "stripe" || len(policy.SourceIPs) != 1 || policy.SourceIPs[0] != "198.51.100.0/24" {
				t.Fatalf("restricted webhook sources = %#v", policy)
			}
		})
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
		"json": `{"version":1,"tnl":{"services":{"web":{"http":{"paths":{"/api":"api","/v1":{"service":"api","strip_prefix":true}}}},"api":{}}}}`,
		"yml":  "version: 1\ntnl:\n  services:\n    web:\n      http:\n        paths:\n          /api: api\n          /v1:\n            service: api\n            strip_prefix: true\n    api: {}\n",
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
			if err != nil || ServicePaths(parsed.TNL.Services["web"])["/api"].Service != "api" ||
				ServicePaths(parsed.TNL.Services["web"])["/v1"].Service != "api" || !ServicePaths(parsed.TNL.Services["web"])["/v1"].StripPrefix {
				t.Fatalf("paths = %+v, %v", parsed.TNL, err)
			}
		})
	}
	for _, prefix := range []string{"/", "/api/", "/api//v1", "/api/../admin", "/api%2Fv1", "/__tnl", "/__tnl/share"} {
		if err := ValidateTNL(TNL{Services: Services{"web": {HTTP: &HTTPService{Paths: map[string]PathMount{prefix: {Service: "api"}}}}, "api": {}}}); err == nil {
			t.Fatalf("invalid mount prefix %q was accepted", prefix)
		}
	}
	for _, destination := range []string{"missing", "web", ""} {
		if err := ValidateTNL(TNL{Services: Services{"web": {HTTP: &HTTPService{Paths: map[string]PathMount{"/api": {Service: destination}}}}, "api": {}}}); err == nil {
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
		"target":            {Services: Services{"web": {Target: &ServiceTarget{Type: "address", Address: &invalidTarget}}}},
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

func TestDatabaseServiceConfigurationKeepsWebServicesIndependent(t *testing.T) {
	protocol, target, tlsName, caFile := "postgres", Target("db.internal:5432"), "db.internal", "./certs/target-ca.pem"
	webTarget := Target("3000")
	project := TNL{OAuth: true, Services: Services{
		"web":    {Target: &ServiceTarget{Type: "address", Address: &webTarget}},
		"orders": {Protocol: &protocol, Target: &ServiceTarget{Type: "address", Address: &target, TLS: &TargetTLS{ServerName: &tlsName, CAFile: &caFile}}},
	}}
	if err := ValidateTNL(project); err != nil {
		t.Fatalf("mixed web and PostgreSQL services: %v", err)
	}
	for name, change := range map[string]func(*TNL){
		"http target": func(value *TNL) {
			invalid := Target("http://db.internal:5432")
			service := value.Services["orders"]
			service.Target.Address = &invalid
		},
		"readiness": func(value *TNL) {
			service := value.Services["orders"]
			service.HTTP = &HTTPService{Readiness: &Readiness{Path: "/health"}}
			value.Services["orders"] = service
		},
		"mount": func(value *TNL) {
			service := value.Services["web"]
			service.HTTP = &HTTPService{Paths: map[string]PathMount{"/db": {Service: "orders"}}}
			value.Services["web"] = service
		},
		"protocol": func(value *TNL) {
			invalid := "unknown"
			service := value.Services["orders"]
			service.Protocol = &invalid
			value.Services["orders"] = service
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := TNL{OAuth: project.OAuth, Services: Services{"web": project.Services["web"], "orders": project.Services["orders"]}}
			for key, service := range changed.Services {
				if service.Target != nil {
					copy := *service.Target
					service.Target = &copy
					changed.Services[key] = service
				}
			}
			change(&changed)
			if err := ValidateTNL(changed); err == nil {
				t.Fatal("invalid mixed project was accepted")
			}
		})
	}
}

func TestInspectionModeValid(t *testing.T) {
	for _, test := range []struct {
		mode  InspectionMode
		valid bool
	}{
		{InspectionNone, true},
		{InspectionSummary, true},
		{InspectionMode("detailed"), false},
		{InspectionMode("all"), false},
		{"", false},
	} {
		if got := test.mode.Valid(); got != test.valid {
			t.Errorf("mode %q valid = %t, want %t", test.mode, got, test.valid)
		}
	}
}

func TestTCPInspectionModes(t *testing.T) {
	for _, protocol := range []string{"postgres", "mysql", "redis"} {
		mode := InspectionSummary
		project := TNL{Inspection: &Inspection{Mode: &mode}, Services: Services{"service": {
			Protocol: &protocol, Target: &ServiceTarget{Type: "address", Address: targetPointer("5432")},
		}}}
		if err := ValidateTNL(project); err != nil {
			t.Fatalf("%s summary inspection: %v", protocol, err)
		}
	}
	protocol, mode := "ssh", InspectionSummary
	project := TNL{Inspection: &Inspection{Mode: &mode}, Services: Services{"service": {
		Protocol: &protocol, Target: &ServiceTarget{Type: "address", Address: targetPointer("22")},
	}}}
	if err := ValidateTNL(project); err == nil {
		t.Fatal("SSH accepted summary inspection")
	}
	mode = InspectionNone
	if err := ValidateTNL(project); err != nil {
		t.Fatalf("SSH rejected none mode: %v", err)
	}
}

func TestStaticFormatsShareTargetIPAndDurationValidation(t *testing.T) {
	for extension, valid := range map[string]string{
		"json": `{"version":1,"tnl":{"inspection":{"mode":"none"},"services":{"web":{"inspection":{"mode":"summary"},"target":{"type":"address","address":3000},"http":{"readiness":{"path":"/health"}}}},"tunnel":{"allow_ip":["192.0.2.1"]}}}`,
		"yml":  "version: 1\ntnl:\n  inspection: {mode: none}\n  services:\n    web:\n      inspection: {mode: summary}\n      target: {type: address, address: 3000}\n      http:\n        readiness: {path: /health}\n  tunnel:\n    allow_ip: [192.0.2.1]\n",
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
		"zero concurrency":           {`{"version":1,"tnl":{"tunnel":{"limits":{"http":{"concurrency":0}}}}}`, "version: 1\ntnl:\n  tunnel:\n    limits:\n      http: {concurrency: 0}\n", "positive safe integers"},
		"negative total":             {`{"version":1,"tnl":{"services":{"web":{"tunnel":{"limits":{"http":{"total":-1}}}}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      tunnel:\n        limits:\n          http: {total: -1}\n", "positive safe integers"},
		"missing rate period":        {`{"version":1,"tnl":{"tunnel":{"limits":{"http":{"rate":{"count":2}}}}}}`, "version: 1\ntnl:\n  tunnel:\n    limits:\n      http:\n        rate: {count: 2}\n", "rate requires count and per"},
		"retired request limit":      {`{"version":1,"tnl":{"tunnel":{"request_limit":2}}}`, "version: 1\ntnl:\n  tunnel:\n    request_limit: 2\n", "request_limit"},
		"invalid inspection":         {`{"version":1,"tnl":{"inspection":{"mode":"all"}}}`, "version: 1\ntnl:\n  inspection: {mode: all}\n", "inspection: mode must be none or summary"},
		"invalid service inspection": {`{"version":1,"tnl":{"services":{"web":{"inspection":{"mode":"all"}}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      inspection: {mode: all}\n", "services.web.inspection: mode must be none or summary"},
		"retired dev":                {`{"version":1,"tnl":{"dev":{"startup_timeout":"+1s"}}}`, "version: 1\ntnl:\n  dev:\n    startup_timeout: +1s\n", "dev"},
		"server URL":                 {`{"version":1,"tnl":{"server":"http://control.example"}}`, "version: 1\ntnl:\n  server: http://control.example\n", "server must be an HTTPS origin"},
		"uppercase domain":           {`{"version":1,"tnl":{"tunnel":{"domain":"API.EXAMPLE.TEST"}}}`, "version: 1\ntnl:\n  tunnel:\n    domain: API.EXAMPLE.TEST\n", "tunnel.domain must be a canonical domain name"},
		"multi-label name":           {`{"version":1,"tnl":{"tunnel":{"name":"api.example"}}}`, "version: 1\ntnl:\n  tunnel:\n    name: api.example\n", "tunnel.name must be one lowercase ASCII DNS label"},
		"public URL path":            {`{"version":1,"tnl":{"tunnel":{"public_url":"https://api.example.test/path"}}}`, "version: 1\ntnl:\n  tunnel:\n    public_url: https://api.example.test/path\n", "tunnel.public_url must be a canonical hostname or HTTPS public URL"},
		"root name with service":     {`{"version":1,"tnl":{"tunnel":{"name":"api"},"services":{"api":{}}}}`, "version: 1\ntnl:\n  tunnel:\n    name: api\n  services:\n    api: {}\n", "tunnel.name and tunnel.public_url belong under services.NAME.tunnel"},
		"service server":             {`{"version":1,"tnl":{"services":{"web":{"server":"https://control.example"}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      server: https://control.example\n", "server"},
		"service team":               {`{"version":1,"tnl":{"services":{"web":{"team":"studio"}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      team: studio\n", "team"},
		"service feedback":           {`{"version":1,"tnl":{"services":{"web":{"feedback":true}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      feedback: true\n", "feedback"},
		"obsolete subdomain":         {`{"version":1,"tnl":{"tunnel":{"subdomain":"api"}}}`, "version: 1\ntnl:\n  tunnel:\n    subdomain: api\n", "subdomain"},
		"target":                     {`{"version":1,"tnl":{"services":{"web":{"target":{"type":"address","address":"https://example.com/path"}}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      target: {type: address, address: https://example.com/path}\n", "target.address:"},
		"ip":                         {`{"version":1,"tnl":{"tunnel":{"allow_ip":["192.0.2.7/24"]}}}`, "version: 1\ntnl:\n  tunnel:\n    allow_ip: [192.0.2.7/24]\n", "must be a canonical IP address or prefix"},
		"duplicate":                  {`{"version":1,"tnl":{"tunnel":{"allow_ip":["192.0.2.1","192.0.2.1/32"]}}}`, "version: 1\ntnl:\n  tunnel:\n    allow_ip: [192.0.2.1, 192.0.2.1/32]\n", "is duplicated"},
		"obsolete provider grant":    {`{"version":1,"tnl":{"tunnel":{"allow_providers":["stripe"]}}}`, "version: 1\ntnl:\n  tunnel:\n    allow_providers: [stripe]\n", "allow_providers"},
		"unknown webhook provider":   {`{"version":1,"tnl":{"services":{"api":{}},"webhooks":{"stripe":{"service":"api","path":"/hooks/stripe","provider":"other"}}}}`, "version: 1\ntnl:\n  services:\n    api: {}\n  webhooks:\n    stripe:\n      service: api\n      path: /hooks/stripe\n      provider: other\n", "provider must be"},
		"missing webhook provider":   {`{"version":1,"tnl":{"services":{"api":{}},"webhooks":{"stripe":{"service":"api","path":"/hooks/stripe"}}}}`, "version: 1\ntnl:\n  services:\n    api: {}\n  webhooks:\n    stripe:\n      service: api\n      path: /hooks/stripe\n", "provider must be"},
		"obsolete webhook source":    {`{"version":1,"tnl":{"services":{"api":{}},"webhooks":{"stripe":{"service":"api","path":"/hooks/stripe","provider":"stripe","allow_from":"*"}}}}`, "version: 1\ntnl:\n  services:\n    api: {}\n  webhooks:\n    stripe:\n      service: api\n      path: /hooks/stripe\n      provider: stripe\n      allow_from: '*'\n", "allow_from"},
		"obsolete webhook grant":     {`{"version":1,"tnl":{"services":{"api":{}},"webhooks":{"stripe":{"service":"api","path":"/hooks/stripe","allow_providers":["stripe"]}}}}`, "version: 1\ntnl:\n  services:\n    api: {}\n  webhooks:\n    stripe:\n      service: api\n      path: /hooks/stripe\n      allow_providers: [stripe]\n", "allow_providers"},
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
