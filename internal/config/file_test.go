package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"go.yaml.in/yaml/v3"
)

func TestLoadDocumentPreservesExactDNSHostnames(t *testing.T) {
	for name, contents := range map[string]string{
		"tnl.yml":  "version: 1\ntnl:\n  services:\n    api: {}\n  deployments:\n    local:\n      targets:\n        api:\n          hostname: api.example.test\n  aliases:\n    review:\n      service: api\n      hostname: review.example.test\n",
		"tnl.json": `{"version":1,"tnl":{"services":{"api":{}},"deployments":{"local":{"targets":{"api":{"hostname":"api.example.test"}}}},"aliases":{"review":{"service":"api","hostname":"review.example.test"}}}}`,
	} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		document, err := LoadDocument(path)
		if err != nil {
			t.Fatal(err)
		}
		service := document.TNL.Deployments["local"].Targets["api"]
		alias := document.TNL.Aliases["review"]
		if service.Hostname == nil || *service.Hostname != "api.example.test" || alias.Hostname == nil || *alias.Hostname != "review.example.test" {
			t.Fatalf("%s exact DNS hostnames changed: %#v", name, document.TNL)
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
		"root-public.yml":    {"version: 1\ntnl:\n  public_url: {}\n", "field public_url not found"},
		"root-public.json":   {`{"version":1,"tnl":{"public_url":{}}}`, `unknown object member name "public_url"`},
		"root-domain.yml":    {"version: 1\ntnl:\n  domain: example.test\n", "field domain not found"},
		"root-limits.json":   {`{"version":1,"tnl":{"limits":{"http":{"total":1}}}}`, `unknown object member name "limits"`},
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
  services:
    web: {}
  deployments:
    local:
      targets:
        web:
          address: 3000
          http:
            readiness: {path: /health}
            access: {ip: [192.0.2.1]}
            limits:
              total: 20
              rate: {count: 5, per: 1m}
              concurrency: 750
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
		document.TNL.Deployments["local"].Targets["web"].Address == nil || string(*document.TNL.Deployments["local"].Targets["web"].Address) != "3000" ||
		document.TNL.Deployments["local"].Targets["web"].HTTP.Readiness.Path != "/health" ||
		document.TNL.Deployments["local"].Targets["web"].HTTP.Access == nil || document.TNL.Deployments["local"].Targets["web"].HTTP.Access.VisitorMode() != "restricted" || len(document.TNL.Deployments["local"].Targets["web"].HTTP.Access.IP) != 1 ||
		document.TNL.Deployments["local"].Targets["web"].HTTP.Limits == nil || document.TNL.Deployments["local"].Targets["web"].HTTP.Limits.Concurrency == nil || *document.TNL.Deployments["local"].Targets["web"].HTTP.Limits.Concurrency != 750 ||
		document.TNL.Deployments["local"].Targets["web"].HTTP.Limits.Total == nil || *document.TNL.Deployments["local"].Targets["web"].HTTP.Limits.Total != 20 ||
		document.TNL.Deployments["local"].Targets["web"].HTTP.Limits.Rate == nil || document.TNL.Deployments["local"].Targets["web"].HTTP.Limits.Rate.Count == nil || *document.TNL.Deployments["local"].Targets["web"].HTTP.Limits.Rate.Count != 5 ||
		document.TNL.Deployments["local"].Targets["web"].HTTP.Limits.Rate.Per == nil || document.TNL.Deployments["local"].Targets["web"].HTTP.Limits.Rate.Per.Value() != time.Minute {
		t.Fatalf("document = %#v", document)
	}
}

func TestWebhookProviderAndSourceOverrideInStaticFiles(t *testing.T) {
	for name, contents := range map[string]string{
		"restricted.json":   `{"version":1,"tnl":{"services":{"api":{}},"deployments":{"local":{"targets":{"api":{}}}},"webhooks":{"payments":{"service":"api","path":"/hooks/payments","provider":"stripe","source_ips":["198.51.100.0/24"]}}}}`,
		"unrestricted.json": `{"version":1,"tnl":{"services":{"api":{}},"deployments":{"local":{"targets":{"api":{}}}},"webhooks":{"payments":{"service":"api","path":"/hooks/payments","provider":"custom"}}}}`,
		"restricted.yml":    "version: 1\ntnl:\n  services:\n    api: {}\n  deployments:\n    local:\n      targets:\n        api: {}\n  webhooks:\n    payments:\n      service: api\n      path: /hooks/payments\n      provider: stripe\n      source_ips: [198.51.100.0/24]\n",
		"unrestricted.yml":  "version: 1\ntnl:\n  services:\n    api: {}\n  deployments:\n    local:\n      targets:\n        api: {}\n  webhooks:\n    payments:\n      service: api\n      path: /hooks/payments\n      provider: custom\n",
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
			value := daemonconfig.Config{MetricsListen: "default", RelayStreamCapacity: 99}
			document.TNLD.Apply(&value)
			if value.Role != daemonconfig.RoleRelay || value.MetricsListen != "" || value.RelayStreamCapacity != 12 || value.QUICIdleTimeout != 30*time.Second {
				t.Fatalf("tnld = %#v", value)
			}
		})
	}
}

func TestTNLDEnrollmentCeilingsFromFiles(t *testing.T) {
	for extension, contents := range map[string]string{
		"json": `{"version":1,"tnld":{"publisher_enrollment_max_members":100000,"publisher_enrollment_max_lifetime":"2160h","project_max_publishers":500}}`,
		"yml":  "version: 1\ntnld:\n  publisher_enrollment_max_members: 100000\n  publisher_enrollment_max_lifetime: 2160h\n  project_max_publishers: 500\n",
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
			var value daemonconfig.Config
			document.TNLD.Apply(&value)
			got := value.PublisherEnrollmentLimits()
			if got.Members != 100000 || got.Lifetime != 2160*time.Hour || got.ProjectPublishers != 500 {
				t.Fatal("file lost configured ceilings", got)
			}
		})
	}
	for _, bad := range []string{
		`{"version":1,"tnld":{"publisher_enrollment_max_lifetime":2160}}`,
		`{"version":1,"tnld":{"publisher_enrollment_max_members":null}}`,
	} {
		path := filepath.Join(t.TempDir(), "tnl.json")
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDocument(path); err == nil {
			t.Fatal("invalid file ceiling accepted")
		}
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
		"json": `{"version":1,"tnl":{"services":{"web":{},"api":{}},"deployments":{"local":{"targets":{"web":{"http":{"paths":{"/api":"api","/v1":{"service":"api","strip_prefix":true}}}},"api":{}}}}}}`,
		"yml":  "version: 1\ntnl:\n  services:\n    web: {}\n    api: {}\n  deployments:\n    local:\n      targets:\n        web:\n          http:\n            paths:\n              /api: api\n              /v1:\n                service: api\n                strip_prefix: true\n        api: {}\n",
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
			if err != nil || parsed.TNL.Deployments["local"].Targets["web"].HTTP.Paths["/api"].Service != "api" ||
				parsed.TNL.Deployments["local"].Targets["web"].HTTP.Paths["/v1"].Service != "api" || !parsed.TNL.Deployments["local"].Targets["web"].HTTP.Paths["/v1"].StripPrefix {
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
	name, hostname, domain := "preview", "preview.example.test", "example.test"
	configuration := TNL{Name: &name, Services: Services{
		"web": {Name: &name, Hostname: &hostname, Domain: &domain, HTTP: &HTTPService{Open: new(true)}}, "api": {},
	}}
	if err := ValidateTNL(configuration); err != nil {
		t.Fatalf("per-service fixed address: %v", err)
	}
	if configuration.Services["api"].Hostname != nil || configuration.Services["api"].Domain != nil || configuration.Services["api"].HTTP != nil {
		t.Fatal("endpoint or browser settings leaked into another binding")
	}
}

func TestValidateTNLRejectsInvalidTargetsAndAcceptsIPAliases(t *testing.T) {
	invalidTarget := Target("https://example.com")
	for name, value := range map[string]TNL{
		"target":             {Services: Services{"web": {Target: &ServiceTarget{Type: "address", Address: &invalidTarget}}}},
		"wide mapped prefix": {Services: Services{"web": {HTTP: &HTTPService{Access: &Access{IP: []string{"::ffff:192.0.2.7/95"}}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateTNL(value); err == nil {
				t.Fatalf("invalid configuration was accepted: %#v", value)
			}
		})
	}
	for _, test := range []struct{ input, want []string }{
		{[]string{"192.0.2.7/24", "192.0.2.0/24"}, []string{"192.0.2.0/24"}},
		{[]string{"192.0.2.1", "192.0.2.1/32"}, []string{"192.0.2.1/32"}},
	} {
		access := &Access{IP: slices.Clone(test.input)}
		value := TNL{Services: Services{"web": {HTTP: &HTTPService{Access: access}}}}
		if err := ValidateTNL(value); err != nil || !slices.Equal(access.IP, test.input) || access.VisitorMode() != "restricted" {
			t.Fatalf("validation must accept aliases without rewriting caller policy: %+v, %v", access, err)
		}
		owned := *access
		if err := owned.Validate(); err != nil || !slices.Equal(owned.IP, test.want) || !slices.Equal(access.IP, test.input) {
			t.Fatalf("owned normalization must retain exact prefixes without changing source: %+v, %v", owned, err)
		}
	}
}

func TestDatabaseServiceConfigurationKeepsWebServicesIndependent(t *testing.T) {
	protocol, target, tlsName, ca := "postgres", Target("db.internal:5432"), "db.internal", "system"
	webTarget := Target("3000")
	project := TNL{OAuth: true, Services: Services{
		"web":    {Target: &ServiceTarget{Type: "address", Address: &webTarget}},
		"orders": {Protocol: &protocol, Target: &ServiceTarget{Type: "address", Address: &target, TLS: &TargetTLS{Hostname: &tlsName, CA: &ca}}},
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
	for _, protocol := range []string{"tcp"} {
		mode := InspectionSummary
		project := TNL{Inspection: &Inspection{Mode: &mode}, Services: Services{"service": {
			Protocol: &protocol, Target: &ServiceTarget{Type: "address", Address: targetPointer("5432")},
		}}}
		if err := ValidateTNL(project); err != nil {
			t.Fatalf("%s summary inspection: %v", protocol, err)
		}
	}
}

func TestRemovedSSHProtocolDirectsExistingSSHDToTCP(t *testing.T) {
	protocol, mode, name, port := "ssh", InspectionNone, "sshd", 22
	for _, target := range []*ServiceTarget{
		nil,
		{Type: "app"},
		{Type: "address", Address: targetPointer("sshd:22")},
		{Type: "address", Address: targetPointer("22"), TLS: &TargetTLS{Hostname: &name}},
		{Type: "compose", Service: &name, Port: &port},
		{Type: "docker", Container: &name, Port: &port},
	} {
		service := Service{Protocol: &protocol, Target: target, Inspection: &Inspection{Mode: &mode}}
		project := TNL{Services: Services{"shell": service}}
		if err := ValidateTNL(project); err == nil || !strings.Contains(err.Error(), "use tcp for an existing sshd") {
			t.Fatalf("SSH target %+v validation = %v, want tcp hint", target, err)
		}
		if _, err := ResolveServiceTarget(service, "127.0.0.1:22"); err == nil || !strings.Contains(err.Error(), "use tcp for an existing sshd") {
			t.Fatalf("SSH target %+v resolution = %v, want tcp hint", target, err)
		}
	}
}

func TestStaticFormatsShareTargetIPAndDurationValidation(t *testing.T) {
	for extension, valid := range map[string]string{
		"json": `{"version":1,"tnl":{"inspection":{"mode":"none"},"services":{"web":{}},"deployments":{"local":{"targets":{"web":{"inspection":{"mode":"summary"},"address":3000,"http":{"readiness":{"path":"/health"},"access":{"ip":["192.0.2.1"]}}}}}}}}`,
		"yml":  "version: 1\ntnl:\n  inspection: {mode: none}\n  services:\n    web: {}\n  deployments:\n    local:\n      targets:\n        web:\n          inspection: {mode: summary}\n          address: 3000\n          http:\n            readiness: {path: /health}\n            access: {ip: [192.0.2.1]}\n",
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
	for name, test := range map[string]struct{ source, category string }{
		"zero concurrency":           {serviceCase("web", "", `{"http":{"limits":{"concurrency":0}}}`), "positive safe integers"},
		"negative total":             {serviceCase("web", "", `{"http":{"limits":{"total":-1}}}`), "positive safe integers"},
		"missing rate period":        {serviceCase("web", "", `{"http":{"limits":{"rate":{"count":2}}}}`), "rate requires count and per"},
		"retired request limit":      {serviceCase("web", "", `{"http":{"request_limit":2}}`), "request_limit"},
		"invalid inspection":         {`{"inspection":{"mode":"all"}}`, "inspection: mode must be none or summary"},
		"invalid service inspection": {serviceCase("web", "", `{"inspection":{"mode":"all"}}`), "services.web.inspection: mode must be none or summary"},
		"retired dev":                {`{"dev":{"startup_timeout":"+1s"}}`, "dev"},
		"server URL":                 {`{"server":"http://control.example"}`, "server must be an HTTPS origin"},
		"uppercase domain":           {serviceCase("web", "", `{"domain":"API.EXAMPLE.TEST"}`), "domain must be a canonical DNS hostname"},
		"multi-label name":           {`{"name":"api.example"}`, "name must be one lowercase DNS label"},
		"hostname path":              {serviceCase("web", "", `{"hostname":"https://api.example.test/path"}`), "hostname must be a canonical DNS hostname"},
		"root hostname":              {`{"hostname":"api.example"}`, "hostname"},
		"service server":             {`{"services":{"web":{"server":"https://control.example"}}}`, "server"},
		"service team":               {`{"services":{"web":{"team":"studio"}}}`, "team"},
		"service feedback":           {`{"services":{"web":{"feedback":true}}}`, "feedback"},
		"obsolete subdomain":         {serviceCase("web", "", `{"subdomain":"api"}`), "subdomain"},
		"target":                     {serviceCase("web", "", `{"address":"https://example.com/path"}`), "target.address:"},
		"raw SSH":                    {serviceCase("shell", "ssh", `{"inspection":{"mode":"none"},"address":"sshd:22"}`), "use tcp for an existing sshd"},
		"raw SSH target TLS":         {serviceCase("shell", "ssh", `{"address":"sshd:22","tls":{}}`), "use tcp for an existing sshd"},
		"ip":                         {serviceCase("web", "", `{"http":{"access":{"ip":["::ffff:192.0.2.7/95"]}}}`), "access.ip"},
		"invalid ip":                 {serviceCase("web", "", `{"http":{"access":{"ip":["invalid"]}}}`), "access.ip"},
		"obsolete provider grant":    {serviceCase("web", "", `{"http":{"access":{"allow_providers":["stripe"]}}}`), "allow_providers"},
		"unknown webhook provider":   {`{"services":{"api":{}},"deployments":{"local":{"targets":{"api":{}}}},"webhooks":{"stripe":{"service":"api","path":"/hooks/stripe","provider":"other"}}}`, "provider must be"},
		"missing webhook provider":   {`{"services":{"api":{}},"deployments":{"local":{"targets":{"api":{}}}},"webhooks":{"stripe":{"service":"api","path":"/hooks/stripe"}}}`, "provider must be"},
		"obsolete webhook source":    {`{"services":{"api":{}},"webhooks":{"stripe":{"service":"api","path":"/hooks/stripe","provider":"stripe","allow_from":"*"}}}`, "allow_from"},
		"obsolete webhook grant":     {`{"services":{"api":{}},"webhooks":{"stripe":{"service":"api","path":"/hooks/stripe","allow_providers":["stripe"]}}}`, "allow_providers"},
	} {
		var value map[string]any
		if err := json.Unmarshal([]byte(test.source), &value); err != nil {
			t.Fatal(err)
		}
		integerValues(value)
		document := map[string]any{"version": 1, "tnl": value}
		jsonData, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		yamlData, err := yaml.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		for extension, invalid := range map[string][]byte{"json": jsonData, "yml": yamlData} {
			t.Run(name+"/"+extension, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "tnl."+extension)
				if err := os.WriteFile(path, invalid, 0o600); err != nil {
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
			base := daemonconfig.Config{MetricsListen: test.environment, RelayStreamCapacity: 99}
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
