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
		"missing.yml":                  {"tnl: {}\n", "version is required"},
		"missing.json":                 {`{"tnl":{}}`, "version is required"},
		"future.yml":                   {"version: 2\n", "unsupported configuration version 2"},
		"future.json":                  {`{"version":2}`, "unsupported configuration version 2"},
		"unknown.yml":                  {"version: 1\ntnl:\n  unexpected_key: true\n", "field unexpected_key not found"},
		"unknown.json":                 {`{"version":1,"tnl":{"unexpected_key":true}}`, `unknown object member name "unexpected_key"`},
		"service-oauth.json":           {`{"version":1,"tnl":{"services":{"api":{"oauth":true}}}}`, `unknown object member name "oauth"`},
		"retired-publish.yml":          {"version: 1\ntnl:\n  publish:\n    target: 3000\n", "field publish not found"},
		"retired-publish.json":         {`{"version":1,"tnl":{"publish":{"target":3000}}}`, `unknown object member name "publish"`},
		"retired-service.yml":          {"version: 1\ntnl:\n  services:\n    web:\n      directory: apps/web\n", "field directory not found"},
		"retired-service.json":         {`{"version":1,"tnl":{"services":{"web":{"paths":{"/api":"api"}}}}}`, `unknown object member name "paths"`},
		"retired-service-publish.json": {`{"version":1,"tnl":{"services":{"api":{"publish":{"target":3000}}}}}`, `unknown object member name "publish"`},
		"duplicate.yml":                {"version: 1\nversion: 1\n", "already defined"},
		"duplicate.json":               {`{"version":1,"version":1}`, "duplicate object member name"},
		"tagged.yml":                   {"version: 1\ntnl: !include config.yml\n", "custom YAML tag"},
		"trailing.json":                {"{\"version\":1} {}", "after top-level value"},
		"trailing.yml":                 {"version: 1\n---\nversion: 1\n", "more than one YAML document"},
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
    app:
      target: {type: address, address: 3000}
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
		document.TNL.Services["app"].Target == nil || string(*document.TNL.Services["app"].Target.Address) != "3000" ||
		document.TNL.Services["app"].Readiness == nil || document.TNL.Services["app"].Readiness.Path != "/health" ||
		document.TNL.Tunnel == nil || document.TNL.Tunnel.AllowAllIPs == nil || *document.TNL.Tunnel.AllowAllIPs ||
		document.TNL.Tunnel.Limits == nil || document.TNL.Tunnel.Limits.HTTP == nil || document.TNL.Tunnel.Limits.HTTP.Concurrency == nil || *document.TNL.Tunnel.Limits.HTTP.Concurrency != 750 ||
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

func TestNamedServiceTargetsAndHTTPOptions(t *testing.T) {
	for filename, source := range map[string]string{
		"tnl.json": `{"version":1,"tnl":{"services":{"web":{"target":{"type":"app"},"readiness":{"path":"/health"},"http":{"paths":{"/api":"api"}}},"api":{"target":{"type":"address","address":3000}},"orders":{"protocol":"postgres","target":{"type":"docker","compose":{"file":"compose.yaml","project":"shop-k7n2p9","service":"database"},"container_port":5432},"tcp":{"visitor_tls":"passthrough"}}}}}`,
		"tnl.yml":  "version: 1\ntnl:\n  services:\n    web:\n      target: {type: app}\n      readiness: {path: /health}\n      http:\n        paths: {/api: api}\n    api:\n      target: {type: address, address: 3000}\n    orders:\n      protocol: postgres\n      target: {type: docker, compose: {file: compose.yaml, project: shop-k7n2p9, service: database}, container_port: 5432}\n      tcp: {visitor_tls: passthrough}\n",
	} {
		path := filepath.Join(t.TempDir(), filename)
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		document, err := LoadDocument(path)
		if err != nil {
			t.Fatalf("%s: %v", filename, err)
		}
		web, api, orders := document.TNL.Services["web"], document.TNL.Services["api"], document.TNL.Services["orders"]
		if web.Target.Type != "app" || web.Readiness.Path != "/health" || ServicePaths(web)["/api"].Service != "api" ||
			api.Target.Type != "address" || string(*api.Target.Address) != "3000" ||
			orders.Protocol == nil || *orders.Protocol != "postgres" || orders.Target.Type != "docker" || orders.Target.Compose == nil || orders.Target.Compose.Service != "database" || *orders.Target.ContainerPort != 5432 ||
			*orders.TCP.VisitorTLS != "passthrough" {
			t.Fatalf("%s: services = %#v", filename, document.TNL.Services)
		}
	}
	for _, test := range []struct{ source, detail string }{
		{`{"tunnel":{"limits":{"requests":20}}}`, "requests"},
		{`{"tunnel":{"visitor_tls":"passthrough"}}`, "visitor_tls"},
		{`{"services":{"web":{"http":{"readiness":{"path":"/"}}}}}`, "readiness"},
		{`{"services":{"web":{"target":{"type":"address","address":"3000","target_tls":true}}}}`, "target_tls"},
		{`{"services":{"web":{"tunnel":{"limits":{"tcp":{"concurrency":2}}}}}}`, "select only the service protocol"},
		{`{"services":{"orders":{"protocol":"postgres","target":{"type":"address","address":"db:5432"},"tunnel":{"limits":{"http":{"concurrency":2}}}}}}`, "select only the service protocol"},
		{`{"services":{"web":{"target":{"type":"app","address":3000}}}}`, "app requires"},
		{`{"services":{"orders":{"protocol":"postgres","target":{"type":"app"}}}}`, "app requires"},
		{`{"services":{"orders":{"protocol":"postgres","target":{"type":"address"}}}}`, "address is required"},
		{`{"services":{"orders":{"protocol":"postgres","target":{"type":"docker","container":"db"}}}}`, "container_port"},
		{`{"services":{"orders":{"protocol":"postgres","target":{"type":"docker","container":"db","container_port":0}}}}`, "container_port"},
		{`{"services":{"orders":{"protocol":"postgres","target":{"type":"docker","compose":{"file":"../compose.yaml","project":"shop-k7n2p9","service":"database"},"container_port":5432}}}}`, "relative file"},
		{`{"services":{"orders":{"protocol":"postgres","target":{"type":"docker","container":"db","container_port":5432,"address":"db:5432"}}}}`, "docker cannot use address"},
		{`{"services":{"orders":{"protocol":"postgres","target":{"type":"docker","container":"db","compose":{"file":"compose.yaml","project":"shop-k7n2p9","service":"db"},"container_port":5432}}}}`, "exactly one"},
		{`{"services":{"orders":{"protocol":"postgres","target":{"type":"address","address":"db:5432","container_port":5432}}}}`, "address cannot"},
		{`{"services":{"orders":{"protocol":"postgres","target":{"type":"address","address":"db:5432"},"http":{"paths":{}}}}}`, "http and tcp settings"},
		{`{"services":{"web":{"target":{"type":"app"},"tcp":{"visitor_tls":"passthrough"}}}}`, "http and tcp settings"},
		{`{"services":{"orders":{"protocol":"postgres","target":{"type":"address","address":"db:5432","tls":{}},"tcp":{"visitor_tls":"passthrough"}}}}`, "cannot use private target TLS"},
	} {
		path := filepath.Join(t.TempDir(), "tnl.json")
		if err := os.WriteFile(path, []byte(`{"version":1,"tnl":`+test.source+`}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDocument(path); err == nil || !strings.Contains(err.Error(), test.detail) {
			t.Fatalf("%s: error = %v, want %q", test.source, err, test.detail)
		}
	}
}

func TestProjectPublisherSelectsOneOwnerWithoutPuttingCredentialsInConfig(t *testing.T) {
	for filename, source := range map[string]string{
		"tnl.json": `{"version":1,"tnl":{"publisher":{"type":"docker","compose":{"file":"compose.yaml","project":"shop-k7n2p9","service":"publisher"},"container_port":8765},"services":{"web":{"target":{"type":"app"}}}}}`,
		"tnl.yml":  "version: 1\ntnl:\n  publisher:\n    type: docker\n    compose: {file: compose.yaml, project: shop-k7n2p9, service: publisher}\n    container_port: 8765\n  services:\n    orders:\n      protocol: postgres\n      target: {type: docker, compose: {file: compose.yaml, project: shop-k7n2p9, service: database}, container_port: 5432}\n",
	} {
		path := filepath.Join(t.TempDir(), filename)
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		value, err := LoadDocument(path)
		if err != nil || value.TNL.Publisher == nil || value.TNL.Publisher.Type != "docker" {
			t.Fatalf("publisher in %s = %+v, %v", filename, value.TNL, err)
		}
	}
	for _, test := range []struct{ publisher, detail string }{
		{`{"type":"local","container":"publisher"}`, "local publisher"},
		{`{"type":"url"}`, "local or docker"},
		{`{"type":"docker","compose":{"file":"compose.yaml","project":"shop-k7n2p9","service":"--other"},"container_port":8765}`, "docker compose requires"},
		{`{"type":"docker","container":"publisher","container_port":0}`, "container_port"},
		{`{"type":"docker","container":"publisher","container_port":8765,"owner_credential_file":"owner"}`, "owner_credential_file"},
	} {
		path := filepath.Join(t.TempDir(), "tnl.json")
		if err := os.WriteFile(path, []byte(`{"version":1,"tnl":{"publisher":`+test.publisher+`}}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDocument(path); err == nil || !strings.Contains(err.Error(), test.detail) {
			t.Fatalf("invalid publisher %s: %v; want %q", test.publisher, err, test.detail)
		}
	}
	service := "publisher"
	port := 8765
	if err := ValidateTNL(TNL{Publisher: &ProjectPublisher{Type: "docker", DockerSelection: DockerSelection{Container: &service, ContainerPort: &port}},
		Services: Services{"web": {Target: &ServiceTarget{Type: "app"}}}}); err != nil {
		t.Fatalf("docker publisher rejected an app on its network: %v", err)
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

func TestDatabaseServiceConfigurationKeepsWebServicesIndependent(t *testing.T) {
	protocol, target, tlsName, caFile, targetTLS := "postgres", Target("db.internal:5432"), "db.internal", "./certs/target-ca.pem", true
	webTarget := Target("3000")
	project := TNL{OAuth: true, Services: Services{
		"web":    {Publish: &Publish{Target: &webTarget}},
		"orders": {Publish: &Publish{Protocol: &protocol, Target: &target, TargetTLS: &targetTLS, TargetTLSName: &tlsName, TargetCAFile: &caFile}},
	}}
	if err := ValidateTNL(project); err != nil {
		t.Fatalf("mixed web and PostgreSQL services: %v", err)
	}
	for name, change := range map[string]func(*TNL){
		"http target": func(value *TNL) {
			invalid := Target("http://db.internal:5432")
			service := value.Services["orders"]
			service.Publish.Target = &invalid
		},
		"readiness": func(value *TNL) {
			service := value.Services["orders"]
			service.Readiness = &Readiness{Path: "/health"}
			value.Services["orders"] = service
		},
		"mount": func(value *TNL) {
			service := value.Services["web"]
			service.Paths = map[string]PathMount{"/db": {Service: "orders"}}
			value.Services["web"] = service
		},
		"protocol": func(value *TNL) {
			invalid := "unknown"
			service := value.Services["orders"]
			service.Publish.Protocol = &invalid
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := TNL{OAuth: project.OAuth, Services: Services{"web": project.Services["web"], "orders": project.Services["orders"]}}
			for key, service := range changed.Services {
				if service.Publish != nil {
					copy := *service.Publish
					service.Publish = &copy
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
		{InspectionSummary, true},
		{InspectionDetailed, true},
		{InspectionMode("all"), false},
		{"", false},
	} {
		if got := test.mode.Valid(); got != test.valid {
			t.Errorf("mode %q valid = %t, want %t", test.mode, got, test.valid)
		}
	}
}

func TestInspectionRetentionAndByteSizeValidation(t *testing.T) {
	for _, test := range []struct {
		value string
		valid bool
	}{
		{"1MiB", true}, {"64MiB", true}, {"1GiB", true},
		{"1000KiB", false}, {"2GiB", false}, {"1 MB", false}, {"-1MiB", false},
	} {
		_, err := ParseByteSize(test.value)
		if (err == nil) != test.valid {
			t.Errorf("inspection byte size %q: %v", test.value, err)
		}
	}
	tooLong := Duration(30*24*time.Hour + time.Hour)
	if err := ValidateInspection(&Inspection{Retention: &tooLong}); err == nil {
		t.Fatal("inspection retention exceeded 30 days")
	}
	if err := ValidateInspection(&Inspection{}); err != nil {
		t.Fatalf("partial service override was rejected: %v", err)
	}
}

func TestDetailedInspectionRejectsOpaqueServiceProtocols(t *testing.T) {
	mode := InspectionDetailed
	protocol := "postgres"
	project := TNL{Inspection: &Inspection{Mode: &mode}, Services: Services{"orders": {
		Publish: &Publish{Protocol: &protocol},
	}}}
	if err := ValidateTNL(project); err != nil {
		t.Fatalf("PostgreSQL rejected detailed inspection: %v", err)
	}
	protocol = "mysql"
	if err := ValidateTNL(project); err != nil {
		t.Fatalf("MySQL rejected detailed inspection: %v", err)
	}
	protocol = "redis"
	if err := ValidateTNL(project); err == nil {
		t.Fatal("opaque Redis traffic accepted detailed inspection")
	}
}

func TestStaticFormatsShareTargetIPAndDurationValidation(t *testing.T) {
	for extension, valid := range map[string]string{
		"json": `{"version":1,"tnl":{"inspection":{"mode":"detailed","retention":"168h","max_bytes":"64MiB"},"services":{"web":{"inspection":{"mode":"summary"},"target":{"type":"address","address":3000},"readiness":{"path":"/health"}}},"tunnel":{"allow_ip":["192.0.2.1"]}}}`,
		"yml":  "version: 1\ntnl:\n  inspection: {mode: detailed, retention: 168h, max_bytes: 64MiB}\n  services:\n    web:\n      inspection: {mode: summary}\n      target: {type: address, address: 3000}\n      readiness: {path: /health}\n  tunnel:\n    allow_ip: [192.0.2.1]\n",
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
		"zero concurrency":           {`{"version":1,"tnl":{"tunnel":{"limits":{"http":{"concurrency":0}}}}}`, "version: 1\ntnl:\n  tunnel:\n    limits:\n      http: {concurrency: 0}\n", "tunnel.limits.http total and concurrency must be positive"},
		"negative total":             {`{"version":1,"tnl":{"services":{"web":{"tunnel":{"limits":{"http":{"total":-1}}}}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      tunnel:\n        limits:\n          http: {total: -1}\n", "services.web: tunnel.limits.http total and concurrency must be positive"},
		"missing rate period":        {`{"version":1,"tnl":{"tunnel":{"limits":{"http":{"rate":{"count":2}}}}}}`, "version: 1\ntnl:\n  tunnel:\n    limits:\n      http:\n        rate: {count: 2}\n", "tunnel.limits.http.rate requires positive count and per"},
		"retired request limit":      {`{"version":1,"tnl":{"tunnel":{"request_limit":2}}}`, "version: 1\ntnl:\n  tunnel:\n    request_limit: 2\n", "request_limit"},
		"invalid inspection":         {`{"version":1,"tnl":{"inspection":{"mode":"all"}}}`, "version: 1\ntnl:\n  inspection: {mode: all}\n", "inspection: mode must be summary or detailed"},
		"invalid service inspection": {`{"version":1,"tnl":{"services":{"web":{"inspection":{"mode":"all"}}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      inspection: {mode: all}\n", "services.web.inspection: mode must be summary or detailed"},
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
		"target":                     {`{"version":1,"tnl":{"services":{"web":{"target":{"type":"address","address":"https://example.com/path"}}}}}`, "version: 1\ntnl:\n  services:\n    web:\n      target: {type: address, address: https://example.com/path}\n", "publish.target:"},
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

func TestTrafficLimitsValidateInBothStaticFormats(t *testing.T) {
	for name, source := range map[string]string{
		"tnl.json": `{"version":1,"tnl":{"tunnel":{"limits":{"traffic":{"connections":32,"rate":{"count":20,"per":"1s","burst":40},"bandwidth":{"upload":"8MiB/s","download":"16MiB/s"}}}},"services":{"web":{"target":{"type":"app"},"tunnel":{"limits":{"traffic":{"connections":16}}}},"orders":{"protocol":"postgres","target":{"type":"address","address":"db:5432"}}}}}`,
		"tnl.yml":  "version: 1\ntnl:\n  tunnel:\n    limits:\n      traffic:\n        connections: 32\n        rate: {count: 20, per: 1s, burst: 40}\n        bandwidth: {upload: 8MiB/s, download: 16MiB/s}\n  services:\n    web:\n      target: {type: app}\n      tunnel: {limits: {traffic: {connections: 16}}}\n    orders:\n      protocol: postgres\n      target: {type: address, address: 'db:5432'}\n",
	} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadDocument(path)
		if err != nil || loaded.TNL == nil || loaded.TNL.Tunnel == nil || loaded.TNL.Tunnel.Limits == nil ||
			loaded.TNL.Tunnel.Limits.Traffic == nil || loaded.TNL.Tunnel.Limits.Traffic.Rate == nil ||
			*loaded.TNL.Tunnel.Limits.Traffic.Rate.Count != 20 {
			t.Fatalf("traffic in %s = %+v, %v", name, loaded, err)
		}
	}
	for _, upload := range []string{"0MiB/s", "1MB/s", "32KiB/s"} {
		value := ByteRate(upload)
		if err := ValidateTNL(TNL{Tunnel: &Tunnel{Limits: &Limits{Traffic: &TrafficLimits{
			Bandwidth: &Bandwidth{Upload: &value},
		}}}}); err == nil {
			t.Fatalf("invalid visitor bandwidth %s was accepted", upload)
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
