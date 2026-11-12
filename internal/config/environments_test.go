package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestEnvironmentConfigurationAcrossStaticFormats(t *testing.T) {
	configuration := `{"services":{"web":{},"api":{},"database":{"protocol":"postgres"}},"environments":{"local":{"server":"https://local-control.example","targets":{"web":{"public_url":{},"http":{"readiness":{"path":"/health"},"paths":{"/api":{"service":"api","strip_prefix":true}}}},"api":{"address":4000},"database":{"address":"127.0.0.1:5432"}}},"staging":{"server":"https://staging-control.example","targets":{"web":{"address":3000},"api":{"address":4000},"database":{"address":"db.staging.internal:5432","tls":{}}},"workloads":{"accounts":{"vercel":{"project":"tnl-accounts-staging","environment":"production"},"visit":["database"]}}},"production":{"targets":{"web":{"address":3000},"api":{"address":4000},"database":{"address":"db.production.internal:5432","tls":{"hostname":"database.internal","ca_file":"certs/ca.pem"}}}}},"collections":{"customers":{}},"aliases":{"review":{"service":"web"}}}`
	var value map[string]any
	if err := json.Unmarshal([]byte(configuration), &value); err != nil {
		t.Fatal(err)
	}
	document := map[string]any{"version": 1, "tnl": value}
	for _, extension := range []string{"json", "yaml"} {
		t.Run(extension, func(t *testing.T) {
			var data []byte
			var err error
			if extension == "json" {
				data, err = json.Marshal(document)
			} else {
				data, err = yaml.Marshal(document)
			}
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "tnl."+extension)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			parsed, err := LoadDocument(path)
			if err != nil {
				t.Fatal(err)
			}
			c := *parsed.TNL
			if c.Services["database"].Target != nil || c.Services["web"].Tunnel != nil {
				t.Fatal("logical service acquired environment authority")
			}
			if string(*c.Environments["staging"].Targets["database"].Address) != "db.staging.internal:5432" || c.Environments["staging"].Targets["database"].TLS == nil || c.Environments["staging"].Workloads["accounts"].Services[0] != "database" {
				t.Fatal("staging target, TLS or explicit visitor allowlist lost")
			}
			local := LocalServices(c)
			if string(*local["database"].Target.Address) != "127.0.0.1:5432" || local["web"].Tunnel == nil || local["web"].HTTP.Readiness.Path != "/health" || !local["web"].HTTP.Paths["/api"].StripPrefix {
				t.Fatal("local listener or preview features lost")
			}
			encoded, err := json.Marshal(c.Services)
			if err != nil || strings.Contains(string(encoded), "address") || strings.Contains(string(encoded), "tls") || strings.Contains(string(encoded), "workload") {
				t.Fatalf("definition contains authority: %s: %v", encoded, err)
			}
		})
	}
}

func TestEnvironmentConfigurationRejectsCrossBoundaryAuthority(t *testing.T) {
	for name, configuration := range map[string]string{
		"root target":                 `{"services":{"database":{"protocol":"postgres","target":{"type":"address","address":5432}}}}`,
		"root public URL":             `{"services":{"web":{"public_url":{}}}}`,
		"root workload":               `{"workloads":{"accounts":{"fly":{"app":"accounts"},"visit":["database"]}}}`,
		"workload services alias":     `{"services":{"database":{"protocol":"postgres"}},"environments":{"staging":{"targets":{"database":{"address":5432}},"workloads":{"accounts":{"fly":{"app":"accounts"},"services":["database"]}}}}}`,
		"definition template":         `{"collections":{"customers":{"services":{"database":{"protocol":"postgres"}}}}}`,
		"missing destination":         `{"services":{"database":{"protocol":"postgres"}},"environments":{"staging":{"targets":{"database":{}}}}}`,
		"missing service":             `{"services":{"database":{"protocol":"postgres"}},"environments":{"staging":{"targets":{}}}}`,
		"unknown target":              `{"services":{"database":{"protocol":"postgres"}},"environments":{"staging":{"targets":{"missing":{"address":5432}}}}}`,
		"mixed destination":           `{"services":{"database":{"protocol":"postgres"}},"environments":{"staging":{"targets":{"database":{"address":5432,"discovery":{"type":"rds","region":"us-east-1","instance":"orders"}}}}}}`,
		"provider TLS override":       `{"services":{"database":{"protocol":"postgres"}},"environments":{"staging":{"targets":{"database":{"discovery":{"type":"rds","region":"us-east-1","instance":"orders"},"tls":{}}}}}}`,
		"remote readiness":            `{"services":{"web":{}},"environments":{"staging":{"targets":{"web":{"address":3000,"http":{"readiness":{"path":"/health"}}}}}}}`,
		"remote public URL":           `{"services":{"web":{}},"environments":{"staging":{"targets":{"web":{"address":3000,"public_url":{}}}}}}`,
		"unknown visit":               `{"services":{"database":{"protocol":"postgres"}},"environments":{"staging":{"targets":{"database":{"address":5432}},"workloads":{"accounts":{"fly":{"app":"accounts"},"visit":["missing"]}}}}}`,
		"local workload":              `{"services":{"database":{"protocol":"postgres"}},"environments":{"local":{"targets":{"database":{"address":5432}},"workloads":{"accounts":{"fly":{"app":"accounts"},"visit":["database"]}}}}}`,
		"insecure environment server": `{"environments":{"staging":{"server":"http://control.example"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal([]byte(configuration), &value); err != nil {
				t.Fatal(err)
			}
			for _, extension := range []string{"json", "yaml"} {
				document := map[string]any{"version": 1, "tnl": value}
				var data []byte
				if extension == "json" {
					data, _ = json.Marshal(document)
				} else {
					data, _ = yaml.Marshal(document)
				}
				path := filepath.Join(t.TempDir(), "tnl."+extension)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := LoadDocument(path); err == nil {
					t.Fatalf("%s accepted cross-boundary authority", extension)
				}
			}
		})
	}
}
