package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerContainerNamedTargetValidation(t *testing.T) {
	for _, protocol := range []string{"http", "postgres", "ssh"} {
		container, port := "db-dev", 5432
		selected := &ServiceTarget{Type: "docker", Container: &container, Port: &port}
		configuration := TNL{Services: Services{"db": {Protocol: &protocol, Target: selected}}}
		if err := ValidateTNL(configuration); err != nil {
			t.Fatalf("%s Docker service: %v", protocol, err)
		}
		for _, invalid := range []struct {
			name string
			edit func(*ServiceTarget)
		}{
			{"missing container", func(v *ServiceTarget) { v.Container = nil }},
			{"option as container", func(v *ServiceTarget) { value := "--all"; v.Container = &value }},
			{"container with whitespace", func(v *ServiceTarget) { value := "db dev"; v.Container = &value }},
			{"port missing", func(v *ServiceTarget) { v.Port = nil }},
			{"port zero", func(v *ServiceTarget) { value := 0; v.Port = &value }},
			{"port overflow", func(v *ServiceTarget) { value := 65536; v.Port = &value }},
			{"compose project", func(v *ServiceTarget) { value := "other"; v.Project = &value }},
			{"compose file", func(v *ServiceTarget) { value := "compose.yaml"; v.File = &value }},
			{"compose service", func(v *ServiceTarget) { value := "db"; v.Service = &value }},
			{"address", func(v *ServiceTarget) { value := Target("3000"); v.Address = &value }},
			{"tls", func(v *ServiceTarget) { v.TLS = &TargetTLS{} }},
		} {
			t.Run(protocol+"/"+invalid.name, func(t *testing.T) {
				copy := *selected
				invalid.edit(&copy)
				configuration.Services["db"] = Service{Protocol: &protocol, Target: &copy}
				if err := ValidateTNL(configuration); err == nil || !strings.Contains(err.Error(), "services.db.target") {
					t.Fatalf("invalid Docker target: %v", err)
				}
			})
		}
	}
	for _, invalid := range []struct{ name, typeName string }{
		{"compose", "compose"}, {"address", "address"}, {"app", "app"},
	} {
		t.Run(invalid.name+" rejects container", func(t *testing.T) {
			name := "db-dev"
			configuration := TNL{Services: Services{"db": {Target: &ServiceTarget{Type: invalid.typeName, Container: &name}}}}
			if err := ValidateTNL(configuration); err == nil || !strings.Contains(err.Error(), "services.db.target") {
				t.Fatalf("accepted Docker container field under %s: %v", invalid.typeName, err)
			}
		})
	}
}

func TestLoadDockerContainerTargetFromYAMLAndJSON(t *testing.T) {
	for name, document := range map[string]string{
		"tnl.yml":  "version: 1\ntnl:\n  services:\n    db:\n      protocol: redis\n      target:\n        type: docker\n        container: cache-dev\n        port: 6379\n",
		"tnl.json": `{"version":1,"tnl":{"services":{"db":{"protocol":"redis","target":{"type":"docker","container":"cache-dev","port":6379}}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte(document), 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadDocument(path)
			if err != nil {
				t.Fatal(err)
			}
			selected := loaded.TNL.Services["db"].Target
			if selected == nil || selected.Type != "docker" || *selected.Container != "cache-dev" || *selected.Port != 6379 {
				t.Fatalf("decoded target = %+v", selected)
			}
		})
	}
}
