package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposeNamedTargetValidation(t *testing.T) {
	for _, protocol := range []string{"http", "postgres", "ssh"} {
		project, file, service, port := "my_worktree", "deploy/compose.yaml", "db", 5432
		target := &ServiceTarget{Type: "compose", Project: &project, File: &file, Service: &service, Port: &port}
		configuration := TNL{Services: Services{"db": {Protocol: &protocol, Target: target}}}
		if err := ValidateTNL(configuration); err != nil {
			t.Fatalf("%s Compose service: %v", protocol, err)
		}
		for _, invalid := range []struct {
			name string
			edit func(*ServiceTarget)
		}{
			{"missing project", func(v *ServiceTarget) { v.Project = nil }},
			{"invalid project", func(v *ServiceTarget) { bad := "UPPER"; v.Project = &bad }},
			{"traversal", func(v *ServiceTarget) { bad := "../other.yaml"; v.File = &bad }},
			{"missing file", func(v *ServiceTarget) { v.File = nil }},
			{"missing service", func(v *ServiceTarget) { v.Service = nil }},
			{"invalid port", func(v *ServiceTarget) { bad := 65536; v.Port = &bad }},
			{"address", func(v *ServiceTarget) { address := Target("1234"); v.Address = &address }},
			{"TLS", func(v *ServiceTarget) { v.TLS = &TargetTLS{} }},
		} {
			t.Run(protocol+"/"+invalid.name, func(t *testing.T) {
				copy := *target
				invalid.edit(&copy)
				configuration.Services["db"] = Service{Protocol: &protocol, Target: &copy}
				if err := ValidateTNL(configuration); err == nil || !strings.Contains(err.Error(), "services.db.target") {
					t.Fatalf("invalid Compose target: %v", err)
				}
			})
		}
	}
}

func TestLoadComposeTargetFromYAMLAndJSON(t *testing.T) {
	for name, document := range map[string]string{
		"tnl.yml":  "version: 1\ntnl:\n  services:\n    db:\n      protocol: redis\n      target:\n        type: compose\n        project: my_worktree\n        file: deploy/compose.yaml\n        service: cache\n        port: 6379\n",
		"tnl.json": `{"version":1,"tnl":{"services":{"db":{"protocol":"redis","target":{"type":"compose","project":"my_worktree","file":"deploy/compose.yaml","service":"cache","port":6379}}}}}`,
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
			if selected == nil || selected.Type != "compose" || *selected.Port != 6379 || *selected.Project != "my_worktree" {
				t.Fatalf("decoded target = %+v", selected)
			}
		})
	}
}
