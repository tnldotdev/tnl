package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProjectConfigurationRejectsRemoteManagementFields(t *testing.T) {
	for name, document := range map[string]string{
		"groups.json":  `{"version":1,"tnl":{"publisher_groups":{"customer":{"template":true}}}}`,
		"group.json":   `{"version":1,"tnl":{"services":{"db":{"publisher_group":"customer","protocol":"postgres","target":{"type":"address","address":"db.internal:5432"}}}}}`,
		"binding.json": `{"version":1,"tnl":{"services":{"db":{"target_binding":"fixed","protocol":"postgres","target":{"type":"address","address":"db.internal:5432"}}}}}`,
		"groups.yaml":  "version: 1\ntnl:\n  publisher_groups:\n    customer:\n      template: true\n",
		"group.yaml":   "version: 1\ntnl:\n  services:\n    db:\n      publisher_group: customer\n",
		"binding.yaml": "version: 1\ntnl:\n  services:\n    db:\n      target_binding: group\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte(document), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadDocument(path); err == nil {
				t.Fatal("removed remote management field was accepted")
			}
		})
	}
}
