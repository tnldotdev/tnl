package projectconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceReferencesAgreeForStaticAndTypeScript(t *testing.T) {
	for _, test := range []struct {
		name, static, typescript string
		valid                    bool
	}{
		{"public local alias", `"services":{"web":{"public_url":{}}},"aliases":{"review":{"service":"web"}}`, `services: {web: {publicURL: {}}}, aliases: {review: {service: "web"}}`, true},
		{"private alias", `"services":{"web":{}},"aliases":{"review":{"service":"web"}}`, `services: {web: {}}, aliases: {review: {service: "web"}}`, false},
		{"group alias", `"publishers":{"cloud":{}},"services":{"web":{"publisher":"cloud","public_url":{},"target":{"type":"address","address":3000}}},"aliases":{"review":{"service":"web"}}`, `publishers: {cloud: {}}, services: {web: {publisher: "cloud", publicURL: {}, target: {type: "address", address: 3000}}}, aliases: {review: {service: "web"}}`, false},
		{"implicit local workload", `"services":{"web":{}},"workloads":{"ci":{"provider":"fly","org":"acme","org_id":"1","app":"web","app_id":"2","services":["web"]}}`, `services: {web: {}}, workloads: {ci: {provider: "fly", org: "acme", orgId: "1", app: "web", appId: "2", services: ["web"]}}`, false},
		{"explicit local workload", `"services":{"web":{"publisher":"local"}},"workloads":{"ci":{"provider":"fly","org":"acme","org_id":"1","app":"web","app_id":"2","services":["web"]}}`, `services: {web: {publisher: "local"}}, workloads: {ci: {provider: "fly", org: "acme", orgId: "1", app: "web", appId: "2", services: ["web"]}}`, false},
		{"group workload", `"publishers":{"cloud":{}},"services":{"web":{"publisher":"cloud","target":{"type":"address","address":3000}}},"workloads":{"ci":{"provider":"fly","org":"acme","org_id":"1","app":"web","app_id":"2","services":["web"]}}`, `publishers: {cloud: {}}, services: {web: {publisher: "cloud", target: {type: "address", address: 3000}}}, workloads: {ci: {provider: "fly", org: "acme", orgId: "1", app: "web", appId: "2", services: ["web"]}}`, true},
	} {
		for _, file := range []struct{ name, source string }{
			{"tnl.json", `{"version":1,"tnl":{` + test.static + `}}`},
			{"tnl.config.ts", `export default () => ({` + test.typescript + `});`},
		} {
			t.Run(test.name+"/"+file.name, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, file.name)
				if err := os.WriteFile(path, []byte(file.source), 0600); err != nil {
					t.Fatal(err)
				}
				_, err := Resolve(t.Context(), Selection{Path: path}, root, [32]byte{})
				if (err == nil) != test.valid {
					t.Fatalf("valid=%t, load error: %v", test.valid, err)
				}
			})
		}
	}
}
