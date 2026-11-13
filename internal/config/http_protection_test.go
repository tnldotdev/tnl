package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
)

func TestHTTPProtectionStaticConfiguration(t *testing.T) {
	for name, source := range map[string]string{
		"tnl.json": `{"version":1,"tnl":{"services":{"app":{"public_url":{},"http":{"protection":{"waf":"detect","max_body_bytes":2048,"exclusions":[{"rule_id":942100,"path":"/search","parameter":"q"}]}}}}}}`,
		"tnl.yml":  "version: 1\ntnl:\n  services:\n    app:\n      public_url: {}\n      http:\n        protection:\n          waf: detect\n          max_body_bytes: 2048\n          exclusions:\n            - rule_id: 942100\n              path: /search\n              parameter: q\n",
	} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		doc, err := LoadDocument(path)
		if err != nil {
			t.Fatal(err)
		}
		p := ServiceProtection(doc.TNL.Services["app"])
		if p.WAF != httpprotection.Detect || p.MaxBodyBytes == nil || *p.MaxBodyBytes != 2048 || len(p.Exclusions) != 1 || p.Exclusions[0].RuleID != 942100 {
			t.Fatal("lost protection settings", p)
		}
	}
	for _, protocol := range []string{"tcp", "postgres", "mysql", "kubernetes"} {
		if err := ValidateTNL(TNL{Services: Services{"app": {Protocol: &protocol, HTTP: &HTTPService{Protection: &httpprotection.Settings{}}}}}); err == nil {
			t.Fatal("accepted HTTP protection on", protocol)
		}
	}
}
