package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
)

func TestHTTPProtectionChallengeStaticConfiguration(t *testing.T) {
	for _, value := range []string{`"turnstile"`, `false`, `true`, `"false"`, `null`, `1`, `{}`} {
		for _, name := range []string{"tnl.json", "tnl.yml"} {
			t.Run(name+"/"+value, func(t *testing.T) {
				source := `{"version":1,"tnl":{"services":{"app":{"public_url":{},"http":{"protection":{"challenge":` + value + `}}}}}}`
				if strings.HasSuffix(name, ".yml") {
					source = "version: 1\ntnl:\n  services:\n    app:\n      public_url: {}\n      http:\n        protection:\n          challenge: " + value + "\n"
				}
				path := filepath.Join(t.TempDir(), name)
				if err := os.WriteFile(path, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				document, err := LoadDocument(path)
				valid := value == `"turnstile"` || value == `false`
				if (err == nil) != valid {
					t.Fatal("challenge configuration acceptance differs from its contract", err)
				}
				if valid {
					want := httpprotection.Challenge("")
					if value == `"turnstile"` {
						want = httpprotection.Turnstile
					}
					if got := ServiceProtection(document.TNL.Services["app"]).Challenge; got != want {
						t.Fatal("lost challenge setting", got)
					}
				}
			})
		}
	}
}

func TestHTTPProtectionStaticConfiguration(t *testing.T) {
	for name, source := range map[string]string{
		"tnl.json": `{"version":1,"tnl":{"services":{"app":{"public_url":{},"http":{"protection":{"waf":"detect","temporary_blocks":true,"challenge":"turnstile","max_body_bytes":2048,"exclusions":[{"rule_id":942100,"path":"/search","parameter":"q"}]}}}}}}`,
		"tnl.yml":  "version: 1\ntnl:\n  services:\n    app:\n      public_url: {}\n      http:\n        protection:\n          waf: detect\n          temporary_blocks: true\n          challenge: turnstile\n          max_body_bytes: 2048\n          exclusions:\n            - rule_id: 942100\n              path: /search\n              parameter: q\n",
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
		if p.WAF != httpprotection.Detect || !p.TemporaryBlocks || p.Challenge != httpprotection.Turnstile || p.MaxBodyBytes == nil || *p.MaxBodyBytes != 2048 || len(p.Exclusions) != 1 || p.Exclusions[0].RuleID != 942100 {
			t.Fatal("lost protection settings", p)
		}
	}
	for _, protocol := range []string{"tcp", "postgres", "mysql", "kubernetes"} {
		if err := ValidateTNL(TNL{Services: Services{"app": {Protocol: &protocol, HTTP: &HTTPService{Protection: &httpprotection.Settings{}}}}}); err == nil {
			t.Fatal("accepted HTTP protection on", protocol)
		}
	}
}
