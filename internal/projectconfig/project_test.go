package projectconfig

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestServicesShareOneModelAndInheritRootDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tnl.yml")
	contents := `version: 1
tnl:
  server: https://root.example
  team: Root Team
  tunnel:
    domain: routes.example.test
    open: true
    allow_ip: [192.0.2.0/24]
    ephemeral: true
  publish:
    target: 3000
  dev:
    command: [pnpm, dev]
    startup_timeout: 30s
  services:
    web:
      team: Web Team
      tunnel:
        name: web
        allow_all_ips: true
      publish:
        target: 4000
      dev:
        startup_timeout: 45s
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := config.LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	project := Project{Config: *document.TNL}
	effective, err := project.EffectiveService("web")
	if err != nil {
		t.Fatal(err)
	}
	if effective.Server == nil || *effective.Server != "https://root.example" ||
		effective.Team == nil || *effective.Team != "Web Team" ||
		effective.Tunnel == nil || effective.Tunnel.Name == nil || *effective.Tunnel.Name != "web" ||
		effective.Tunnel.Domain == nil || *effective.Tunnel.Domain != "routes.example.test" ||
		effective.Tunnel.Open == nil || !*effective.Tunnel.Open ||
		effective.Tunnel.AllowAllIPs == nil || !*effective.Tunnel.AllowAllIPs || effective.Tunnel.AllowIP != nil ||
		effective.Tunnel.Ephemeral == nil || !*effective.Tunnel.Ephemeral ||
		effective.Publish == nil || effective.Publish.Target == nil || string(*effective.Publish.Target) != "4000" ||
		effective.Dev == nil || effective.Dev.StartupTimeout == nil || effective.Dev.StartupTimeout.Value() != 45*time.Second ||
		len(effective.Dev.Command) != 2 {
		t.Fatalf("effective service = %#v", effective)
	}
	if _, err := project.EffectiveService("missing"); err == nil {
		t.Fatal("missing service was accepted")
	}
}

func TestServiceProviderOverridesAndAllowAllIPs(t *testing.T) {
	all := true
	project := Project{Config: config.TNL{
		Tunnel: &config.Tunnel{AllowProviders: []string{"stripe"}, AllowIP: []string{"192.0.2.1"}},
		Services: config.Services{
			"api":    {Tunnel: &config.Tunnel{AllowProviders: []string{"github"}}},
			"none":   {Tunnel: &config.Tunnel{AllowProviders: []string{}}},
			"public": {Tunnel: &config.Tunnel{AllowAllIPs: &all}},
		},
	}}
	for _, test := range []struct {
		name string
		want []string
		all  bool
	}{
		{"api", []string{"github"}, false},
		{"none", []string{}, false},
		{"public", nil, true},
	} {
		effective, err := project.EffectiveService(test.name)
		if err != nil || effective.Tunnel == nil || !slices.Equal(effective.Tunnel.AllowProviders, test.want) ||
			(effective.Tunnel.AllowProviders == nil) != (test.want == nil) ||
			(effective.Tunnel.AllowAllIPs != nil && *effective.Tunnel.AllowAllIPs) != test.all {
			t.Fatalf("service %s: tunnel = %#v, error = %v", test.name, effective.Tunnel, err)
		}
	}
}

func TestServiceDirectoryRejectsTraversalAndSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	for name, directory := range map[string]string{
		"absolute":  outside,
		"traversal": "apps/../web",
		"nul":       "web\x00app",
		"symlink":   "outside",
	} {
		t.Run(name, func(t *testing.T) {
			value := config.TNL{Services: config.Services{"web": {Directory: &directory}}}
			if err := config.ValidateTNL(value); err == nil {
				if _, _, err := (Project{Config: value, Root: root}).ServiceDirectory("web"); err == nil {
					t.Fatalf("directory %q was accepted", directory)
				}
			}
		})
	}
	directory := "."
	project := Project{Config: config.TNL{Services: config.Services{"web": {Directory: &directory}}}, Root: root}
	resolved, relative, err := project.ServiceDirectory("web")
	if err != nil || resolved != root || relative != "." {
		t.Fatalf("default directory = %q, %q, %v", resolved, relative, err)
	}
}
