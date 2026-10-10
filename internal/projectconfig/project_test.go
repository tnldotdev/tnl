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
  readiness:
    path: /health
    status: 204
  services:
    web:
      tunnel:
        name: web
        allow_all_ips: true
      publish:
        target: 4000
      readiness:
        path: /status
        status: 200
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
		effective.Team == nil || *effective.Team != "Root Team" ||
		effective.Tunnel == nil || effective.Tunnel.Name == nil || *effective.Tunnel.Name != "web" ||
		effective.Tunnel.Domain == nil || *effective.Tunnel.Domain != "routes.example.test" ||
		effective.Tunnel.Open == nil || !*effective.Tunnel.Open ||
		effective.Tunnel.AllowAllIPs == nil || !*effective.Tunnel.AllowAllIPs || effective.Tunnel.AllowIP != nil ||
		effective.Tunnel.Ephemeral == nil || !*effective.Tunnel.Ephemeral ||
		effective.Publish == nil || effective.Publish.Target == nil || string(*effective.Publish.Target) != "4000" ||
		effective.Readiness == nil || effective.Readiness.Path != "/status" || effective.Readiness.Status == nil || *effective.Readiness.Status != 200 {
		t.Fatalf("effective service = %#v", effective)
	}
	if _, err := project.EffectiveService("missing"); err == nil {
		t.Fatal("missing service was accepted")
	}
}

func TestServiceIPOverridesAndAllowAllIPs(t *testing.T) {
	all := true
	project := Project{Config: config.TNL{
		Tunnel: &config.Tunnel{AllowIP: []string{"192.0.2.1"}},
		Services: config.Services{
			"api":    {Tunnel: &config.Tunnel{AllowIP: []string{"198.51.100.1"}}},
			"none":   {Tunnel: &config.Tunnel{AllowIP: []string{}}},
			"public": {Tunnel: &config.Tunnel{AllowAllIPs: &all}},
		},
	}}
	for _, test := range []struct {
		name string
		want []string
		all  bool
	}{
		{"api", []string{"198.51.100.1"}, false},
		{"none", []string{}, false},
		{"public", nil, true},
	} {
		effective, err := project.EffectiveService(test.name)
		if err != nil || effective.Tunnel == nil || !slices.Equal(effective.Tunnel.AllowIP, test.want) ||
			(effective.Tunnel.AllowIP == nil) != (test.want == nil) ||
			(effective.Tunnel.AllowAllIPs != nil && *effective.Tunnel.AllowAllIPs) != test.all {
			t.Fatalf("service %s: tunnel = %#v, error = %v", test.name, effective.Tunnel, err)
		}
	}
}

func TestServiceLimitsOverrideEachFieldWithoutChangingRoot(t *testing.T) {
	requests, rateRequests, concurrency := 20, 5, 3
	period := config.Duration(time.Minute)
	override := config.Duration(2 * time.Minute)
	project := Project{Config: config.TNL{
		Tunnel: &config.Tunnel{Limits: &config.Limits{
			Requests: &requests, Rate: &config.Rate{Requests: &rateRequests, Per: &period}, Concurrency: &concurrency,
		}},
		Services: config.Services{"api": {Tunnel: &config.Tunnel{Limits: &config.Limits{
			Rate: &config.Rate{Per: &override},
		}}}},
	}}
	if err := config.ValidateTNL(project.Config); err != nil {
		t.Fatal(err)
	}
	service, err := project.EffectiveService("api")
	if err != nil {
		t.Fatal(err)
	}
	limits := service.Tunnel.Limits
	if limits.Requests != &requests || limits.Concurrency != &concurrency || limits.Rate.Requests != &rateRequests || limits.Rate.Per != &override {
		t.Fatalf("service limits = %#v", limits)
	}
	if project.Config.Tunnel.Limits.Rate.Per != &period {
		t.Fatal("service override changed root rate period")
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
