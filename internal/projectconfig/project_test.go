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
    allow_ip: [192.0.2.0/24]
    ephemeral: true
  services:
    web:
      tunnel:
        name: web
        allow_all_ips: true
      target: {type: address, address: 4000}
      http:
        readiness: {path: /status}
        open: true
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
		effective.Readiness == nil || effective.Readiness.Path != "/status" {
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
	tcpCount, tcpConcurrency := 10, 8
	address := config.Target("db.internal:5432")
	period := config.Duration(time.Minute)
	override := config.Duration(2 * time.Minute)
	project := Project{Config: config.TNL{
		Tunnel: &config.Tunnel{Limits: &config.Limits{HTTP: &config.WorkLimits{
			Total: &requests, Rate: &config.Rate{Count: &rateRequests, Per: &period}, Concurrency: &concurrency,
		}, TCP: &config.WorkLimits{Rate: &config.Rate{Count: &tcpCount, Per: &period}, Concurrency: &tcpConcurrency}}},
		Services: config.Services{"api": {Tunnel: &config.Tunnel{Limits: &config.Limits{
			HTTP: &config.WorkLimits{Rate: &config.Rate{Per: &override}},
		}}}, "orders": {Protocol: new("postgres"), Target: &config.ServiceTarget{Type: "address", Address: &address}, Tunnel: &config.Tunnel{Limits: &config.Limits{
			TCP: &config.WorkLimits{Rate: &config.Rate{Per: &override}},
		}}}},
	}}
	if err := config.ValidateTNL(project.Config); err != nil {
		t.Fatal(err)
	}
	service, err := project.EffectiveService("api")
	if err != nil {
		t.Fatal(err)
	}
	limits := service.Tunnel.Limits.HTTP
	if limits.Total != &requests || limits.Concurrency != &concurrency || limits.Rate.Count != &rateRequests || limits.Rate.Per != &override {
		t.Fatalf("service limits = %#v", limits)
	}
	if project.Config.Tunnel.Limits.HTTP.Rate.Per != &period {
		t.Fatal("service override changed root rate period")
	}
	tcp, err := project.EffectiveService("orders")
	if err != nil || tcp.Tunnel.Limits.TCP.Rate.Count != &tcpCount || tcp.Tunnel.Limits.TCP.Rate.Per != &override || tcp.Tunnel.Limits.TCP.Concurrency != &tcpConcurrency ||
		tcp.Tunnel.Limits.HTTP.Rate.Per != &period || project.Config.Tunnel.Limits.TCP.Rate.Per != &period {
		t.Fatalf("TCP service inheritance changed a different protocol's defaults: %+v, %v", tcp.Tunnel, err)
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
