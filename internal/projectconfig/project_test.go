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
    access: {ip: [192.0.2.0/24]}
    ephemeral: true
  services:
    web:
      tunnel:
        name: web
        access: anonymous
      target: {type: address, address: 4000}
      http:
        open: true
        readiness: {path: /status}
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
		effective.Tunnel.Access == nil || effective.Tunnel.Access.VisitorMode() != "anonymous" || len(effective.Tunnel.Access.IP) != 0 ||
		effective.Tunnel.Ephemeral == nil || !*effective.Tunnel.Ephemeral ||
		effective.Publish == nil || effective.Publish.Target == nil || string(*effective.Publish.Target) != "4000" ||
		effective.Readiness == nil || effective.Readiness.Path != "/status" {
		t.Fatalf("effective service = %#v", effective)
	}
	if _, err := project.EffectiveService("missing"); err == nil {
		t.Fatal("missing service was accepted")
	}
}

func TestServiceAccessPolicyReplacesProjectDefault(t *testing.T) {
	project := Project{Config: config.TNL{
		Tunnel: &config.Tunnel{Access: &config.Access{IP: []string{"192.0.2.1"}}},
		Services: config.Services{
			"api":    {Tunnel: &config.Tunnel{Access: &config.Access{IP: []string{"198.51.100.1"}}}},
			"none":   {Tunnel: &config.Tunnel{Access: &config.Access{Mode: "restricted"}}},
			"public": {Tunnel: &config.Tunnel{Access: &config.Access{Mode: "anonymous"}}},
		},
	}}
	for _, test := range []struct {
		name string
		want []string
		mode string
	}{
		{"api", []string{"198.51.100.1"}, "restricted"},
		{"none", nil, "restricted"},
		{"public", nil, "anonymous"},
	} {
		effective, err := project.EffectiveService(test.name)
		if err != nil || effective.Tunnel == nil || effective.Tunnel.Access == nil || !slices.Equal(effective.Tunnel.Access.IP, test.want) ||
			effective.Tunnel.Access.VisitorMode() != test.mode {
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
			HTTP: &config.WorkLimits{Total: &requests, Rate: &config.Rate{Count: &rateRequests, Per: &period}, Concurrency: &concurrency},
		}},
		Services: config.Services{"api": {Tunnel: &config.Tunnel{Limits: &config.Limits{
			HTTP: &config.WorkLimits{Rate: &config.Rate{Per: &override}},
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
}
