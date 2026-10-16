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

func TestMixedPublicDefaultsNeverReachPrivateTCPService(t *testing.T) {
	all, ephemeral := true, true
	domain, dbTarget, sshTarget := "member.example", config.Target("db.internal:5432"), config.Target("22")
	tcp, ssh := "tcp", "ssh"
	connections := 4
	project := Project{Config: config.TNL{
		Tunnel: &config.Tunnel{Domain: &domain, AllowAllIPs: &all, Ephemeral: &ephemeral,
			Limits: &config.Limits{Traffic: &config.TrafficLimits{Connections: &connections}}},
		Services: config.Services{
			"web":    {},
			"orders": {Protocol: &tcp, Target: &config.ServiceTarget{Type: "address", Address: &dbTarget}},
			"shell":  {Protocol: &ssh, Target: &config.ServiceTarget{Type: "address", Address: &sshTarget}},
		},
	}}
	if err := config.ValidateTNL(project.Config); err != nil {
		t.Fatalf("mixed HTTP, SSH and private TCP project: %v", err)
	}
	for _, name := range []string{"web", "shell"} {
		service, err := project.EffectiveService(name)
		if err != nil || service.Tunnel == nil || service.Tunnel.AllowAllIPs == nil || !*service.Tunnel.AllowAllIPs ||
			service.Tunnel.Domain == nil || *service.Tunnel.Domain != domain || service.Tunnel.Limits == nil ||
			service.Tunnel.Limits.Traffic == nil || service.Tunnel.Limits.Traffic.Connections == nil ||
			*service.Tunnel.Limits.Traffic.Connections != connections {
			t.Fatalf("public %s lost root defaults: %+v: %v", name, service.Tunnel, err)
		}
	}
	private, err := project.EffectiveService("orders")
	if err != nil || private.Tunnel != nil || private.Publish == nil || config.ServiceProtocol(private.Publish) != "tcp" ||
		private.Publish.Target != &dbTarget || config.PrivateServiceName("orders", project.Config.Services["orders"]) != "orders" {
		t.Fatalf("private orders inherited public access or lost target: %+v: %v", private, err)
	}
	if project.Config.Tunnel.AllowAllIPs == nil || !*project.Config.Tunnel.AllowAllIPs {
		t.Fatal("resolving private service mutated public defaults")
	}
	orders := project.Config.Services["orders"]
	orders.Tunnel = &config.Tunnel{AllowAllIPs: &all}
	project.Config.Services["orders"] = orders
	if _, err := project.EffectiveService("orders"); err == nil {
		t.Fatal("private TCP service accepted per-service public access")
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
