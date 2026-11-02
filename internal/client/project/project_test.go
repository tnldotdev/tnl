package project

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
  public_url:
    domain: routes.example.test
    access: {ip: [192.0.2.0/24]}
    ephemeral: true
  services:
    web:
      name: website
      public_url:
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
		effective.Tunnel == nil || effective.Tunnel.Name == nil || *effective.Tunnel.Name != "website" ||
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

func TestPublicDefaultsNeverReachPrivateTCPService(t *testing.T) {
	ephemeral := true
	domain, dbTarget := "member.example", config.Target("db.internal:5432")
	tcp := "tcp"
	none := config.InspectionNone
	connections := 4
	project := Project{Config: config.TNL{
		Feedback: &ephemeral, OAuth: true, Inspection: &config.Inspection{Mode: &none},
		Tunnel: &config.Tunnel{Domain: &domain, Access: &config.Access{Mode: "anonymous"}, Ephemeral: &ephemeral,
			Limits: &config.Limits{Traffic: &config.TrafficLimits{Connections: &connections}}},
		Services: config.Services{
			"web":          {Tunnel: &config.Tunnel{}},
			"private-http": {},
			"orders":       {Protocol: &tcp, Target: &config.ServiceTarget{Type: "address", Address: &dbTarget}},
		},
	}}
	if err := config.ValidateTNL(project.Config); err != nil {
		t.Fatalf("mixed HTTP and private TCP project: %v", err)
	}
	for _, name := range []string{"web"} {
		service, err := project.EffectiveService(name)
		if err != nil || service.Tunnel == nil || service.Tunnel.Access == nil || service.Tunnel.Access.VisitorMode() != "anonymous" ||
			service.Tunnel.Domain == nil || *service.Tunnel.Domain != domain || service.Tunnel.Limits == nil ||
			service.Tunnel.Limits.Traffic == nil || service.Tunnel.Limits.Traffic.Connections == nil ||
			*service.Tunnel.Limits.Traffic.Connections != connections {
			t.Fatalf("public %s lost root defaults: %+v: %v", name, service.Tunnel, err)
		}
	}
	private, err := project.EffectiveService("orders")
	if err != nil || private.Tunnel != nil || private.Feedback != nil || private.OAuth || private.Inspection != nil || private.Publish == nil || config.ServiceProtocol(private.Publish) != "tcp" ||
		private.Publish.Target != &dbTarget || config.ServiceName("orders", project.Config.Services["orders"]) != "orders" {
		t.Fatalf("private orders inherited public access or lost target: %+v: %v", private, err)
	}
	if project.Config.Tunnel.Access == nil || project.Config.Tunnel.Access.VisitorMode() != "anonymous" {
		t.Fatal("resolving service mutated public defaults")
	}
	privateHTTP, err := project.EffectiveService("private-http")
	if err != nil || privateHTTP.Tunnel != nil || privateHTTP.OAuth || privateHTTP.Feedback != nil {
		t.Fatalf("private HTTP inherited public defaults: %+v: %v", privateHTTP, err)
	}
	orders := project.Config.Services["orders"]
	orders.Tunnel = &config.Tunnel{Access: &config.Access{Mode: "anonymous"}}
	project.Config.Services["orders"] = orders
	if _, err := project.EffectiveService("orders"); err == nil {
		t.Fatal("private TCP service accepted per-service public access")
	}
}

func TestResolvedServiceSelectsOnlyApplicableProjectDefaults(t *testing.T) {
	name, server, team := "checkout", "https://control.example", "studio"
	feedback := true
	mode, privateMode := config.InspectionSummary, config.InspectionNone
	retention := config.Duration(time.Hour)
	project := Project{Config: config.TNL{
		Server: &server, Team: &team, Feedback: &feedback, OAuth: true,
		Inspection: &config.Inspection{Mode: &mode, Retention: &retention},
		Tunnel:     &config.Tunnel{Access: &config.Access{IP: []string{"192.0.2.0/24"}}},
		Services: config.Services{
			"web": {Tunnel: &config.Tunnel{}},
			"internal": {Inspection: &config.Inspection{Mode: &privateMode},
				HTTP: &config.HTTPService{Readiness: &config.Readiness{Path: "/ready"}}},
		},
		Webhooks: map[string]config.Webhook{"stripe": {Service: "web", Path: "/stripe", Provider: "stripe"}},
	}}
	for _, selected := range []string{"", "web", "internal", "web", ""} {
		settings, err := project.EffectiveService(selected)
		if err != nil {
			t.Fatal(err)
		}
		if settings.Server != &server || settings.Team != &team || settings.Publish == nil {
			t.Fatal("lost shared selection or publication settings", settings)
		}
		if selected == "internal" {
			if settings.Tunnel != nil || settings.Feedback != nil || settings.OAuth || settings.Webhooks != nil ||
				settings.Inspection == nil || settings.Inspection.Mode != &privateMode || settings.Inspection.Retention != nil ||
				settings.Readiness == nil || settings.Readiness.Path != "/ready" {
				t.Fatal("private HTTP service inherited public defaults or lost its own settings", settings)
			}
			continue
		}
		if settings.Tunnel == nil || settings.Tunnel.Access == nil || settings.Tunnel.Access.IP[0] != "192.0.2.0/24" ||
			settings.Feedback != &feedback || !settings.OAuth || len(settings.Webhooks) != 1 ||
			settings.Inspection == nil || settings.Inspection.Retention != &retention || settings.Readiness != nil {
			t.Fatal("public service or root lost project defaults", settings)
		}
		settings.Tunnel.Access.IP[0] = "198.51.100.0/24"
		settings.Inspection.Retention = nil
	}
	if project.Config.Tunnel.Name != nil || project.Config.Tunnel.Access.IP[0] != "192.0.2.0/24" || project.Config.Inspection.Retention != &retention {
		t.Fatal("resolving settings changed the parsed project document")
	}
	named := Project{Config: config.TNL{Name: &name}}
	settings, err := named.EffectiveService("")
	if err != nil || settings.Tunnel == nil || settings.Tunnel.Name == nil || *settings.Tunnel.Name != name || named.Config.Tunnel != nil {
		t.Fatal("root settings lost the unnamed publication's saved name or mutated its declaration", settings, err)
	}
	settings, err = (Project{}).EffectiveService("")
	if err != nil || settings.Name != nil || settings.Tunnel != nil || settings.Publish == nil || settings.Readiness != nil {
		t.Fatal("empty root acquired service-only settings", settings, err)
	}
}

func TestPublisherGroupIsExplicitAndDefaultsToLocal(t *testing.T) {
	group, protocol := "cloud", "postgres"
	target := config.Target("db.internal:5432")
	project := Project{Config: config.TNL{
		PublisherGroups: map[string]config.PublisherGroup{"cloud": {}},
		Services: config.Services{
			"default": {},
			"db":      {PublisherGroup: &group, Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &target}},
		},
	}}
	for _, test := range []struct {
		name     string
		expected string
	}{{"default", "local"}, {"db", "cloud"}} {
		if actual := config.PublisherGroupName(project.Config.Services[test.name]); actual != test.expected {
			t.Fatalf("service %q group=%s", test.name, actual)
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
