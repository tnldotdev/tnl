package project

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestEffectiveServiceNormalizesOnlyItsOwnedAccess(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "invalid-after-access"}[invalid], func(t *testing.T) {
			raw := []string{"198.51.100.9", "192.0.2.7/24", "::ffff:192.0.2.8/120"}
			access := &config.Access{IP: slices.Clone(raw)}
			http := &config.HTTPService{Access: access}
			if invalid {
				http.Limits = &config.WorkLimits{Concurrency: new(0)}
			}
			project := Project{Config: config.TNL{Services: config.Services{
				"api": {HTTP: http}, "web": {HTTP: &config.HTTPService{Access: access}},
			}}}
			before, err := json.Marshal(project.Config)
			if err != nil {
				t.Fatal(err)
			}
			effective, err := project.EffectiveService("api")
			if (err != nil) != invalid {
				t.Fatalf("effective service error=%v, invalid=%t", err, invalid)
			}
			after, err := json.Marshal(project.Config)
			if err != nil || string(before) != string(after) || !slices.Equal(access.IP, raw) {
				t.Fatalf("resolving wrote through source/sibling access: before=%s after=%s error=%v", before, after, err)
			}
			if invalid {
				return
			}
			want := []string{"192.0.2.0/24", "198.51.100.9/32"}
			if effective.HTTP.Access == access || !slices.Equal(effective.HTTP.Access.IP, want) || effective.HTTP.Access.VisitorMode() != "restricted" {
				t.Fatal("effective service did not own its normalized restricted policy", effective.HTTP.Access)
			}
			effective.HTTP.Access.IP[0] = "203.0.113.0/24"
			sibling, err := project.EffectiveService("web")
			if err != nil || !slices.Equal(sibling.HTTP.Access.IP, want) || !slices.Equal(access.IP, raw) {
				t.Fatal("resolved output changed source or sibling policy", sibling.HTTP, access, err)
			}
		})
	}
}

func TestServicesShareOneModelAndSelectTheirOwnSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tnl.yml")
	contents := `version: 1
tnl:
  name: invocation
  server: https://root.example
  team: Root Team
  services:
    web: {}
  deployments:
    local:
      targets:
        web:
          name: website
          domain: routes.example.test
          ephemeral: true
          address: 4000
          http:
            access: anonymous
            open: true
            readiness: {path: /status}
`
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	document, err := config.LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := config.ResolveDeployment(*document.TNL, "local")
	if err != nil {
		t.Fatal(err)
	}
	project := Project{Config: selected}
	effective, err := project.EffectiveService("web")
	if err != nil {
		t.Fatal(err)
	}
	if effective.Server == nil || *effective.Server != "https://root.example" || effective.Team == nil || *effective.Team != "Root Team" ||
		effective.Name == nil || *effective.Name != "website" || effective.Domain == nil || *effective.Domain != "routes.example.test" ||
		effective.HTTP == nil || effective.HTTP.Open == nil || !*effective.HTTP.Open || effective.HTTP.Access.VisitorMode() != "anonymous" || len(effective.HTTP.Access.IP) != 0 ||
		effective.Ephemeral == nil || !*effective.Ephemeral || effective.Publish == nil || effective.Publish.Target == nil || string(*effective.Publish.Target) != "4000" ||
		effective.HTTP.Readiness == nil || effective.HTTP.Readiness.Path != "/status" {
		t.Fatalf("effective service = %#v", effective)
	}
	root, err := project.EffectiveService("")
	if err != nil || root.Name == nil || *root.Name != "invocation" || root.Domain != nil || root.HTTP != nil || root.Ephemeral != nil {
		t.Fatal("unnamed invocation borrowed a binding's endpoint or HTTP settings", root, err)
	}
	if _, err := project.EffectiveService("missing"); err == nil {
		t.Fatal("missing service was accepted")
	}
}

func TestServiceAccessPolicyIsIndependentForEachBinding(t *testing.T) {
	project := Project{Config: config.TNL{Services: config.Services{
		"api":    {HTTP: &config.HTTPService{Access: &config.Access{IP: []string{"198.51.100.1"}}}},
		"none":   {HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted"}}},
		"public": {HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}},
	}}}
	for _, test := range []struct {
		name string
		want []string
		mode string
	}{{"api", []string{"198.51.100.1/32"}, "restricted"}, {"none", nil, "restricted"}, {"public", nil, "anonymous"}} {
		effective, err := project.EffectiveService(test.name)
		if err != nil || effective.HTTP == nil || effective.HTTP.Access == nil || !slices.Equal(effective.HTTP.Access.IP, test.want) || effective.HTTP.Access.VisitorMode() != test.mode || effective.Public != nil {
			t.Fatalf("service %s: HTTP=%#v, error=%v", test.name, effective.HTTP, err)
		}
	}
	if !slices.Equal(project.Config.Services["api"].HTTP.Access.IP, []string{"198.51.100.1"}) {
		t.Fatal("binding selection changed its source policy")
	}
}

func TestHTTPSettingsNeverReachAnotherService(t *testing.T) {
	dbTarget := config.Target("db.internal:5432")
	project := Project{Config: config.TNL{
		Feedback: new(true), OAuth: true, Inspection: &config.Inspection{Mode: new(config.InspectionNone)},
		Services: config.Services{
			"web": {Domain: new("member.example"), Ephemeral: new(true), Traffic: &config.TrafficLimits{Connections: new(4)},
				HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}},
			"internal": {},
			"orders":   {Protocol: new("tcp"), Target: &config.ServiceTarget{Type: "address", Address: &dbTarget}},
		},
	}}
	web, err := project.EffectiveService("web")
	if err != nil || web.Domain == nil || *web.Domain != "member.example" || web.Traffic == nil || *web.Traffic.Connections != 4 || web.HTTP.Access.VisitorMode() != "anonymous" {
		t.Fatal("HTTP binding lost its explicit settings", web, err)
	}
	private, err := project.EffectiveService("orders")
	if err != nil || private.Domain != nil || private.HTTP != nil || private.Ephemeral != nil || private.Traffic != nil || private.Feedback != nil || private.OAuth || private.Inspection != nil ||
		private.Publish == nil || config.ServiceProtocol(private.Publish) != "tcp" || private.Publish.Target != &dbTarget || *private.Name != "orders" {
		t.Fatal("TCP binding borrowed HTTP settings or lost its target/name", private, err)
	}
	internal, err := project.EffectiveService("internal")
	if err != nil || internal.HTTP != nil || internal.Domain != nil || internal.Traffic != nil || !internal.OAuth || internal.Feedback == nil {
		t.Fatal("connector-only HTTP lost project behavior or borrowed endpoint settings", internal, err)
	}
	orders := project.Config.Services["orders"]
	orders.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}
	project.Config.Services["orders"] = orders
	if _, err := project.EffectiveService("orders"); err == nil {
		t.Fatal("TCP binding accepted HTTP visitor policy")
	}
}

func TestResolvedServiceSelectsOnlyApplicableProjectDefaults(t *testing.T) {
	name, server, team := "checkout", "https://control.example", "studio"
	retention := config.Duration(time.Hour)
	project := Project{Config: config.TNL{
		Name: &name, Server: &server, Team: &team, Feedback: new(true), OAuth: true,
		Inspection: &config.Inspection{Mode: new(config.InspectionSummary), Retention: &retention},
		Services: config.Services{
			"web":      {HTTP: &config.HTTPService{Access: &config.Access{IP: []string{"192.0.2.0/24"}}}},
			"internal": {Inspection: &config.Inspection{Mode: new(config.InspectionNone)}, HTTP: &config.HTTPService{Readiness: &config.Readiness{Path: "/ready"}}},
		},
		Webhooks: map[string]config.Webhook{"stripe": {Service: "web", Path: "/stripe", Provider: "stripe"}},
	}}
	for _, selected := range []string{"", "web", "internal", "web", ""} {
		settings, err := project.EffectiveService(selected)
		if err != nil || settings.Server != &server || settings.Team != &team || settings.Publish == nil || settings.Feedback == nil || !settings.OAuth || len(settings.Webhooks) != 1 ||
			settings.Inspection == nil || settings.Inspection.Retention != &retention {
			t.Fatal("lost shared project identity or local HTTP behavior", settings, err)
		}
		if selected == "internal" {
			if *settings.Inspection.Mode != config.InspectionNone || settings.HTTP.Readiness.Path != "/ready" || settings.HTTP.Access != nil {
				t.Fatal("service lost its own inspection/readiness or inherited visitor policy", settings)
			}
		} else if selected == "web" {
			if settings.HTTP.Access.IP[0] != "192.0.2.0/24" {
				t.Fatal("resolved access changed its parsed declaration")
			}
			settings.HTTP.Access.IP[0] = "198.51.100.0/24"
		} else if settings.Name != &name || settings.HTTP != nil {
			t.Fatal("root defaults acquired binding HTTP settings")
		}
		settings.Inspection.Retention = nil
	}
	if project.Config.Services["web"].HTTP.Access.IP[0] != "192.0.2.0/24" || project.Config.Inspection.Retention != &retention {
		t.Fatal("resolving settings changed the parsed project")
	}
	settings, err := (Project{}).EffectiveService("")
	if err != nil || settings.Name != nil || settings.HTTP != nil || settings.Publish == nil || settings.Traffic != nil {
		t.Fatal("empty root acquired service-only settings", settings, err)
	}
}

func TestSelectedDeploymentIsExplicitAndDefaultsToLocal(t *testing.T) {
	project := Project{Config: config.TNL{Services: config.Services{"default": {}}}}
	if actual := config.SelectedDeployment(project.Config); actual != "local" {
		t.Fatalf("default deployment=%s", actual)
	}
	project.Config.Deployment = "cloud"
	project.Config.Services = config.Services{"db": {Protocol: new("postgres"), Target: &config.ServiceTarget{Type: "address", Address: new(config.Target("db.internal:5432"))}}}
	if actual := config.SelectedDeployment(project.Config); actual != "cloud" || config.Protocol(project.Config.Services["db"]) != "postgres" || *project.Config.Services["db"].Target.Address != "db.internal:5432" {
		t.Fatal("selected deployment lost its binding")
	}
}

func TestServiceLimitsAreCompleteAndResolutionDoesNotChangeTheirSource(t *testing.T) {
	period := config.Duration(time.Minute)
	project := Project{Config: config.TNL{Services: config.Services{
		"api": {HTTP: &config.HTTPService{Limits: &config.WorkLimits{Total: new(20), Concurrency: new(3), Rate: &config.Rate{Count: new(5), Per: &period}}}, Traffic: &config.TrafficLimits{RatePer: &period}},
		"web": {HTTP: &config.HTTPService{Limits: &config.WorkLimits{Total: new(100)}}},
	}}}
	service, err := project.EffectiveService("api")
	if err != nil {
		t.Fatal(err)
	}
	limits := service.HTTP.Limits
	if *limits.Total != 20 || *limits.Concurrency != 3 || *limits.Rate.Count != 5 || limits.Rate.Per != &period || service.Traffic.RatePer != &period {
		t.Fatalf("service limits = %#v", limits)
	}
	limits.Rate.Per, service.Traffic.RatePer = nil, nil
	if project.Config.Services["api"].HTTP.Limits.Rate.Per != &period || project.Config.Services["api"].Traffic.RatePer != &period || project.Config.Services["web"].HTTP.Limits.Concurrency != nil {
		t.Fatal("resolution changed source limits or another binding")
	}
	project.Config.Services["api"].HTTP.Limits.Rate.Per = nil
	if _, err := project.EffectiveService("api"); err == nil {
		t.Fatal("a partial rate borrowed settings from another binding")
	}
}
