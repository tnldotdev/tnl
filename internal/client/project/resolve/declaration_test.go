package resolve

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func appliedTestContext() team.Context {
	return team.NewContext(authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_1"}, authorityv1.Membership{Id: "membership_1", TeamId: "team_1", ManagedLabel: "member", MemberSlug: "member"}, []authorityv1.Domain{{Id: "domain_1", CanonicalDomain: "tnl.dev", Kind: authorityv1.Managed, State: authorityv1.DomainStateReady}}, "")
}

func TestRemoteHTTPSettingsDoNotEnablePublicReachability(t *testing.T) {
	deployment, address := "production", config.Target("http://app.internal:3000")
	total, concurrency := 100, 2
	project := clientproject.Project{Config: config.TNL{
		Deployment: deployment,
		Services: config.Services{"api": {Target: &config.ServiceTarget{Type: "address", Address: &address}, HTTP: &config.HTTPService{
			Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.1"}}, Limits: &config.WorkLimits{Total: &total, Concurrency: &concurrency}}}},
	}}
	declaration, err := Declaration(t.Context(), project, appliedTestContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	service := declaration.Services["api"]
	if service.Public != nil || service.Http == nil || service.Http.Access == nil || service.Http.Access.Mode == nil || *service.Http.Access.Mode != "restricted" || service.Http.Limits == nil || *service.Http.Limits.Total != total || *service.Http.Limits.Concurrency != concurrency || len(*service.Http.Access.Ip) != 1 {
		t.Fatalf("remote HTTP defaults or reachability changed: %+v", service)
	}
	project.Config.Services["api"].HTTP.Access.Mode = "anonymous"
	anonymous, err := Declaration(t.Context(), project, appliedTestContext(), nil)
	if err != nil || anonymous.Services["api"].Http.Access.Mode == nil || *anonymous.Services["api"].Http.Access.Mode != "anonymous" || anonymous.Services["api"].Public != nil {
		t.Fatal("anonymous HTTP access changed reachability or selected another publication kind", err)
	}
}

func TestServiceHTTPRequestPolicyDeclarationMatchesLocalAndRemote(t *testing.T) {
	period := config.Duration(time.Second)
	project := clientproject.Project{Config: config.TNL{
		Services: config.Services{"web": {
			Public: new(true), Target: &config.ServiceTarget{Type: "address", Address: new(config.Target("http://app.internal:3000"))},
			HTTP: &config.HTTPService{RequestBodyIdleTimeout: new(config.Duration(45 * time.Second)), Access: &config.Access{IP: []string{"192.0.2.1"}}, Limits: &config.WorkLimits{Total: new(100), Concurrency: new(2), Rate: &config.Rate{Count: new(5), Per: &period, Burst: new(2)}}},
		}},
	}}
	local, err := Declaration(t.Context(), project, appliedTestContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	project.Config.Deployment = "production"
	remote, err := Declaration(t.Context(), project, appliedTestContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := json.Marshal(local.Services["web"])
	if err != nil {
		t.Fatal(err)
	}
	r, err := json.Marshal(remote.Services["web"])
	if err != nil || string(l) != string(r) {
		t.Fatal("placement changed service request policy or reachability", string(l), string(r), err)
	}
	if value := local.Services["web"]; value.Http == nil || value.Http.Access == nil || value.Http.Limits == nil || *value.Http.Limits.Total != 100 || *value.Http.Limits.Concurrency != 2 {
		t.Fatal("local declaration lost its request policy", value)
	}
	if rate := local.Services["web"].Http.Limits.Rate; rate == nil || rate.Count != 5 || rate.Per != "1s" || rate.Burst == nil || *rate.Burst != 2 {
		t.Fatal("explicit rate fields did not round-trip", rate)
	}
	if timeout := local.Services["web"].Http.RequestBodyIdleTimeout; timeout == nil || *timeout != "45s" {
		t.Fatal("declaration lost the HTTP body idle timeout", timeout)
	}
}

func TestRemoteDeclarationKeepsExposureOnEachService(t *testing.T) {
	project := clientproject.Project{Config: config.TNL{
		Deployment: "production",
		Services: config.Services{
			"api": {Public: new(true), Target: &config.ServiceTarget{Type: "address", Address: new(config.Target("http://app.internal:3000"))}},
			"db":  {Public: new(false), Protocol: new("postgres"), Target: &config.ServiceTarget{Type: "address", Address: new(config.Target("db.internal:5432"))}},
		},
	}}
	declaration, err := Declaration(t.Context(), project, appliedTestContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	api, db := declaration.Services["api"], declaration.Services["db"]
	if api.Public == nil || !*api.Public || db.Public == nil || *db.Public || declaration.Settings == nil {
		t.Fatal("declaration broadened placement, HTTP resource kind, or another service")
	}
}

func TestProjectDeclarationPreservesDirectSettingsPolicyLimitsAndGrantIntent(t *testing.T) {
	deployment := "cloud"
	remote := config.Target("http://api.internal:8080")
	connections, total, count := 8, 100, 5
	period := config.Duration(2 * time.Minute)
	upload := int64(1 << 20)
	project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{
		Services: config.Services{
			"web": {Public: new(true), RequirePostQuantum: new(true), Ephemeral: new(true), Traffic: &config.TrafficLimits{Connections: &connections, UploadBytes: &upload}, Access: &config.ServiceAccess{Team: true},
				HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous", IP: []string{"198.51.100.1", "192.0.2.1"}}, Limits: &config.WorkLimits{Total: &total, Rate: &config.Rate{Count: &count, Per: &period}},
					Readiness: &config.Readiness{Path: "/health"}, Paths: map[string]config.PathMount{"/api": {Service: "internal", StripPrefix: true}}}},
			"internal": {Access: &config.ServiceAccess{Team: true}},
		},
	}}
	declaration, err := Declaration(t.Context(), project, appliedTestContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	internal := declaration.Services["internal"]
	if internal.Public != nil || internal.Traffic != nil || internal.Http != nil || internal.Target != "app" || internal.Access == nil || !bool(internal.Access.Team) || internal.Protocol == nil || *internal.Protocol != "http" {
		t.Fatalf("private HTTP declaration: %+v", internal)
	}
	web := declaration.Services["web"]
	if web.RequirePostQuantum == nil || !*web.RequirePostQuantum || web.Ephemeral == nil || !*web.Ephemeral {
		t.Fatal("declaration lost the public HTTPS requirement")
	}
	if web.Hostname != nil || web.DomainId != nil || web.Access == nil || !bool(web.Access.Team) {
		t.Fatalf("local public declaration was allocated or lost team access: %+v", web)
	}
	if web.Http == nil || web.Http.Readiness == nil || web.Http.Readiness.Path != "/health" || web.Http.Paths == nil || (*web.Http.Paths)["/api"].Service != "internal" || (*web.Http.Paths)["/api"].StripPrefix == nil || !*(*web.Http.Paths)["/api"].StripPrefix {
		t.Fatalf("apply dropped local HTTP behavior: %+v", web.Http)
	}
	remoteProject := project
	remoteProject.Config.Deployment = deployment
	remoteProject.Config.Services = config.Services{"remote": {Target: &config.ServiceTarget{Type: "address", Address: &remote}, Access: &config.ServiceAccess{Team: true}}}
	remoteDeclaration, err := Declaration(t.Context(), remoteProject, appliedTestContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	remoteService := remoteDeclaration.Services["remote"]
	if remoteService.Public != nil || remoteService.Traffic != nil || remoteService.Http != nil || remoteService.Access == nil || !bool(remoteService.Access.Team) {
		t.Fatalf("remote HTTP inherited public URL defaults: %+v", remoteService)
	}
	limits, traffic := web.Http.Limits, web.Traffic
	if limits == nil || *limits.Total != 100 || limits.Rate.Count != 5 || limits.Rate.Per != "2m0s" || traffic == nil || *traffic.Connections != 8 || *traffic.UploadBytes != 1<<20 {
		t.Fatalf("applied limits did not round-trip: %+v %+v", limits, traffic)
	}
	if *web.Http.Access.Ip == nil || (*web.Http.Access.Ip)[0] != "192.0.2.1" || project.Config.Services["web"].HTTP.Access.IP[0] != "198.51.100.1" {
		t.Fatal("applied IP policy is not normalized")
	}
	data, err := json.Marshal(declaration)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), project.Root) || strings.Contains(string(data), "worktree") || strings.Contains(string(data), "publisher_pool") {
		t.Fatalf("apply included machine-local configuration: %s", data)
	}
}

func TestProjectDeclarationLocalDiscoveryNeedsNoRunningTarget(t *testing.T) {
	composeService, container, port := "db", "cache", 5432
	protocol := "postgres"
	project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{
		"web":   {},
		"db":    {Protocol: &protocol, Target: &config.ServiceTarget{Type: "compose", Service: &composeService, Port: &port}},
		"cache": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "docker", Container: &container, Port: &port}},
	}}}
	declaration, err := Declaration(t.Context(), project, team.Context{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"web": "app", "db": "compose:db:5432", "cache": "docker:cache:5432"} {
		if got := declaration.Services[name].Target; got != target {
			t.Fatalf("%s target=%q", name, got)
		}
	}
}

func TestDeploymentDeclarationCapturesExactHostnameWithoutLocalListenerFacts(t *testing.T) {
	project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{Deployment: "production", Services: config.Services{
		"web": {Target: &config.ServiceTarget{Type: "app"}, Hostname: new("web.tnl.dev"), Domain: new("tnl.dev"), HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}},
	}}}
	value, err := Declaration(t.Context(), project, appliedTestContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	web := value.Services["web"]
	if web.Target != "app" || web.Hostname == nil || *web.Hostname != "web.tnl.dev" || web.DomainId == nil || *web.DomainId != "domain_1" || web.Http == nil || web.Http.Access == nil || *web.Http.Access.Mode != "anonymous" || web.Public != nil {
		t.Fatal("declaration lost exact saved URL settings or invented remote HTTP defaults")
	}
}
