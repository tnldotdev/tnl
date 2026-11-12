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

func TestDefinitionContainsOnlyLogicalShape(t *testing.T) {
	project := clientproject.Project{Config: config.TNL{
		Services:     config.Services{"db": {Protocol: new("postgres")}},
		Environments: map[string]config.Environment{"staging": {Targets: map[string]config.EnvironmentTarget{"db": {Address: new(config.Target("db.internal:5432")), TLS: &config.EnvironmentTargetTLS{}}}, Workloads: map[string]config.Workload{"accounts": {Vercel: &config.WorkloadVercel{Project: "accounts", Environment: "production"}, Services: []string{"db"}}}}},
		Collections:  map[string]config.Collection{"customers": {}},
	}}
	definition, err := Definition(project)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(definition)
	if err != nil || string(data) != `{"services":{"db":{"protocol":"postgres"}}}` {
		t.Fatalf("definition leaked environment authority: %s, %v", data, err)
	}
}

func TestEnvironmentHTTPSettingsDoNotInheritLocalPublicURLDefaults(t *testing.T) {
	total, concurrency := 100, 2
	project := clientproject.Project{Config: config.TNL{
		Tunnel:       &config.Tunnel{Access: &config.Access{Mode: "anonymous"}, Limits: &config.Limits{HTTP: &config.WorkLimits{Total: &total}}},
		Services:     config.Services{"api": {}},
		Environments: map[string]config.Environment{"staging": {Targets: map[string]config.EnvironmentTarget{"api": {Address: new(config.Target("http://app.internal:3000")), HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.1"}}, Limits: &config.WorkLimits{Concurrency: &concurrency}}}}}},
	}}
	targets, err := EnvironmentTargets(t.Context(), project, "staging")
	if err != nil {
		t.Fatal(err)
	}
	service := targets["api"]
	if service.Http == nil || service.Http.Access == nil || service.Http.Limits == nil || service.Http.Limits.Total != nil || *service.Http.Limits.Concurrency != concurrency || len(*service.Http.Access.Ip) != 1 {
		t.Fatalf("remote HTTP inherited local defaults or lost explicit policy: %+v", service)
	}
	project.Config.Environments["staging"].Targets["api"].HTTP.Access.Mode = "anonymous"
	if _, err := EnvironmentTargets(t.Context(), project, "staging"); err == nil {
		t.Fatal("remote target accepted anonymous HTTP access")
	}
}

func TestLocalDeclarationPreservesPublicURLPolicyLimitsAndGrantIntent(t *testing.T) {
	connections, total, count := 8, 100, 5
	period := config.Duration(2 * time.Minute)
	upload := int64(1 << 20)
	project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{
		Tunnel: &config.Tunnel{Access: &config.Access{Mode: "anonymous", IP: []string{"198.51.100.1", "192.0.2.1"}}, Limits: &config.Limits{HTTP: &config.WorkLimits{Total: &total, Rate: &config.Rate{Count: &count, Per: &period}}, Traffic: &config.TrafficLimits{Connections: &connections, UploadBytes: &upload}}},
		Services: config.Services{
			"web":      {Tunnel: &config.Tunnel{RequirePostQuantum: new(true)}, Access: &config.ServiceAccess{Team: true}, HTTP: &config.HTTPService{Readiness: &config.Readiness{Path: "/health"}, Paths: map[string]config.PathMount{"/api": {Service: "internal", StripPrefix: true}}}},
			"internal": {Access: &config.ServiceAccess{Team: true}},
		},
	}}
	internal, err := LocalServiceDeclaration(t.Context(), project, appliedTestContext(), "internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	if internal.PublicUrl != nil || internal.Target != "app" || internal.Access == nil || !bool(internal.Access.Team) || internal.Protocol == nil || *internal.Protocol != "http" {
		t.Fatalf("private HTTP declaration: %+v", internal)
	}
	web, err := LocalServiceDeclaration(t.Context(), project, appliedTestContext(), "web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if web.PublicUrl == nil || web.PublicUrl.RequirePostQuantum == nil || !*web.PublicUrl.RequirePostQuantum || web.PublicUrl.Hostname != nil || web.PublicUrl.DomainId != nil || web.Access == nil || !bool(web.Access.Team) {
		t.Fatalf("local public declaration was allocated or lost policy intent: %+v", web)
	}
	if web.Http == nil || web.Http.Readiness == nil || web.Http.Readiness.Path != "/health" || web.Http.Paths == nil || (*web.Http.Paths)["/api"].Service != "internal" || (*web.Http.Paths)["/api"].StripPrefix == nil || !*(*web.Http.Paths)["/api"].StripPrefix {
		t.Fatalf("local HTTP behavior lost: %+v", web.Http)
	}
	limits, traffic := web.PublicUrl.Limits.Http, web.PublicUrl.Limits.Traffic
	if limits == nil || *limits.Total != 100 || limits.Rate.Count != 5 || limits.Rate.Per != "2m0s" || traffic == nil || *traffic.Connections != 8 || *traffic.UploadBytes != 1<<20 {
		t.Fatalf("local limits did not round-trip: %+v %+v", limits, traffic)
	}
	if (*web.PublicUrl.Access.Ip)[0] != "192.0.2.1" {
		t.Fatal("IP policy is not normalized")
	}
	data, err := json.Marshal(web)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), project.Root) || strings.Contains(string(data), "worktree") || strings.Contains(string(data), "publisher_pool") {
		t.Fatalf("declaration leaked local state: %s", data)
	}
}

func TestLocalDeclarationDiscoveryNeedsNoRunningTarget(t *testing.T) {
	project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{
		"web":   {Tunnel: &config.Tunnel{}},
		"db":    {Protocol: new("postgres"), Target: &config.ServiceTarget{Type: "compose", Service: new("db"), Port: new(5432)}},
		"cache": {Protocol: new("postgres"), Target: &config.ServiceTarget{Type: "docker", Container: new("cache"), Port: new(5432)}},
	}}}
	for name, target := range map[string]string{"web": "app", "db": "compose:db:5432", "cache": "docker:cache:5432"} {
		declaration, err := LocalServiceDeclaration(t.Context(), project, team.Context{}, name, nil)
		if err != nil || declaration.Target != target {
			t.Fatalf("%s target=%q: %v", name, declaration.Target, err)
		}
	}
}
