package resolve

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestProjectDeclarationIgnoresPublisherInfrastructure(t *testing.T) {
	group, target := "production", config.Target("http://internal.example:8080")
	project := clientproject.Project{Config: config.TNL{
		PublisherGroups: map[string]config.PublisherGroup{group: {}},
		Services:        config.Services{"api": {PublisherGroup: &group, Target: &config.ServiceTarget{Type: "address", Address: &target}}},
	}}
	var original []byte
	for _, count := range []int{0, 1, 2, config.MaxPublisherReplicas} {
		entry := config.PublisherGroup{}
		if count != 0 {
			entry.AWS = &config.PublisherGroupAWS{Replicas: &count}
		}
		project.Config.PublisherGroups[group] = entry
		declaration, err := Declaration(t.Context(), project, appliedTestContext(), nil)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(declaration)
		if err != nil {
			t.Fatal(err)
		}
		if original == nil {
			original = encoded
		}
		if !bytes.Equal(original, encoded) {
			t.Fatal("AWS capacity changed the control declaration and would change its assignment hash")
		}
	}
}

func appliedTestContext() team.Context {
	return team.NewContext(authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_1"}, authorityv1.Membership{Id: "membership_1", TeamId: "team_1", ManagedLabel: "member", MemberSlug: "member"}, []authorityv1.Domain{{Id: "domain_1", CanonicalDomain: "tnl.dev", Kind: authorityv1.Managed, State: authorityv1.DomainStateReady}}, "")
}

func TestGroupHTTPSettingsInheritDefaultsWithoutCreatingPublicURL(t *testing.T) {
	group, address := "production", config.Target("http://app.internal:3000")
	total, concurrency := 100, 2
	project := clientproject.Project{Config: config.TNL{
		PublisherGroups: map[string]config.PublisherGroup{group: {}},
		Tunnel:          &config.Tunnel{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.1"}}, Limits: &config.Limits{HTTP: &config.WorkLimits{Total: &total}}},
		Services:        config.Services{"api": {PublisherGroup: &group, Target: &config.ServiceTarget{Type: "address", Address: &address}, HTTP: &config.HTTPService{Limits: &config.WorkLimits{Concurrency: &concurrency}}}},
	}}
	declaration, err := Declaration(t.Context(), project, appliedTestContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	service := declaration.Services["api"]
	if service.PublicUrl != nil || service.Http == nil || service.Http.Access == nil || service.Http.Access.Mode == nil || *service.Http.Access.Mode != "restricted" || service.Http.Limits == nil || *service.Http.Limits.Total != total || *service.Http.Limits.Concurrency != concurrency || len(*service.Http.Access.Ip) != 1 {
		t.Fatalf("group HTTP defaults or reachability changed: %+v", service)
	}
	project.Config.Tunnel.Access.Mode = "anonymous"
	if _, err := Declaration(t.Context(), project, appliedTestContext(), nil); err == nil {
		t.Fatal("group HTTP inherited anonymous access")
	}
}

func TestProjectDeclarationUsesPublicURLPresenceAndPreservesPolicyLimitsAndGrantIntent(t *testing.T) {
	group := "cloud"
	remote := config.Target("http://api.internal:8080")
	connections, total, count := 8, 100, 5
	period := config.Duration(2 * time.Minute)
	upload := int64(1 << 20)
	project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{
		PublisherGroups: map[string]config.PublisherGroup{group: {}},
		Tunnel:          &config.Tunnel{Access: &config.Access{Mode: "anonymous", IP: []string{"198.51.100.1", "192.0.2.1"}}, Limits: &config.Limits{HTTP: &config.WorkLimits{Total: &total, Rate: &config.Rate{Count: &count, Per: &period}}, Traffic: &config.TrafficLimits{Connections: &connections, UploadBytes: &upload}}},
		Services: config.Services{
			"web":      {Tunnel: &config.Tunnel{}, Access: &config.ServiceAccess{Team: true}, HTTP: &config.HTTPService{Readiness: &config.Readiness{Path: "/health"}, Paths: map[string]config.PathMount{"/api": {Service: "internal", StripPrefix: true}}}},
			"internal": {Access: &config.ServiceAccess{Team: true}},
			"remote":   {PublisherGroup: &group, Target: &config.ServiceTarget{Type: "address", Address: &remote}, Access: &config.ServiceAccess{Team: true}},
		},
	}}
	declaration, err := Declaration(t.Context(), project, appliedTestContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	internal := declaration.Services["internal"]
	if internal.PublicUrl != nil || internal.Target != "app" || internal.Access == nil || !bool(internal.Access.Team) || internal.Protocol == nil || *internal.Protocol != "http" {
		t.Fatalf("private HTTP declaration: %+v", internal)
	}
	web := declaration.Services["web"]
	if web.PublicUrl == nil || web.PublicUrl.Hostname != nil || web.PublicUrl.DomainId != nil || web.Access == nil || !bool(web.Access.Team) {
		t.Fatalf("local public declaration was allocated or lost team access: %+v", web)
	}
	if web.Http == nil || web.Http.Readiness == nil || web.Http.Readiness.Path != "/health" || web.Http.Paths == nil || (*web.Http.Paths)["/api"].Service != "internal" || (*web.Http.Paths)["/api"].StripPrefix == nil || !*(*web.Http.Paths)["/api"].StripPrefix {
		t.Fatalf("apply dropped local HTTP behavior: %+v", web.Http)
	}
	remoteService := declaration.Services["remote"]
	if remoteService.PublicUrl != nil || remoteService.Access == nil || !bool(remoteService.Access.Team) {
		t.Fatalf("group HTTP inherited public URL defaults: %+v", remoteService)
	}
	limits, traffic := web.PublicUrl.Limits.Http, web.PublicUrl.Limits.Traffic
	if limits == nil || *limits.Total != 100 || limits.Rate.Count != 5 || limits.Rate.Per != "2m0s" || traffic == nil || *traffic.Connections != 8 || *traffic.UploadBytes != 1<<20 {
		t.Fatalf("applied limits did not round-trip: %+v %+v", limits, traffic)
	}
	if *web.PublicUrl.Access.Ip == nil || (*web.PublicUrl.Access.Ip)[0] != "192.0.2.1" {
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
		"web":   {Tunnel: &config.Tunnel{}},
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
