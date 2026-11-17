package invocation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestProjectRuntimePreparationRealizesOnlySelectedLocalService(t *testing.T) {
	for _, public := range []bool{false, true} {
		name := "connector-only"
		if public {
			name = "public"
		}
		t.Run(name, func(t *testing.T) {
			testProjectRuntimePreparation(t, public, nil)
		})
	}
}

func TestProjectRuntimePreparationRejectsInvalidSelectedEndpoint(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*controlv1.LocalProjectService)
	}{
		{"missing metadata", func(s *controlv1.LocalProjectService) { s.Metadata = nil }},
		{"missing endpoint", func(s *controlv1.LocalProjectService) { s.Metadata.Endpoint = nil }},
		{"another service", func(s *controlv1.LocalProjectService) { s.Service = "private" }},
		{"another worktree", func(s *controlv1.LocalProjectService) { s.WorktreeKey = "other" }},
		{"missing service ID", func(s *controlv1.LocalProjectService) { s.ServiceId = "" }},
		{"another protocol", func(s *controlv1.LocalProjectService) { s.Metadata.Protocol = controlv1.ServiceProtocol("tcp") }},
		{"mismatched hostname", func(s *controlv1.LocalProjectService) { s.Hostname = new("other.developer.example.test") }},
		{"noncanonical hostname", func(s *controlv1.LocalProjectService) { s.Metadata.Endpoint.Hostname = "Web.developer.example.test" }},
		{"zero HTTP port", func(s *controlv1.LocalProjectService) { s.Metadata.Endpoint.Port = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			testProjectRuntimePreparation(t, false, test.change)
		})
	}
}

func testProjectRuntimePreparation(t *testing.T, public bool, corrupt func(*controlv1.LocalProjectService)) {
	t.Helper()
	root := t.TempDir()
	project := clientproject.Project{Root: root, Selection: clientproject.Selection{Path: filepath.Join(root, "tnl.json")},
		Config: config.TNL{Services: config.Services{
			"web": {Public: new(public)},
			"other": {Public: new(true), Target: &config.ServiceTarget{Type: "docker", Container: new("unrelated"), Port: new(443),
				TLS: &config.TargetTLS{CA: new("system")}}},
			"private": {},
		}},
		Declared: &config.Project{Services: map[string]config.ServiceDeclaration{"web": {}, "other": {}, "private": {}, "remote": {}},
			Deployments: map[string]config.Deployment{"production": {Targets: map[string]config.DeploymentBinding{
				"remote": {ServiceTarget: config.ServiceTarget{Type: "address", Address: new(config.Target("https://remote.internal:443")),
					TLS: &config.TargetTLS{CA: new("invalid remote trust")}}},
			}}}},
	}
	source, worktree := project.LocalPublicationIdentity(), project.LocalWorktreeKey()
	localPath := "/v1/projects/" + source.Key + "/local-services/"
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var mutations []string
	realized := false
	preparing := false
	selected := controlv1.LocalProjectService{Service: "web", WorktreeKey: worktree, ServiceId: "svc_0123456789abcdefghijkl",
		Hostname: new("web.developer.example.test"),
		Metadata: &controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1,
			TargetTls: &controlv1.ServiceTargetTLS{Hostname: "target.internal", Pem: new("must-not-reach-browser"), Digest: "private-trust"},
			Endpoint:  &controlv1.ServiceEndpoint{Hostname: "web.developer.example.test", Port: 443, Public: public}}}
	if corrupt != nil {
		corrupt(&selected)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+token.String() {
			t.Error("preparation lost the selected control credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var response any
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/discovery":
			response = controlv1.ControlDiscovery{ManagedUrlMode: "simple", Authentication: controlv1.AuthenticationFacts{
				Methods: []controlv1.AuthenticationFactsMethods{controlv1.Oidc},
				Oidc:    &controlv1.OIDCAuthenticationFacts{Issuer: "https://identity.example", LoginFlow: controlv1.DeviceCode},
			}}
		case "GET /v1/identity":
			response = authorityv1.IdentityContext{PersonalTeamId: "team_1", Memberships: []authorityv1.Membership{
				{TeamId: "team_1", MemberSlug: "developer", ManagedLabel: "developer"},
			}}
		case "GET /v1/teams/team_1":
			response = authorityv1.Team{Id: "team_1", DisplayName: "developer", Kind: authorityv1.Personal, DefaultDomainId: "domain_1"}
		case "GET /v1/teams/team_1/domains":
			response = authorityv1.DomainPage{Domains: []authorityv1.Domain{
				{Id: "domain_1", CanonicalDomain: "example.test", Kind: authorityv1.Managed, State: authorityv1.DomainStateReady},
			}}
		case "PUT " + localPath + "web":
			mutations = append(mutations, r.Method+" "+r.URL.Path)
			var request controlv1.RealizeLocalProjectServiceRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if request.TeamId != "team_1" || request.WorktreeKey != worktree || request.SourceFingerprint != source.Fingerprint ||
				request.Configuration.Name == nil || *request.Configuration.Name != "web" ||
				request.Configuration.Protocol == nil || *request.Configuration.Protocol != controlv1.ServiceProtocolHTTP ||
				request.Configuration.Target != "app" || request.Configuration.Public == nil || *request.Configuration.Public != public ||
				request.Configuration.TargetTls != nil {
				t.Error("preparation changed its exact local declaration", request)
			}
			realized = true
			response = selected
		case "GET " + localPath + "web":
			if r.URL.Query().Get("team_id") != "team_1" || r.URL.Query().Get("source_fingerprint") != source.Fingerprint ||
				r.URL.Query().Get("worktree_key") != worktree {
				t.Error("metadata read another local selection")
			}
			if !realized {
				w.WriteHeader(http.StatusNotFound)
				response = controlv1.Problem{Code: controlv1.NotFound, Status: 404}
				break
			}
			// only ordinary metadata reads use this projection. preparation must
			// retain the endpoint returned by its selected realization instead.
			response = selected
			if preparing {
				t.Error("preparation discarded its selected realization endpoint")
			}
		case "GET " + localPath + "other":
			w.WriteHeader(http.StatusNotFound)
			response = controlv1.Problem{Code: controlv1.NotFound, Status: 404}
		default:
			t.Errorf("preparation evaluated or mutated unrelated work: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			response = controlv1.Problem{Code: controlv1.NotFound, Status: 404}
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	project.Config.Server = &server.URL
	t.Setenv("TNL_SERVER", server.URL)
	t.Setenv("TNL_ACCESS_TOKEN", token.String())
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	operation := NewProjectRuntime(project, state, nil, target.TargetResolverFunc(func(context.Context, clientproject.Project, string) (string, string, error) {
		t.Error("app preparation evaluated an unrelated target or trust source")
		return "", "", errors.New("unexpected discovery")
	}))
	before, err := operation.Metadata(t.Context())
	if err != nil || len(before.Services) != 0 {
		t.Fatal("read-only metadata invented an unrealized service", before, err)
	}
	mu.Lock()
	initialMutations := len(mutations)
	mu.Unlock()
	if initialMutations != 0 {
		t.Fatal("read-only metadata realized a service")
	}
	mu.Lock()
	preparing = true
	mu.Unlock()
	prepared, err := operation.PrepareLocalService(t.Context(), "web")
	mu.Lock()
	preparing = false
	mu.Unlock()
	if corrupt != nil {
		if err == nil {
			t.Fatal("preparation accepted invalid selected endpoint metadata")
		}
		return
	}
	if err != nil || len(prepared.Services) != 1 || prepared.Services["web"].URL != "https://web.developer.example.test" ||
		prepared.Services["web"].Public != public || prepared.Services["web"].Port != 443 {
		t.Fatal("preparation omitted its selected endpoint", prepared, err)
	}
	after, err := operation.Metadata(t.Context())
	if err != nil || public && !reflect.DeepEqual(after, prepared) || !public && len(after.Services) != 0 {
		t.Fatal("read-only metadata expanded its inclusion or invented an endpoint", after, err)
	}
	mu.Lock()
	gotMutations := append([]string(nil), mutations...)
	mu.Unlock()
	if !reflect.DeepEqual(gotMutations, []string{"PUT " + localPath + "web"}) {
		t.Fatal("preparation applied another service or metadata mutated state", gotMutations)
	}
	encoded, err := json.Marshal(prepared)
	if err != nil || bytes.Contains(encoded, []byte(token.String())) || strings.Contains(string(encoded), "trust") ||
		strings.Contains(string(encoded), "remote.internal") || strings.Contains(string(encoded), "unrelated") ||
		strings.Contains(string(encoded), "must-not-reach-browser") || strings.Contains(string(encoded), "target.internal") {
		t.Fatal("preparation leaked target configuration or credentials", err)
	}
	snapshot, err := state.SnapshotProject(t.Context(), root)
	if err != nil || len(snapshot.Tunnels) != 0 {
		t.Fatal("preparation started publication before registration", err)
	}
}

func TestProjectRuntimePreparationRejectsMissingAndRemoteSelections(t *testing.T) {
	for _, test := range []struct {
		name, deployment, service string
	}{
		{"missing local service", "local", "missing"},
		{"remote deployment", "production", "web"},
	} {
		t.Run(test.name, func(t *testing.T) {
			operation := NewProjectRuntime(clientproject.Project{Config: config.TNL{Deployment: test.deployment,
				Services: config.Services{"web": {Public: new(true)}}}}, nil, nil, nil)
			if _, err := operation.PrepareLocalService(t.Context(), test.service); err == nil {
				t.Fatal("preparation accepted a missing or remote selection")
			}
		})
	}
}
