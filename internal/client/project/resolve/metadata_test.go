package resolve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestProjectMetadataUsesVisitorProjectionWithoutManagerConfiguration(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/review/project.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("Git fixture: %v %s", err, output)
		}
	}
	deployment := "cloud"
	project := clientproject.Project{Root: root, Selection: clientproject.Selection{Path: filepath.Join(root, "tnl.json")}, Worktree: clientproject.Worktree{Root: root, IsGit: true}, Declared: &config.Project{Services: map[string]config.ServiceDeclaration{"api": {}, "web": {}}}, Config: config.TNL{Deployment: deployment, Services: config.Services{
		"web": {Public: new(true), HTTP: &config.HTTPService{}, Target: &config.ServiceTarget{Type: "address", Address: testTarget("http://production.internal:3000")}},
	}}}
	source, err := project.SourceIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	hostname := "review.tnl.dev"
	protocol, public := "http", false
	port := 443
	status := http.StatusOK
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/projects/"+source.Key+"/services/web" || r.URL.Query().Get("team_id") != "team_1" || r.URL.Query().Get("source_fingerprint") != source.Fingerprint {
			t.Errorf("ordinary metadata requested a manager API: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			code := "forbidden"
			if status == http.StatusNotFound {
				code = "not_found"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": "service unavailable"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "svc_web", "team_id": "team_1", "name": "web", "protocol": protocol, "enabled": true, "endpoint": map[string]any{"hostname": hostname, "port": port, "public": public}, "target_tls": map[string]any{"hostname": "private.internal", "pem": "private-target-trust-must-not-leak"}})
	}))
	defer server.Close()
	project.Config.Server = &server.URL
	control, err := clientcontrol.New(server.URL, server.Client(), "visitor-session")
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewMetadataResolver(nil, project, nil)
	resolver.Seed(server.URL, &auth.Client{ServerEndpoint: server.URL, Control: control})
	resolver.contexts[server.URL+"\x00"] = appliedTestContext()
	metadata, err := resolver.Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil || requests != 1 || len(metadata.Services) != 1 || metadata.Services["web"].URL != "https://review.tnl.dev" || metadata.Services["web"].Port != port || metadata.Services["web"].Public || strings.Contains(string(encoded), "production.internal") || strings.Contains(string(encoded), "private-target-trust") || strings.Contains(string(encoded), `"api"`) || strings.Contains(string(encoded), "visitor-session") {
		t.Fatalf("unsafe or incomplete visitor metadata: %s, requests=%d, error=%v", encoded, requests, err)
	}
	protocol, public, port = "postgres", true, 20001
	service := resolver.project.Config.Services["web"]
	service.Protocol, service.Tunnel = &protocol, nil
	service.HTTP = nil
	service.Target.Address = testTarget("db.internal:5432")
	resolver.project.Config.Services["web"] = service
	metadata, err = resolver.Generate(t.Context())
	if err != nil || metadata.Services["web"].Protocol != "postgres" || metadata.Services["web"].Port != port || !metadata.Services["web"].Public || metadata.Services["web"].URL != "" {
		t.Fatalf("native metadata lost actual exposure: %+v %v", metadata, err)
	}
	protocol, public, port = "kubernetes", false, 10443
	service.Protocol = &protocol
	service.Target.Address = testTarget("https://private.internal:6443")
	service.Target.TLS = &config.TargetTLS{}
	resolver.project.Config.Services["web"] = service
	metadata, err = resolver.Generate(t.Context())
	if err != nil || metadata.Services["web"].Protocol != "kubernetes" || metadata.Services["web"].Port != port || metadata.Services["web"].Public || metadata.Services["web"].URL != "https://review.tnl.dev:10443" {
		t.Fatalf("kubernetes metadata lost its assigned endpoint: %+v %v", metadata, err)
	}
	hostname = "INVALID.tnl.dev"
	_, err = resolver.Generate(t.Context())
	if err == nil || !strings.Contains(err.Error(), `service "web": service hostname must be a canonical hostname`) {
		t.Fatalf("invalid remote metadata lost its validation error: %v", err)
	}
	status = http.StatusNotFound
	metadata, err = resolver.Generate(t.Context())
	if err != nil || len(metadata.Services) != 0 {
		t.Fatalf("unapplied remote service prevented local metadata: %+v %v", metadata, err)
	}
	status = http.StatusForbidden
	if _, err := resolver.Generate(t.Context()); err == nil {
		t.Fatal("remote authorization failure was treated as an unapplied service")
	}
}

func testTarget(value string) *config.Target { target := config.Target(value); return &target }

func TestLocalPublicMetadataUsesExactWorktreeEndpoint(t *testing.T) {
	root := t.TempDir()
	project := clientproject.Project{Root: root, Selection: clientproject.Selection{Path: filepath.Join(root, "tnl.json")}, Config: config.TNL{
		Services: config.Services{"api": {Public: new(true)}, "db": {Protocol: new("postgres"), Public: new(true), Target: &config.ServiceTarget{Type: "address", Address: testTarget("db.internal:5432")}}, "private": {}},
	}}
	source, worktree := project.LocalPublicationIdentity(), project.LocalWorktreeKey()
	public, port, status := true, 443, http.StatusOK
	returnedWorktree := worktree
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/projects/"+source.Key+"/local-services/api" || r.URL.Query().Get("team_id") != "team_1" || r.URL.Query().Get("source_fingerprint") != source.Fingerprint || r.URL.Query().Get("worktree_key") != worktree {
			t.Errorf("metadata read another worktree or mutated state: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			code := "forbidden"
			if status == http.StatusNotFound {
				code = "not_found"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": "unavailable"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service": "api", "worktree_key": returnedWorktree, "service_kind": "service", "service_id": "svc_api",
			"metadata": map[string]any{"protocol": "http", "trust_revision": "1", "endpoint": map[string]any{"hostname": "api.feature.tnl.dev", "port": port, "public": public}},
		})
	}))
	defer server.Close()
	project.Config.Server = &server.URL
	control, err := clientcontrol.New(server.URL, server.Client(), "visitor-session")
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewMetadataResolver(nil, project, nil)
	resolver.Seed(server.URL, &auth.Client{ServerEndpoint: server.URL, Control: control})
	resolver.contexts[server.URL+"\x00"] = appliedTestContext()
	metadata, err := resolver.Generate(t.Context())
	if err != nil || requests != 1 || len(metadata.Services) != 1 || metadata.Services["api"].URL != "https://api.feature.tnl.dev" || !metadata.Services["api"].Public {
		t.Fatal("metadata invented a port or included private/database bindings", metadata, requests, err)
	}
	public = false
	metadata, err = resolver.Generate(t.Context())
	if err != nil || len(metadata.Services) != 0 {
		t.Fatal("local config overrode current private exposure", metadata, err)
	}
	public, port = true, 0
	if _, err := resolver.Generate(t.Context()); err == nil {
		t.Fatal("public service without an allocated port was accepted")
	}
	port, returnedWorktree = 443, "another-worktree"
	if _, err := resolver.Generate(t.Context()); err == nil {
		t.Fatal("metadata adopted another worktree endpoint")
	}
	status = http.StatusNotFound
	metadata, err = resolver.Generate(t.Context())
	if err != nil || len(metadata.Services) != 0 {
		t.Fatal("metadata tried to allocate an unrealized service", metadata, err)
	}
	status = http.StatusForbidden
	if _, err := resolver.Generate(t.Context()); err == nil {
		t.Fatal("metadata ignored a current authorization failure")
	}
}
