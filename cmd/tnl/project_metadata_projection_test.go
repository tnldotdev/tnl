package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func TestRemoteProjectMetadataUsesVisitorProjectionWithoutManagerConfiguration(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/review/project.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("Git fixture: %v %s", err, output)
		}
	}
	group := "cloud"
	project := projectConfiguration{Project: projectconfig.Project{Root: root, Selection: projectconfig.Selection{Path: filepath.Join(root, "tnl.json")}, Worktree: projectconfig.Worktree{Root: root, IsGit: true}, Config: config.TNL{Publishers: map[string]config.Publisher{group: {Public: true}}, Services: config.Services{
		"api": {},
		"web": {Publisher: &group, Tunnel: &config.Tunnel{}, Target: &config.ServiceTarget{Type: "address", Address: testTarget("http://production.internal:3000")}},
	}}}}
	source, err := project.SourceIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	hostname := "review.tnl.dev"
	protocol, public := "http", false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/projects/"+source.Key+"/private-services/web" || r.URL.Query().Get("team_id") != "team_1" || r.URL.Query().Get("source_fingerprint") != source.Fingerprint {
			t.Errorf("ordinary metadata requested a manager API: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "psvc_web", "team_id": "team_1", "name": "web", "protocol": protocol, "enabled": true, "managed_tls": map[string]any{"hostname": hostname, "port": 20001, "public": public}, "target_tls": map[string]any{"hostname": "private.internal", "pem": "private-target-trust-must-not-leak"}})
	}))
	defer server.Close()
	project.Config.Server = &server.URL
	control, err := controlclient.New(server.URL, server.Client(), "visitor-session")
	if err != nil {
		t.Fatal(err)
	}
	resolver := newProjectMetadataResolver(nil, project, nil, io.Discard, "visitor metadata")
	resolver.Seed(server.URL, &clientauth.Client{ServerEndpoint: server.URL, Control: control})
	resolver.contexts[server.URL+"\x00"] = appliedTestContext()
	metadata, err := resolver.Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil || requests != 1 || len(metadata.Services) != 1 || metadata.Services["web"].URL != "https://review.tnl.dev:20001" || metadata.Services["web"].Public || strings.Contains(string(encoded), "production.internal") || strings.Contains(string(encoded), "private-target-trust") || strings.Contains(string(encoded), `"api"`) || strings.Contains(string(encoded), "visitor-session") {
		t.Fatalf("unsafe or incomplete visitor metadata: %s, requests=%d, error=%v", encoded, requests, err)
	}
	protocol, public = "postgres", true
	service := resolver.project.Config.Services["web"]
	service.Protocol, service.Tunnel = &protocol, nil
	service.Target.Address = testTarget("db.internal:5432")
	resolver.project.Config.Services["web"] = service
	metadata, err = resolver.Generate(t.Context())
	if err != nil || metadata.Services["web"].Protocol != "postgres" || !metadata.Services["web"].Public || metadata.Services["web"].URL != "" {
		t.Fatalf("native metadata lost actual exposure: %+v %v", metadata, err)
	}
	hostname = "INVALID.tnl.dev"
	_, err = resolver.Generate(t.Context())
	if err == nil || !strings.Contains(err.Error(), `service "web": service hostname must be a canonical hostname`) {
		t.Fatalf("invalid remote metadata lost its validation error: %v", err)
	}
}

func testTarget(value string) *config.Target { target := config.Target(value); return &target }
