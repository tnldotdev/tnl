package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publishertarget"
)

func TestComposeOverrideIsGeneratedForWorktreeWithoutAppCredentialInConfig(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "compose.yaml")
	if err := os.WriteFile(base, []byte("services:\n  publisher:\n    image: example/publisher\n  web:\n    image: example/web\n  db:\n    image: example/db\n"), 0600); err != nil {
		t.Fatal(err)
	}
	project := projectconfig.Project{Root: root, Worktree: projectconfig.Worktree{Label: projectconfig.WorktreeLabel{FullLabel: "project-checkout-abc123"}}, Config: config.TNL{
		Publisher: &config.AppPublisher{Type: "compose", Service: "publisher"},
		Services:  config.Services{"web": {Target: &config.ServiceTarget{Type: "app"}}, "db": {Protocol: stringPtr("redis"), Target: &config.ServiceTarget{Type: "compose", Service: stringPtr("db"), Port: intPtr(6379)}}},
	}}
	path, err := writeComposeOverride(project, base)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := config.LoadDocument(filepath.Join(root, ".tnl", "compose.project.json"))
	if err != nil || snapshot.TNL == nil || snapshot.TNL.Publisher == nil || len(snapshot.TNL.Services) != 2 {
		t.Fatalf("publisher cannot read host-prepared configuration without Node: %+v, %v", snapshot, err)
	}
	inside, _, err := runtimeProject(t.Context(), runtimeOptions{Directory: root, StateDir: filepath.Join(t.TempDir(), "owner-state"), ComposeOwner: true})
	if err != nil || inside.Root != root || inside.Config.Publisher == nil || inside.Config.Publisher.Service != "publisher" || len(inside.Config.Services) != 2 {
		t.Fatalf("native Compose owner did not consume host-resolved project config: %+v, %v", inside, err)
	}
	for _, expected := range []string{"tnl.worktree: project-checkout-abc123", "TNL_APP_ENDPOINT: /run/tnl/apps/web/private/endpoint.json", "TNL_APP_AUTHORITY: http://publisher:8123", "tnl-owner-state:/run/tnl/state", "tnl-project-metadata:/run/tnl/.tnl", "tnl-project-metadata:/workspace/.tnl:ro", "tnl-app-web:/run/tnl/apps/web:ro", "tnl-private:"} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("generated override missing %q:\n%s", expected, data)
		}
	}
	if strings.Contains(string(data), "publisher_id:") || strings.Contains(string(data), "capability:") || strings.Contains(string(data), "private_key:") {
		t.Fatal("generated override contains a credential")
	}
	if path2, err := writeComposeOverride(project, base); err != nil || path2 != path {
		t.Fatalf("generation is not idempotent: %s: %v", path2, err)
	}
	args := strings.Join(publishertarget.ComposeArgs(root, base, "project-checkout-abc123"), " ")
	if !strings.Contains(args, "--file "+base+" --file "+path) {
		t.Fatalf("compose discovery did not use the generated override: %s", args)
	}
	if err := os.WriteFile(path, []byte("unmanaged: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeComposeOverride(project, base); err == nil {
		t.Fatal("replaced an unrelated compose override")
	}
}

func intPtr(value int) *int          { return &value }
func stringPtr(value string) *string { return &value }

func TestComposeProjectMountMatchesDockerDesktopHostSource(t *testing.T) {
	root := "/private/var/folders/project"
	mount := publishertarget.Mount{Type: "bind", Source: root, Destination: "/workspace"}
	if !composeProjectMount(mount, root) {
		t.Fatal("exact host root mount was rejected")
	}
	mount.Source = "/host_mnt" + root
	if got, want := composeProjectMount(mount, root), runtime.GOOS == "darwin"; got != want {
		t.Fatalf("docker desktop host mount matched=%t, want %t", got, want)
	}
	mount.Source += "/different"
	if composeProjectMount(mount, root) {
		t.Fatal("different host root mount matched")
	}
	mount.Source, mount.Type = root, "volume"
	if composeProjectMount(mount, root) {
		t.Fatal("project volume was accepted as a bind mount")
	}
}

func TestComposeOverrideDockerConfig(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker compose is unavailable")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("docker compose is unavailable")
	}
	root := t.TempDir()
	base := filepath.Join(root, "compose.yaml")
	if err := os.WriteFile(base, []byte("services:\n  publisher:\n    image: example/publisher\n  web:\n    image: example/web\n"), 0600); err != nil {
		t.Fatal(err)
	}
	project := projectconfig.Project{Root: root, Worktree: projectconfig.Worktree{Label: projectconfig.WorktreeLabel{FullLabel: "worktree-abc123"}}, Config: config.TNL{
		Publisher: &config.AppPublisher{Type: "compose", Service: "publisher"},
		Services:  config.Services{"web": {Target: &config.ServiceTarget{Type: "app"}}},
	}}
	if _, err := writeComposeOverride(project, base); err != nil {
		t.Fatal(err)
	}
	args := append(publishertarget.ComposeArgs(root, base, "worktree-abc123"), "config", "--format", "json")
	command := exec.CommandContext(context.Background(), "docker", args...)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("generated override is not a valid Compose project: %v\n%s", err, output)
	}
	var rendered struct {
		Services map[string]struct {
			Labels      map[string]string `json:"labels"`
			Environment map[string]string `json:"environment"`
			Volumes     []struct {
				Source   string `json:"source"`
				Target   string `json:"target"`
				ReadOnly bool   `json:"read_only"`
			} `json:"volumes"`
		} `json:"services"`
		Networks map[string]struct {
			Labels map[string]string `json:"labels"`
		} `json:"networks"`
	}
	if err := json.Unmarshal(output, &rendered); err != nil {
		t.Fatal(err)
	}
	owner, app := rendered.Services["publisher"], rendered.Services["web"]
	if owner.Labels["tnl.worktree"] != "worktree-abc123" || app.Labels["tnl.worktree"] != "worktree-abc123" || app.Environment["TNL_APP_ENDPOINT"] != "/run/tnl/apps/web/private/endpoint.json" || app.Environment["TNL_APP_AUTHORITY"] != "http://publisher:8123" {
		t.Fatalf("compose lost worktree identity or app endpoint: owner=%+v app=%+v", owner, app)
	}
	var sharedVolume, metadataVolume string
	for _, mount := range owner.Volumes {
		if mount.Target == "/run/tnl/apps/web" {
			sharedVolume = mount.Source
		}
		if mount.Target == "/run/tnl/.tnl" && !mount.ReadOnly {
			metadataVolume = mount.Source
		}
	}
	var isolated, browserMetadata bool
	for _, mount := range app.Volumes {
		if mount.Source == sharedVolume && sharedVolume != "" && mount.ReadOnly && mount.Target == "/run/tnl/apps/web" {
			isolated = true
		}
		if mount.Source == metadataVolume && metadataVolume != "" && mount.ReadOnly && mount.Target == "/workspace/.tnl" {
			browserMetadata = true
		}
		if mount.Target == "/run/tnl/state" {
			t.Fatal("app received the publisher's state volume")
		}
	}
	if !isolated || !browserMetadata {
		t.Fatalf("app descriptor or browser-safe metadata volume was not isolated: owner=%+v app=%+v", owner.Volumes, app.Volumes)
	}
}
