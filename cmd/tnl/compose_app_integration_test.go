package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationComposePublisherAppScopedNetwork(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	t.Setenv("TNL_CONFIG", "")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "client")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	database, err := clientstate.Open(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := database.WorktreeHashSalt(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	worktree, err := projectconfig.ResolveWorktree(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	label := projectconfig.ApplyWorktreeHashSalt(worktree, root, salt).Label
	config := fmt.Sprintf(`{"version":1,"tnl":{"publisher":{"type":"docker","compose":{"file":"compose.yaml","project":%q,"service":"publisher"},"container_port":3781},"services":{"web":{"target":{"type":"app"}}}}}`, label.FullLabel)
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	metadata := projectmeta.Metadata{Version: projectmeta.Version, Namespace: "shop.example.test", Services: map[string]projectmeta.Service{},
		ServiceDirectories: map[string]string{}, Worktree: &projectmeta.Worktree{Label: label}}
	if err := projectmeta.Write(t.Context(), root, metadata); err != nil {
		t.Fatal(err)
	}
	owner, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".tnl", "publisher-owner"), []byte(owner), 0600); err != nil {
		t.Fatal(err)
	}
	script := `import {readFileSync,writeFileSync} from "node:fs";
import http from "node:http";
const endpoint = JSON.parse(readFileSync("/run/secrets/tnl-web.endpoint.json", "utf8"));
const server = http.createServer((_request, response) => response.end("app from Compose"));
server.listen(0, "0.0.0.0", async () => {
  try {
    const headers = {Authorization: "Bearer " + endpoint.credential};
    const status = await fetch(endpoint.url + "/v1/status", {headers});
    const snapshot = await status.json();
    const forbidden = await fetch(endpoint.url + "/v1/auth/status", {headers});
    if (status.status !== 200 || snapshot.services.length !== 1 || snapshot.services[0].service !== "web" || forbidden.status !== 401) process.exit(2);
    writeFileSync("/project/ready.json", JSON.stringify({port: server.address().port, url: endpoint.url}));
  } catch { process.exit(3); }
});
process.on("SIGTERM", () => server.close());
`
	if err := os.WriteFile(filepath.Join(root, "app.mjs"), []byte(script), 0644); err != nil {
		t.Fatal(err)
	}
	compose := `services:
  publisher:
    image: tnl:publisher-dev-integration
    user: "${TNL_UID}:${TNL_GID}"
    working_dir: ${PROJECT_ROOT}
    command: ["runtime", "serve", "--directory", "${PROJECT_ROOT}"]
    environment:
      TNL_PUBLISHER_EXTERNAL: "1"
      TNL_STATE_DIR: /state
      TNL_SERVER: https://control.example.test
    volumes:
      - ${PROJECT_ROOT}:${PROJECT_ROOT}
    tmpfs:
      - /state:uid=${TNL_UID},gid=${TNL_GID},mode=0700
    ports:
      - "127.0.0.1::3781"
  web:
    image: public.ecr.aws/docker/library/node:22.23.2-bookworm-slim@sha256:48e4b67d85f87bd551df43704e24d252f56cc5f8e9718841aace50f19948f0f9
    user: "${TNL_UID}:${TNL_GID}"
    working_dir: /project
    command: ["node", "/project/app.mjs"]
    volumes:
      - ${PROJECT_ROOT}:/project
      - ${PROJECT_ROOT}/.tnl/publisher-web.endpoint.json:/run/secrets/tnl-web.endpoint.json:ro
    depends_on: [publisher]
`
	if err := os.WriteFile(filepath.Join(root, "compose.yaml"), []byte(compose), 0600); err != nil {
		t.Fatal(err)
	}
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	t.Setenv("TNL_UID", uid)
	t.Setenv("TNL_GID", gid)
	t.Setenv("PROJECT_ROOT", root)
	command := func(timeout time.Duration, arguments ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		args := append([]string{"compose", "--project-directory", root, "--file", filepath.Join(root, "compose.yaml"), "--project-name", label.FullLabel}, arguments...)
		call := exec.CommandContext(ctx, "docker", args...)
		call.Dir = root
		output, err := call.CombinedOutput()
		return string(output), err
	}
	t.Cleanup(func() {
		if t.Failed() {
			if output, err := command(10*time.Second, "logs"); err == nil {
				t.Logf("Compose publisher/app logs:\n%s", output)
			}
		}
		if output, err := command(30*time.Second, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Errorf("remove disposable Compose publisher: %v (%s)", err, output)
		}
	})
	if output, err := command(90*time.Second, "up", "-d", "publisher"); err != nil {
		t.Fatalf("start Compose publisher: %v (%s)", err, output)
	}
	t.Chdir(root)
	deadline := time.Now().Add(15 * time.Second)
	var output, diagnostics bytes.Buffer
	for {
		output.Reset()
		diagnostics.Reset()
		err = run(t.Context(), []string{"project", "publisher", "credential", "export", "--service", "web", "--state-dir", state, "--output", "raw"}, &output, &diagnostics)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || strings.TrimSpace(output.String()) != filepath.Join(root, ".tnl", "publisher-web.endpoint.json") {
		t.Fatalf("export container app credential: %v, output=%q, diagnostics=%q", err, output.String(), diagnostics.String())
	}
	if output, err := command(90*time.Second, "up", "-d", "web"); err != nil {
		t.Fatalf("start Compose app: %v (%s)", err, output)
	}
	var ready struct {
		Port int    `json:"port"`
		URL  string `json:"url"`
	}
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(filepath.Join(root, "ready.json"))
		if err == nil && json.Unmarshal(data, &ready) == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if ready.Port < 1 || ready.URL != "http://publisher:3781" {
		t.Fatalf("Compose app did not attach through its scoped private endpoint: %+v", ready)
	}
	output.Reset()
	diagnostics.Reset()
	if err := run(t.Context(), []string{"status", "--state-dir", state, "--output", "json"}, &output, &diagnostics); err != nil {
		t.Fatalf("host could not read container publisher status: %v (%s)", err, diagnostics.String())
	}
	var status struct {
		Services []clientruntime.Service `json:"services"`
	}
	if err := json.Unmarshal(output.Bytes(), &status); err != nil || len(status.Services) != 1 || status.Services[0].Name != "web" {
		t.Fatalf("container publisher status = %s, %v", output.String(), err)
	}
	watchContext, stopWatch := context.WithTimeout(t.Context(), 3*time.Second)
	defer stopWatch()
	output.Reset()
	if err := run(watchContext, []string{"watch", "--state-dir", state, "--output", "ndjson"}, &output, &diagnostics); err != nil || !strings.Contains(output.String(), `"service":"web"`) {
		t.Fatalf("host could not watch container publisher: %v (%s)", err, output.String())
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", label.FullLabel+"_default", "--entrypoint", "node",
		"public.ecr.aws/docker/library/node:22.23.2-bookworm-slim@sha256:48e4b67d85f87bd551df43704e24d252f56cc5f8e9718841aace50f19948f0f9",
		"-e", fmt.Sprintf(`fetch('http://web:%d').then(async r => { if (!r.ok || await r.text() !== 'app from Compose') process.exit(1) }).catch(() => process.exit(1))`, ready.Port))
	probeOutput, err := probe.CombinedOutput()
	if err != nil {
		t.Fatalf("publisher network could not reach app's dynamic listener port: %v (%s)", err, probeOutput)
	}
}
