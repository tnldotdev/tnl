package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/publishertarget"
)

var composeOwnerIntegration = flag.Bool("tnl-compose-integration", false, "run disposable generated Compose publisher integration")

// this fixture uses the actual tnl binary and generated override. it does not
// need a deployed server: URL publication is checked by the split topology
// tests while this test checks container startup and private app capabilities.
func TestComposeGeneratedOwnerBootsAndScopesApp(t *testing.T) {
	if !*composeOwnerIntegration {
		t.Skip("requires -tnl-compose-integration")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	if err := publishertarget.Local(ctx, publishertarget.CLI{}); err != nil {
		t.Fatal(err)
	}
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	image := "mirror.gcr.io/library/golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61"
	binary := filepath.Join(root, "tnl-linux")
	architecture, err := (publishertarget.CLI{}).Run(ctx, nil, "info", "--format", "{{.Architecture}}")
	if err != nil {
		t.Fatal(err)
	}
	arch := strings.TrimSpace(string(architecture))
	switch arch {
	case "x86_64":
		arch = "amd64"
	case "aarch64":
		arch = "arm64"
	}
	if arch != "amd64" && arch != "arm64" {
		t.Fatalf("unsupported disposable Docker architecture %q", arch)
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/tnl")
	build.Dir = repository
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native publisher: %v\n%s", err, output)
	}
	fixture := filepath.Join(root, "compose-app-linux")
	build = exec.CommandContext(ctx, "go", "build", "-o", fixture, "./internal/tnldruntime/testdata/compose-owner")
	build.Dir = repository
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Compose app fixture: %v\n%s", err, output)
	}
	base := filepath.Join(root, "compose.yaml")
	compose := fmt.Sprintf("services:\n  publisher:\n    image: %s\n    volumes:\n      - %q\n  web:\n    image: %s\n    volumes:\n      - %q\n    command: [/fixture/app, app]\n", image, binary+":/usr/local/bin/tnl:ro", image, fixture+":/fixture/app:ro")
	if err := os.WriteFile(base, []byte(compose), 0600); err != nil {
		t.Fatal(err)
	}
	projectConfig := "version: 1\ntnl:\n  server: https://control.integration.test\n  publisher: {type: compose, service: publisher}\n  services:\n    web:\n      target: {type: app}\n"
	if err := os.WriteFile(filepath.Join(root, "tnl.yml"), []byte(projectConfig), 0600); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(t.TempDir(), "client-state")
	project, file, err := selectedComposeProject(ctx, cli{}, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if project.Root != root {
		t.Fatalf("selected project root %q differs from fixture root %q", project.Root, root)
	}
	if _, err := writeComposeOverride(project, file); err != nil {
		t.Fatal(err)
	}
	args := publishertarget.ComposeArgs(root, file, project.Worktree.Label.FullLabel)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		command := exec.CommandContext(cleanup, "docker", append(append([]string{}, args...), "down", "--volumes", "--remove-orphans", "--timeout", "2")...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("remove test-owned Compose project: %v: %s", err, output)
		}
	})
	up := exec.CommandContext(ctx, "docker", append(append([]string{}, args...), "up", "--detach")...)
	up.Dir = root
	if output, err := up.CombinedOutput(); err != nil {
		t.Fatalf("start generated publisher: %v\n%s", err, output)
	}
	owner, err := runtimeComposeOwner(ctx, project)
	if err != nil {
		container, inspectErr := publishertarget.ComposeContainer(ctx, publishertarget.CLI{}, root, file, project.Worktree.Label.FullLabel, "publisher", project.Worktree.Label.FullLabel)
		t.Fatalf("discover generated owner: %v; root=%q, mounts=%+v, inspect=%v", err, project.Root, container.Mounts, inspectErr)
	}
	setup, err := runtimeComposeHostSetup(ctx, project, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Configure(ctx, setup); err != nil {
		t.Fatal(err)
	}
	if err := runtimeWaitComposeOwner(ctx, owner); err != nil {
		t.Fatal(err)
	}
	query := append(append([]string{}, args...), "exec", "--no-TTY", "web", "cat", "/run/tnl/apps/web/private/endpoint.json")
	read := exec.CommandContext(ctx, "docker", query...)
	read.Dir = root
	data, err := read.CombinedOutput()
	if err != nil {
		t.Fatalf("app cannot read only its scoped descriptor: %v\n%s", err, data)
	}
	var endpoint privateprotocol.Endpoint
	if err := json.Unmarshal(data, &endpoint); err != nil || endpoint.Scope != "app" || endpoint.Service == nil || *endpoint.Service != "web" || endpoint.Capability == "" {
		t.Fatalf("invalid generated app endpoint: %v, scope=%q", err, endpoint.Scope)
	}
	if reply, err := owner.Call(ctx, localpublisher.ComposeQuery{Method: "GET", Path: "/v1/health"}); err != nil || reply.Status != 204 {
		t.Fatalf("generated owner cannot serve private requests: %+v, %v", reply, err)
	}
	appQuery := func(method, path, body string) localpublisher.ComposeReply {
		t.Helper()
		command := exec.CommandContext(ctx, "docker", append(append([]string{}, args...), "exec", "--no-TTY", "web", "/fixture/app", "query", "--method", method, "--path", path, "--body", body)...)
		command.Dir = root
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("app cannot use generated private endpoint: %v\n%s", err, output)
		}
		var reply localpublisher.ComposeReply
		if err := json.Unmarshal(output, &reply); err != nil {
			t.Fatalf("decode app private response: %v\n%s", err, output)
		}
		return reply
	}
	if reply := appQuery("GET", "/v1/status", ""); reply.Status != 200 {
		t.Fatalf("generated app endpoint cannot reach its publisher: %+v", reply)
	}
	if reply := appQuery("POST", "/v1/capabilities", `{"scope":"owner"}`); reply.Status != 403 {
		t.Fatalf("generated app endpoint can mint owner capabilities: %+v", reply)
	}
}
