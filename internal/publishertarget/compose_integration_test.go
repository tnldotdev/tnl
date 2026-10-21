package publishertarget

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

var composeIntegration = flag.Bool("tnl-compose-integration", false, "check disposable host-side Compose targets")

func TestComposeIntegrationHostTargets(t *testing.T) {
	if !*composeIntegration {
		t.Skip("requires -tnl-compose-integration")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	if err := Local(ctx, CLI{}); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate Compose target fixture")
	}
	repository := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	data, err := (CLI{}).Run(ctx, nil, "info", "--format", "{{.Architecture}}")
	if err != nil {
		t.Fatal(err)
	}
	arch := strings.TrimSpace(string(data))
	if arch == "aarch64" {
		arch = "arm64"
	} else if arch == "x86_64" {
		arch = "amd64"
	}
	if arch != "arm64" && arch != "amd64" {
		t.Fatalf("unsupported test Docker architecture %q", arch)
	}
	appBinary := filepath.Join(root, "compose-app-linux")
	build := exec.CommandContext(ctx, "go", "build", "-o", appBinary, "./internal/tnldruntime/testdata/compose-publisher")
	build.Dir, build.Env = repository, append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build disposable app: %v\n%s", err, output)
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	projectName := "tnl-compose-target-" + hex.EncodeToString(suffix[:])
	label := projectName
	file := filepath.Join(root, "compose.yaml")
	configuration := fmt.Sprintf("services:\n  web:\n    image: mirror.gcr.io/library/golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110\n    command: [/fixture/app]\n    labels:\n      tnl.worktree: %s\n    ports: ['127.0.0.1::3000']\n    volumes:\n      - %q\n  db:\n    image: mirror.gcr.io/library/redis:7.4-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499\n    labels:\n      tnl.worktree: %s\n    ports: ['127.0.0.1::6379']\n", label, appBinary+":/fixture/app:ro", label)
	if err := os.WriteFile(file, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	args := ComposeArgs(root, file, projectName)
	compose := func(arguments ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, "docker", append(append([]string{}, args...), arguments...)...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("run disposable Compose command: %v\n%s", err, output)
		}
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		command := exec.CommandContext(cleanup, "docker", append(append([]string{}, args...), "down", "--volumes", "--remove-orphans", "--timeout", "2")...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("remove disposable Compose project: %v\n%s", err, output)
		}
	})
	compose("up", "--detach", "--wait")
	web, db, protocol, relativeFile, webPort, dbPort := "web", "db", "tcp", "compose.yaml", 3000, 6379
	project := projectconfig.Project{Root: root, Worktree: projectconfig.Worktree{Label: projectconfig.WorktreeLabel{FullLabel: label}}, Config: config.TNL{Services: config.Services{
		"web": {Target: &config.ServiceTarget{Type: "compose", Project: &projectName, File: &relativeFile, Service: &web, Port: &webPort}, Tunnel: &config.Tunnel{}},
		"db":  {Protocol: &protocol, Target: &config.ServiceTarget{Type: "compose", Project: &projectName, File: &relativeFile, Service: &db, Port: &dbPort}},
	}}}
	resolver := Resolver{}
	readWeb := func(previous string) string {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			address, err := resolver.ResolveTarget(ctx, project, "web")
			if err == nil {
				client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
				var response *http.Response
				response, err = client.Get("http://" + address)
				if err == nil {
					body, readErr := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if readErr == nil && response.StatusCode == http.StatusOK && string(body) != "" && string(body) != previous {
						return string(body)
					}
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("replacement Compose target did not answer: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	first := readWeb("")
	address, err := resolver.ResolveTarget(ctx, project, "db")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(connection, "*1\r\n$4\r\nPING\r\n")
	answer := make([]byte, 7)
	if err == nil {
		_, err = io.ReadFull(connection, answer)
	}
	_ = connection.Close()
	if err != nil || string(answer) != "+PONG\r\n" {
		t.Fatalf("Compose database target response=%q: %v", answer, err)
	}
	compose("up", "--detach", "--no-deps", "--force-recreate", "web")
	_ = readWeb(first)
}
