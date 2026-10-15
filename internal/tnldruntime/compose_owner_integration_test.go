package tnldruntime

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publishertarget"
)

var composeIntegration = flag.Bool("tnl-compose-integration", false, "run disposable Compose owner/target integration tests")

type composeTestRunner struct{ environment []string }

func (r composeTestRunner) Run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	command.Env = r.environment
	command.Stdin = strings.NewReader(string(input))
	var output, stderr strings.Builder
	command.Stdout, command.Stderr = &output, &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("test-owned Docker operation failed: %w: %s", err, stderr.String())
	}
	return []byte(output.String()), nil
}

type composeOwnerFixture struct {
	t       *testing.T
	runner  composeTestRunner
	project projectconfig.Project
	file    string
	name    string
	setup   localpublisher.ComposeSetup
}

func TestComposeIntegrationOwnerTargets(t *testing.T) {
	if !*composeIntegration {
		t.Skip("requires -tnl-compose-integration")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	if err := publishertarget.Local(ctx, publishertarget.CLI{}); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	architecture, err := (publishertarget.CLI{}).Run(ctx, nil, "info", "--format", "{{.Architecture}}")
	if err != nil {
		t.Fatal(err)
	}
	arch := strings.TrimSpace(string(architecture))
	switch arch {
	case "aarch64":
		arch = "arm64"
	case "x86_64":
		arch = "amd64"
	}
	if arch != "arm64" && arch != "amd64" {
		t.Fatalf("unsupported test Docker architecture %q", arch)
	}
	binary := filepath.Join(t.TempDir(), "compose-owner")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./internal/tnldruntime/testdata/compose-owner")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build compose fixture: %v\n%s", err, output)
	}
	firstRoot, secondRoot := composeIntegrationWorktrees(t, ctx, root)
	first := startComposeOwnerFixture(t, ctx, root, binary, firstRoot)
	second := startComposeOwnerFixture(t, ctx, root, binary, secondRoot)
	firstBody := first.httpTarget(ctx)
	secondBody := second.httpTarget(ctx)
	if firstBody == secondBody {
		t.Fatal("worktrees resolved the same app container")
	}
	first.tcpTarget(ctx)
	second.tcpTarget(ctx)
	first.assertAppScopes(ctx)
	second.assertAppScopes(ctx)
	old, err := publishertarget.ComposeContainer(ctx, first.runner, first.project.Root, first.file, first.name, "web", first.project.Worktree.Label.FullLabel)
	if err != nil {
		t.Fatal(err)
	}
	first.compose(ctx, "up", "--detach", "--no-deps", "--force-recreate", "web")
	current, err := publishertarget.ComposeContainer(ctx, first.runner, first.project.Root, first.file, first.name, "web", first.project.Worktree.Label.FullLabel)
	if err != nil || current.ID == old.ID {
		t.Fatalf("app was not actually replaced: %v", err)
	}
	if got := first.httpTarget(ctx); got == firstBody {
		t.Fatal("new requests still reached the replaced container")
	}
	if got := second.httpTarget(ctx); got != secondBody {
		t.Fatal("replacing one worktree changed the other worktree")
	}
	// the same API accepts HTTP and TCP leases; no app-only owner exists.
	for _, service := range []string{"web", "db"} {
		request := privateprotocol.Lease{Service: service, Owner: "0123456789abcdef0123456789abcdef", Pid: 123456789}
		body, _ := json.Marshal(request)
		reply := first.ownerQuery(ctx, localpublisher.ComposeQuery{Method: "POST", Path: "/v1/leases", Body: body})
		if reply.Status != 200 {
			t.Fatalf("same owner rejected %s lease: %d", service, reply.Status)
		}
	}
	first.appQuery(ctx, "web", "/v1/status", "--save", "/tmp/old-endpoint.json")
	first.compose(ctx, "restart", "publisher")
	first.waitApp(ctx, "web")
	stale := first.appQuery(ctx, "web", "/v1/status", "--descriptor", "/tmp/old-endpoint.json")
	if stale.Status != 401 {
		t.Fatalf("replacement owner accepted old capability: %d", stale.Status)
	}
	reply := first.ownerQuery(ctx, localpublisher.ComposeQuery{Method: "GET", Path: "/v1/status"})
	var snapshot clientruntime.Snapshot
	if json.Unmarshal(reply.Body, &snapshot) != nil {
		t.Fatal("invalid replacement snapshot")
	}
	for _, service := range snapshot.Services {
		if service.Ready || service.Routable || service.Registered {
			t.Fatalf("restart retained stale registration/readiness for %s", service.Name)
		}
	}
	second.assertAppScopes(ctx)
}

func composeIntegrationWorktrees(t *testing.T, ctx context.Context, repo string) (string, string) {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, second := filepath.Join(parent, "main"), filepath.Join(parent, "second")
	// a shared local clone supplies existing objects without creating commits or
	// changing the source repository's worktree registry. neither checkout needs
	// source files: the fixture installs only its own Compose configuration.
	clone := exec.CommandContext(ctx, "git", "clone", "--shared", "--no-checkout", "--", repo, first)
	if output, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("clone test worktree: %v\n%s", err, output)
	}
	worktree := exec.CommandContext(ctx, "git", "-C", first, "worktree", "add", "--detach", "--no-checkout", second, "HEAD")
	if output, err := worktree.CombinedOutput(); err != nil {
		t.Fatalf("add test worktree: %v\n%s", err, output)
	}
	return first, second
}

func startComposeOwnerFixture(t *testing.T, ctx context.Context, repo, binary, root string) *composeOwnerFixture {
	t.Helper()
	setupDir := filepath.Join(root, "setup")
	if err := os.Mkdir(setupDir, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repo, "internal/tnldruntime/testdata/compose-owner.compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "compose.yaml")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	id, err := privateprotocol.Random(6)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnl-compose-test-" + id
	worktreeInfo, err := projectconfig.ResolveWorktree(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if !worktreeInfo.IsGit {
		t.Fatal("Compose fixture is not in a real Git worktree")
	}
	worktreeInfo = projectconfig.ApplyWorktreeHashSalt(worktreeInfo, root, [32]byte{1})
	worktree := worktreeInfo.Label.FullLabel
	runner := composeTestRunner{environment: append(os.Environ(), "TNL_COMPOSE_FIXTURE_BINARY="+binary, "TNL_COMPOSE_FIXTURE_SETUP="+setupDir, "TNL_COMPOSE_FIXTURE_WORKTREE="+worktree)}
	project, service, relative, port := name, "web", "compose.yaml", 3000
	dbService, dbPort, dbProtocol := "db", 6379, "redis"
	p := projectconfig.Project{Root: root, Worktree: worktreeInfo, Config: config.TNL{Services: config.Services{
		"web": {Target: &config.ServiceTarget{Type: "compose", Project: &project, File: &relative, Service: &service, Port: &port}},
		"db":  {Protocol: &dbProtocol, Target: &config.ServiceTarget{Type: "compose", Project: &project, File: &relative, Service: &dbService, Port: &dbPort}},
	}}}
	f := &composeOwnerFixture{t: t, runner: runner, project: p, file: file, name: name}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		args := append(publishertarget.ComposeArgs(root, file, name), "down", "--volumes", "--remove-orphans", "--timeout", "2")
		if _, err := runner.Run(cleanup, nil, args...); err != nil {
			t.Error(err)
		}
	})
	f.compose(ctx, "up", "--detach")
	owner, err := publishertarget.ComposeContainer(ctx, runner, root, file, name, "publisher", worktree)
	if err != nil {
		t.Fatal(err)
	}
	network, err := localpublisher.ComposeNetwork(ctx, runner, owner, worktree)
	if err != nil {
		t.Fatal(err)
	}
	f.setup = localpublisher.ComposeSetup{Placement: publishertarget.Placement{ProjectRoot: root, Worktree: p.Worktree, PrimaryRoot: p.Worktree.PrimaryCheckoutRoot(), OwnerID: owner.ID, NetworkID: network}, Project: name, File: file, Service: "publisher", Port: 8123, ProjectRoot: "/project", Apps: map[string]localpublisher.ComposeApp{
		"web": {Service: "web", Endpoint: "/caps/web/private/endpoint.json"},
		"api": {Service: "api", Endpoint: "/caps/api/private/endpoint.json"},
	}}
	metadata, err := json.Marshal(f.setup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(setupDir, "placement.json"), metadata, 0600); err != nil {
		t.Fatal(err)
	}
	f.waitApp(ctx, "web")
	return f
}

func (f *composeOwnerFixture) compose(ctx context.Context, args ...string) []byte {
	f.t.Helper()
	output, err := f.runner.Run(ctx, nil, append(publishertarget.ComposeArgs(f.project.Root, f.file, f.name), args...)...)
	if err != nil {
		f.t.Fatal(err)
	}
	return output
}

func (f *composeOwnerFixture) waitApp(ctx context.Context, service string) {
	f.t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for {
		args := append(publishertarget.ComposeArgs(f.project.Root, f.file, f.name), "exec", "--no-TTY", service, "/fixture/owner", "query")
		output, err := f.runner.Run(ctx, nil, args...)
		var reply localpublisher.ComposeReply
		if err == nil && json.Unmarshal(output, &reply) == nil && reply.Status == 200 {
			return
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			logs := f.compose(context.Background(), "logs", "publisher")
			f.t.Fatalf("owner did not become ready: %v\n%s", err, logs)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (f *composeOwnerFixture) appQuery(ctx context.Context, service, path string, options ...string) localpublisher.ComposeReply {
	f.t.Helper()
	args := []string{"exec", "--no-TTY", service, "/fixture/owner", "query", "--path", path}
	output := f.compose(ctx, append(args, options...)...)
	var reply localpublisher.ComposeReply
	if err := json.Unmarshal(output, &reply); err != nil {
		f.t.Fatal(err)
	}
	return reply
}

func (f *composeOwnerFixture) ownerQuery(ctx context.Context, query localpublisher.ComposeQuery) localpublisher.ComposeReply {
	f.t.Helper()
	input, _ := json.Marshal(query)
	args := append(publishertarget.ComposeArgs(f.project.Root, f.file, f.name), "exec", "--no-TTY", "publisher", "/fixture/owner", "exec-query")
	output, err := f.runner.Run(ctx, input, args...)
	if err != nil {
		f.t.Fatal(err)
	}
	var reply localpublisher.ComposeReply
	if json.Unmarshal(output, &reply) != nil {
		f.t.Fatal("invalid exec query response")
	}
	return reply
}

func (f *composeOwnerFixture) assertAppScopes(ctx context.Context) {
	f.t.Helper()
	for _, name := range []string{"web", "api"} {
		reply := f.appQuery(ctx, name, "/v1/status")
		var snapshot clientruntime.Snapshot
		if reply.Status != 200 || json.Unmarshal(reply.Body, &snapshot) != nil || len(snapshot.Services) != 1 || snapshot.Services[0].Name != name {
			f.t.Fatalf("%s could see another service", name)
		}
		reply = f.appQuery(ctx, name, "/v1/capabilities", "--method", "POST", "--body", `{"scope":"app","service":"web"}`)
		if reply.Status != 403 {
			f.t.Fatalf("%s could mint sibling credentials", name)
		}
	}
}

func (f *composeOwnerFixture) httpTarget(ctx context.Context) string {
	f.t.Helper()
	address, err := (publishertarget.Resolver{Docker: f.runner}).ResolveTarget(ctx, f.project, "web")
	if err != nil {
		f.t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://"+address, nil)
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(body)
}

func (f *composeOwnerFixture) tcpTarget(ctx context.Context) {
	f.t.Helper()
	address, err := (publishertarget.Resolver{Docker: f.runner}).ResolveTarget(ctx, f.project, "db")
	if err != nil {
		f.t.Fatal(err)
	}
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		f.t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(connection, "*1\r\n$4\r\nPING\r\n"); err != nil {
		f.t.Fatal(err)
	}
	response := make([]byte, 7)
	if _, err := io.ReadFull(connection, response); err != nil || string(response) != "+PONG\r\n" {
		f.t.Fatalf("TCP target response=%q err=%v", response, err)
	}
}
