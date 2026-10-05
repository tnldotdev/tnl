package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

func TestDevBootstrapConfiguresAndRegistersOneTarget(t *testing.T) {
	ctx := devBootstrapTestContext(t)
	bootstrap := startDevBootstrapTest(t, ctx, "", t.TempDir())
	premature := postDevRequest(bootstrap, "/v1/target", devTargetRequest{
		Protocol: 1, Framework: "vite", Target: "http://127.0.0.1:5173",
	})
	if premature.err != nil || premature.status != http.StatusConflict {
		t.Fatalf("premature target result = %#v", premature)
	}
	invalid := postDevJSON(bootstrap, "/v1/configure", []byte(`{"protocol":1,"framework":"vite","options":{}}`))
	if invalid.err != nil || invalid.status != http.StatusBadRequest {
		t.Fatalf("unknown-field configuration result = %#v", invalid)
	}
	configuration := devConfigurationRequest{Protocol: 1, Framework: "vite"}
	configured, configurationDone := configureDevBootstrapTest(t, ctx, bootstrap, configuration)
	if !reflect.DeepEqual(configured, configuration) {
		t.Fatalf("configuration = %#v", configured)
	}
	want := devConfigurationResponse{
		Protocol: 1, TunnelID: "tun_0123456789abcdefghijkl",
		Service: nullableService("web"), Namespace: "member.example",
		Hostname: "agent-feature.example", PublicURL: "https://agent-feature.example",
		Project: projectmeta.PublicMetadata{
			Namespace: "member.example", Dev: true,
			Services: map[string]projectmeta.Service{
				"web": {Namespace: "member.example", Hostname: "agent-feature.example", URL: "https://agent-feature.example"},
			},
		},
	}
	bootstrap.Resolve(want, nil)
	result := awaitDevHTTPResult(t, ctx, configurationDone)
	var response devConfigurationResponse
	if result.err != nil || result.status != http.StatusOK || json.Unmarshal(result.body, &response) != nil || !reflect.DeepEqual(response, want) {
		t.Fatalf("configuration result = %#v, response = %#v", result, response)
	}
	result = postDevRequest(bootstrap, "/v1/configure", configuration)
	if result.err != nil || result.status != http.StatusOK {
		t.Fatalf("idempotent configuration result = %#v", result)
	}
	conflictingConfiguration := configuration
	conflictingConfiguration.Framework = "next"
	result = postDevRequest(bootstrap, "/v1/configure", conflictingConfiguration)
	if result.err != nil || result.status != http.StatusConflict {
		t.Fatalf("conflicting configuration result = %#v", result)
	}
	target := devTargetRequest{Protocol: 1, Framework: "vite", Target: "http://127.0.0.1:5173"}
	result = postDevRequest(bootstrap, "/v1/target", devTargetRequest{Protocol: 1, Framework: "vite", Target: "HTTP://LOCALHOST:05173"})
	if result.err != nil || result.status != http.StatusNoContent {
		t.Fatalf("target result = %#v", result)
	}
	registered, err := bootstrap.Target(ctx)
	if err != nil || !reflect.DeepEqual(registered, target) {
		t.Fatalf("target = %#v, err = %v", registered, err)
	}
	result = postDevRequest(bootstrap, "/v1/target", target)
	if result.err != nil || result.status != http.StatusNoContent {
		t.Fatalf("idempotent target result = %#v", result)
	}
	result = postDevRequest(bootstrap, "/v1/target", devTargetRequest{Protocol: 1, Framework: "vite", Target: "http://127.0.0.1:3000"})
	if result.err != nil || result.status != http.StatusConflict {
		t.Fatalf("conflicting target result = %#v", result)
	}
	result = postDevRequest(bootstrap, "/v1/target", devTargetRequest{Protocol: 1, Framework: "vite", Target: "http://192.0.2.1:5173"})
	if result.err != nil || result.status != http.StatusBadRequest {
		t.Fatalf("remote target result = %#v", result)
	}
}

func TestDevBootstrapRequiresTheForcedPortAndPreservesTheTargetHost(t *testing.T) {
	ctx := devBootstrapTestContext(t)
	bootstrap := startDevBootstrapTest(t, ctx, "http://127.0.0.1:5173", t.TempDir())
	_, done := configureDevBootstrapTest(t, ctx, bootstrap, devConfigurationRequest{Protocol: 1, Framework: "next"})
	bootstrap.Resolve(devConfigurationResponse{Protocol: 1}, nil)
	if result := awaitDevHTTPResult(t, ctx, done); result.err != nil || result.status != http.StatusOK {
		t.Fatalf("configuration result = %#v", result)
	}
	result := postDevRequest(bootstrap, "/v1/target", devTargetRequest{Protocol: 1, Framework: "next", Target: "http://[::1]:5173"})
	if result.err != nil || result.status != http.StatusNoContent {
		t.Fatalf("forced target result = %#v", result)
	}
	registered, err := bootstrap.Target(ctx)
	if err != nil || registered.Target != "http://[::1]:5173" {
		t.Fatalf("registered target = %#v, err = %v", registered, err)
	}
}

func TestDevBootstrapReturnsTargetMismatchDiagnostic(t *testing.T) {
	ctx := devBootstrapTestContext(t)
	bootstrap := startDevBootstrapTest(t, ctx, "http://127.0.0.1:5173", t.TempDir())
	_, done := configureDevBootstrapTest(t, ctx, bootstrap, devConfigurationRequest{Protocol: 1, Framework: "vite"})
	bootstrap.Resolve(devConfigurationResponse{Protocol: 1}, nil)
	if result := awaitDevHTTPResult(t, ctx, done); result.err != nil || result.status != http.StatusOK {
		t.Fatalf("configuration result = %#v", result)
	}
	result := postDevRequest(bootstrap, "/v1/target", devTargetRequest{Protocol: 1, Framework: "vite", Target: "http://127.0.0.2:5174"})
	if result.err != nil || result.status != http.StatusConflict {
		t.Fatalf("mismatched target result = %#v", result)
	}
	_, err := bootstrap.Target(ctx)
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.TargetMismatch {
		t.Fatalf("target error = %v, diagnostic = %q", err, code)
	}
}

func TestDevBootstrapTimesOutAndClosesIdempotently(t *testing.T) {
	ctx := devBootstrapTestContext(t)
	worktree := t.TempDir()
	bootstrap := startDevBootstrapTest(t, ctx, "", worktree)
	directory := filepath.Dir(bootstrap.socket)
	for path, mode := range map[string]os.FileMode{directory: 0o700, bootstrap.socket: 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s mode = %v, want %v", path, info.Mode().Perm(), mode)
		}
	}
	if duplicate, err := newDevBootstrap(ctx, "", worktree); err == nil {
		_ = duplicate.Close()
		t.Fatal("concurrent bootstrap was accepted")
	} else if err.Error() != "another tnl dev is already running for this project service" {
		t.Fatalf("concurrent bootstrap error = %v", err)
	}
	serviceBootstrap := startDevBootstrapTest(t, ctx, "", worktree, "web")
	if serviceBootstrap.socket == bootstrap.socket {
		t.Fatal("parallel service reused the project socket")
	}
	if duplicate, err := newDevBootstrap(ctx, "", worktree, "web"); err == nil {
		_ = duplicate.Close()
		t.Fatal("duplicate service bootstrap was accepted")
	}
	expired, cancel := context.WithTimeout(ctx, time.Millisecond)
	defer cancel()
	if _, err := bootstrap.Configuration(expired); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("configuration error = %v", err)
	}
	for range 2 {
		if err := bootstrap.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("shared runtime directory was removed: %v", err)
	}
	if _, err := os.Stat(bootstrap.socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session socket still exists: %v", err)
	}
	startDevBootstrapTest(t, ctx, "", worktree)
}

func TestDevLockDistinguishesRecursiveChildFromAnotherSession(t *testing.T) {
	ctx := devBootstrapTestContext(t)
	root := t.TempDir()
	bootstrap := startDevBootstrapTest(t, ctx, "", root, "app")
	_, err := newDevBootstrap(ctx, "", root, "app")
	if !errors.Is(err, errDevLockHeld) {
		t.Fatalf("lock error = %v", err)
	}
	command := []string{"pnpm", "dev"}
	if got := devBootstrapError(err, root, "app", command); got != err {
		t.Fatalf("independent session was changed: %v", got)
	}
	t.Setenv("TNL_DEV_SOCKET", bootstrap.socket)
	early := rejectNestedDevSession(root, "app", command)
	if code, ok := diagnostic.CodeOf(early); !ok || code != diagnostic.DevCommandRecursion {
		t.Fatalf("early recursive child error = %v, code = %s", early, code)
	}
	classified := devBootstrapError(err, root, "app", command)
	if code, ok := diagnostic.CodeOf(classified); !ok || code != diagnostic.DevCommandRecursion || !errors.Is(classified, errDevLockHeld) ||
		!strings.Contains(classified.Error(), "pnpm dev") {
		t.Fatalf("recursive child error = %v, code = %s", classified, code)
	}
	if got := devBootstrapError(err, root, "api", command); got != err {
		t.Fatalf("other service was classified as recursive: %v", got)
	}
	if err := bootstrap.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rejectNestedDevSession(root, "app", command); err != nil {
		t.Fatalf("stale child socket blocked a new session: %v", err)
	}
}

func TestDevCommandRecursionNamesOnlySafeCommands(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"scripts":{"dev":"tnl dev"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		command []string
		want    string
	}{
		{[]string{"pnpm", "dev"}, "pnpm dev"},
		{[]string{"pnpm", "run", "dev"}, "pnpm run dev"},
		{[]string{"npm", "run", "dev"}, "npm run dev"},
		{[]string{"yarn", "dev"}, "yarn dev"},
		{[]string{"bun", "run", "dev"}, "bun run dev"},
		{[]string{"bun", "dev"}, "bun dev"},
		{[]string{"tnl", "dev"}, "dev.command starts tnl dev"},
		{[]string{"next", "dev"}, ""},
	} {
		got := devCommandRecursion(test.command, root)
		if !strings.Contains(got, test.want) || (test.want == "" && got != "") {
			t.Fatalf("devCommandRecursion(%q) = %q, want %q", test.command, got, test.want)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"scripts":{"dev":"next dev"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := devCommandRecursion([]string{"pnpm", "dev"}, root); got != "" {
		t.Fatalf("safe package script = %q", got)
	}
}

func TestDevReportsARecursiveCommandBeforeOpeningASession(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"scripts":{"dev":"tnl dev"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "state")
	err := runDev(t.Context(), devCommand{
		remoteFlags: remoteFlags{StateDir: stateRoot}, Command: []string{"pnpm", "dev"}, commandDir: root,
	}, nil, io.Discard, io.Discard)
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.DevCommandRecursion {
		t.Fatalf("preflight error = %v, code = %s", err, code)
	}
	text, ok := diagnostic.TextForCommandError("tnl dev", err)
	if !ok || !strings.Contains(text, "pnpm dev") || !strings.Contains(text, diagnostic.HelpURL(diagnostic.DevCommandRecursion)) ||
		!strings.Contains(text, "TNL_DEV_COMMAND_RECURSION") {
		t.Fatalf("preflight output = %q", text)
	}
	if _, err := os.Stat(stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recursive command opened client state: %v", err)
	}
}

func devBootstrapTestContext(t *testing.T) context.Context {
	t.Helper()
	// t.TempDir's Darwin prefix plus the socket digest can exceed sockaddr_un.
	directory, err := os.MkdirTemp("/tmp", "tnl-dev-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("XDG_RUNTIME_DIR", directory)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func startDevBootstrapTest(t *testing.T, ctx context.Context, target, root string, services ...string) *devBootstrap {
	t.Helper()
	bootstrap, err := newDevBootstrap(ctx, target, root, services...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bootstrap.Close(); err != nil {
			t.Error(err)
		}
	})
	return bootstrap
}

func configureDevBootstrapTest(t *testing.T, ctx context.Context, bootstrap *devBootstrap, request devConfigurationRequest) (devConfigurationRequest, <-chan devHTTPResult) {
	t.Helper()
	done := make(chan devHTTPResult, 1)
	joined := make(chan struct{})
	requestCtx, cancel := context.WithCancel(ctx)
	go func() {
		defer close(joined)
		result := postDevRequest(bootstrap, "/v1/configure", request)
		done <- result
		// a failed HTTP request must also release Configuration's receive.
		if result.err != nil || result.status != http.StatusOK {
			cancel()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = bootstrap.Close()
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Error("configuration request did not join")
		}
	})
	configuration, err := bootstrap.Configuration(requestCtx)
	if err != nil {
		t.Fatalf("wait for configuration: %v", err)
	}
	return configuration, done
}

func awaitDevHTTPResult(t *testing.T, ctx context.Context, done <-chan devHTTPResult) devHTTPResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-ctx.Done():
		t.Fatal("development HTTP request did not finish")
		return devHTTPResult{}
	}
}

type devHTTPResult struct {
	status int
	body   []byte
	err    error
}

func postDevRequest(bootstrap *devBootstrap, path string, value any) devHTTPResult {
	body, err := json.Marshal(value)
	if err != nil {
		return devHTTPResult{err: err}
	}
	return postDevJSON(bootstrap, path, body)
}

func postDevJSON(bootstrap *devBootstrap, path string, body []byte) devHTTPResult {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", bootstrap.socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	request, err := http.NewRequest(http.MethodPost, "http://unix"+path, bytes.NewReader(body))
	if err != nil {
		return devHTTPResult{err: err}
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return devHTTPResult{err: err}
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	return devHTTPResult{status: response.StatusCode, body: responseBody, err: err}
}
