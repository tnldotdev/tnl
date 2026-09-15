package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

func TestDevCommandPassesThroughCommandArguments(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	arguments, command, err := splitDevPassthrough([]string{"dev", "web", "--host", "demo", "--", "npm", "run", "dev", "--", "--host"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse(arguments)
	if err != nil {
		t.Fatal(err)
	}
	flags.Dev.Command = command
	if parsed.Command() != "dev <service>" {
		t.Fatalf("command = %q", parsed.Command())
	}
	want := []string{"npm", "run", "dev", "--", "--host"}
	if flags.Dev.Service != "web" || flags.Dev.Host != "demo" || !reflect.DeepEqual(flags.Dev.Command, want) {
		t.Fatalf("host = %q, command = %#v", flags.Dev.Host, flags.Dev.Command)
	}
}

func TestResolveDevCommandRemovesSeparatorAndFindsExecutable(t *testing.T) {
	if command, err := resolveDevCommand(nil); err != nil || command != nil {
		t.Fatalf("optional command = %#v, %v", command, err)
	}
	command, err := resolveDevCommand([]string{"--", "sh", "-c", "exit 0"})
	if err != nil {
		t.Fatal(err)
	}
	if command[0] == "sh" || !reflect.DeepEqual(command[1:], []string{"-c", "exit 0"}) {
		t.Fatalf("command = %#v", command)
	}
	if _, err := resolveDevCommand([]string{"tnl-command-that-does-not-exist"}); err == nil {
		t.Fatal("missing executable was accepted")
	}
}

func TestResolveDevCommandFindsProjectLocalExecutable(t *testing.T) {
	directory := t.TempDir()
	binDirectory := filepath.Join(directory, "node_modules", ".bin")
	if err := os.MkdirAll(binDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(binDirectory, "next")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	globalDirectory := t.TempDir()
	globalExecutable := filepath.Join(globalDirectory, "next")
	if err := os.WriteFile(globalExecutable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", globalDirectory)

	command, err := resolveDevCommand([]string{"next", "dev"}, directory)
	if err != nil {
		t.Fatal(err)
	}
	if command[0] != executable || !reflect.DeepEqual(command[1:], []string{"dev"}) {
		t.Fatalf("command = %#v", command)
	}
}

func TestDevBootstrapConfiguresAndRegistersOneTarget(t *testing.T) {
	bootstrap, err := newDevBootstrap(t.Context(), "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bootstrap.Close(); err != nil {
			t.Error(err)
		}
	})

	premature := postDevRequest(bootstrap, "/v1/target", devTargetRequest{
		Protocol: 1, Framework: "vite", Target: "http://127.0.0.1:5173",
	})
	if premature.err != nil || premature.status != http.StatusConflict {
		t.Fatalf("premature target result = %#v", premature)
	}
	invalid := postDevJSON(
		bootstrap,
		"/v1/configure",
		[]byte(`{"protocol":1,"framework":"vite","options":{}}`),
	)
	if invalid.err != nil || invalid.status != http.StatusBadRequest {
		t.Fatalf("unknown-field configuration result = %#v", invalid)
	}
	configuration := devConfigurationRequest{Protocol: 1, Framework: "vite"}
	configurationDone := make(chan devHTTPResult, 1)
	go func() {
		configurationDone <- postDevJSON(
			bootstrap,
			"/v1/configure",
			[]byte(`{"protocol":1,"framework":"vite"}`),
		)
	}()
	configured, err := bootstrap.Configuration(context.Background())
	if err != nil || !reflect.DeepEqual(configured, configuration) {
		t.Fatalf("configuration = %#v, err = %v", configured, err)
	}
	want := devConfigurationResponse{
		Protocol: 1, TunnelID: "tunnel_0123456789abcdef0123456789abcdef",
		Service: nullableService("web"), MemberNamespace: "member.example",
		Hostname: "agent-feature.example", PublicURL: "https://agent-feature.example",
		Project: projectmeta.PublicMetadata{
			MemberNamespace: "member.example", RunningUnderTnlDev: true,
			Services: map[string]projectmeta.Service{
				"web": {
					MemberNamespace: "member.example", Hostname: "agent-feature.example",
					URL: "https://agent-feature.example",
				},
			},
		},
	}
	bootstrap.Resolve(want, nil)
	result := <-configurationDone
	var response devConfigurationResponse
	if result.err != nil || result.status != http.StatusOK || json.Unmarshal(result.body, &response) != nil ||
		!reflect.DeepEqual(response, want) {
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
	result = postDevRequest(bootstrap, "/v1/target", devTargetRequest{
		Protocol: 1, Framework: "vite", Target: "HTTP://LOCALHOST:05173",
	})
	if result.err != nil || result.status != http.StatusNoContent {
		t.Fatalf("target result = %#v", result)
	}
	registered, err := bootstrap.Target(context.Background())
	if err != nil || !reflect.DeepEqual(registered, target) {
		t.Fatalf("target = %#v, err = %v", registered, err)
	}
	result = postDevRequest(bootstrap, "/v1/target", target)
	if result.err != nil || result.status != http.StatusNoContent {
		t.Fatalf("idempotent target result = %#v", result)
	}
	result = postDevRequest(bootstrap, "/v1/target", devTargetRequest{
		Protocol: 1, Framework: "vite", Target: "http://127.0.0.1:3000",
	})
	if result.err != nil || result.status != http.StatusConflict {
		t.Fatalf("conflicting target result = %#v", result)
	}
	result = postDevRequest(bootstrap, "/v1/target", devTargetRequest{
		Protocol: 1, Framework: "vite", Target: "http://192.0.2.1:5173",
	})
	if result.err != nil || result.status != http.StatusBadRequest {
		t.Fatalf("non-loopback target result = %#v", result)
	}
}

func TestDevBootstrapRequiresTheForcedPortAndPreservesTheLoopbackHost(t *testing.T) {
	bootstrap, err := newDevBootstrap(t.Context(), "http://127.0.0.1:5173", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bootstrap.Close(); err != nil {
			t.Error(err)
		}
	})

	configurationDone := make(chan devHTTPResult, 1)
	go func() {
		configurationDone <- postDevRequest(bootstrap, "/v1/configure", devConfigurationRequest{
			Protocol: 1, Framework: "next",
		})
	}()
	if _, err := bootstrap.Configuration(t.Context()); err != nil {
		t.Fatal(err)
	}
	bootstrap.Resolve(devConfigurationResponse{Protocol: 1}, nil)
	if result := <-configurationDone; result.err != nil || result.status != http.StatusOK {
		t.Fatalf("configuration result = %#v", result)
	}

	result := postDevRequest(bootstrap, "/v1/target", devTargetRequest{
		Protocol: 1, Framework: "next", Target: "http://[::1]:5173",
	})
	if result.err != nil || result.status != http.StatusNoContent {
		t.Fatalf("forced target result = %#v", result)
	}
	registered, err := bootstrap.Target(t.Context())
	if err != nil || registered.Target != "http://[::1]:5173" {
		t.Fatalf("registered target = %#v, err = %v", registered, err)
	}
}

func TestDevBootstrapReturnsTargetMismatchDiagnostic(t *testing.T) {
	bootstrap, err := newDevBootstrap(t.Context(), "http://127.0.0.1:5173", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Close()

	configurationDone := make(chan devHTTPResult, 1)
	go func() {
		configurationDone <- postDevRequest(bootstrap, "/v1/configure", devConfigurationRequest{
			Protocol: 1, Framework: "vite",
		})
	}()
	if _, err := bootstrap.Configuration(t.Context()); err != nil {
		t.Fatal(err)
	}
	bootstrap.Resolve(devConfigurationResponse{Protocol: 1}, nil)
	if result := <-configurationDone; result.err != nil || result.status != http.StatusOK {
		t.Fatalf("configuration result = %#v", result)
	}

	result := postDevRequest(bootstrap, "/v1/target", devTargetRequest{
		Protocol: 1, Framework: "vite", Target: "http://127.0.0.2:5174",
	})
	if result.err != nil || result.status != http.StatusConflict {
		t.Fatalf("mismatched target result = %#v", result)
	}
	_, err = bootstrap.Target(t.Context())
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.TargetMismatch {
		t.Fatalf("target error = %v, diagnostic = %q", err, code)
	}
}

func TestDevSocketDigestGoldenVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "dev-socket-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		ProjectRoot string `json:"projectRoot"`
		Service     string `json:"service"`
		Digest      string `json:"digest"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		if got := devSocketDigest(vector.ProjectRoot, vector.Service); got != vector.Digest {
			t.Fatalf("digest(%q, %q) = %q, want %q", vector.ProjectRoot, vector.Service, got, vector.Digest)
		}
	}
}

func TestDevProtocolUsesExplicitNullForAdHocService(t *testing.T) {
	data, err := json.Marshal(devConfigurationResponse{
		Protocol: 1, TunnelID: "tunnel_0123456789abcdef0123456789abcdef",
		MemberNamespace: "member.example", Hostname: "route.member.example",
		PublicURL: "https://route.member.example",
		Project: projectmeta.PublicMetadata{
			MemberNamespace: "member.example", Services: map[string]projectmeta.Service{}, RunningUnderTnlDev: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"service":null`)) || bytes.Contains(data, []byte("serviceDirectories")) {
		t.Fatalf("response = %s", data)
	}
}

func TestRuntimeProjectMetadataUsesTheSelectedTunnelAssignment(t *testing.T) {
	metadata := projectmeta.Metadata{
		Version: projectmeta.Version, MemberNamespace: "root.example",
		Services: map[string]projectmeta.Service{
			"api": {
				MemberNamespace: "configured.example", Hostname: "api.configured.example",
				URL: "https://api.configured.example",
			},
		},
		ServiceDirectories: map[string]string{"api": "."},
	}
	project := runtimeProjectMetadata(metadata, "api", "runtime.example", "override.runtime.example")
	if project.MemberNamespace != "root.example" || !project.RunningUnderTnlDev ||
		project.Services["api"].MemberNamespace != "runtime.example" ||
		project.Services["api"].Hostname != "override.runtime.example" ||
		metadata.Services["api"].Hostname != "api.configured.example" {
		t.Fatalf("runtime project = %#v, metadata = %#v", project, metadata)
	}
}

func TestDevBootstrapTimesOutAndClosesIdempotently(t *testing.T) {
	worktree := t.TempDir()
	bootstrap, err := newDevBootstrap(t.Context(), "", worktree)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(bootstrap.socket)
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("session directory mode = %v", info.Mode().Perm())
	}
	info, err = os.Stat(bootstrap.socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("session socket mode = %v", info.Mode().Perm())
	}
	if _, err := newDevBootstrap(t.Context(), "", worktree); err == nil ||
		err.Error() != "another tnl dev is already running for this project service" {
		t.Fatalf("concurrent bootstrap error = %v", err)
	}
	serviceBootstrap, err := newDevBootstrap(t.Context(), "", worktree, "web")
	if err != nil {
		t.Fatalf("parallel service bootstrap: %v", err)
	}
	defer serviceBootstrap.Close()
	if serviceBootstrap.socket == bootstrap.socket {
		t.Fatal("parallel service reused the project socket")
	}
	if _, err := newDevBootstrap(t.Context(), "", worktree, "web"); err == nil {
		t.Fatal("duplicate service bootstrap was accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := bootstrap.Configuration(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("configuration error = %v", err)
	}
	if err := bootstrap.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("shared runtime directory was removed: %v", err)
	}
	if _, err := os.Stat(bootstrap.socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session socket still exists: %v", err)
	}
	replacement, err := newDevBootstrap(t.Context(), "", worktree)
	if err != nil {
		t.Fatalf("replacement bootstrap: %v", err)
	}
	defer replacement.Close()
}

func TestDevEnvironmentReplacesProtocolAndRemovesAccessToken(t *testing.T) {
	t.Setenv("PORT", "9999")
	t.Setenv("TNL_ACCESS_TOKEN", "secret")
	t.Setenv("TNL_LOGIN_TOKEN", "test-login-token-sentinel")
	t.Setenv("TNL_DEV_PROTOCOL", "old")
	t.Setenv("TNL_TUNNEL_ID", "stale")
	t.Setenv("TNL_PUBLIC_HOSTNAME", "stale.example")
	t.Setenv("TNL_PUBLIC_URL", "https://stale.example")
	t.Setenv("TNL_PROJECT_RUNTIME", `{"memberNamespace":"stale.example"}`)
	bootstrap := &devBootstrap{socket: "/private/control.sock"}
	environment := environmentMap(devEnvironment(bootstrap, 3000))
	if environment["PORT"] != "3000" || environment["TNL_DEV_PORT"] != "3000" ||
		environment["TNL_DEV_PROTOCOL"] != "1" || environment["TNL_DEV_SOCKET"] != bootstrap.socket {
		t.Fatal("development protocol environment was not replaced")
	}
	for _, name := range []string{"TNL_ACCESS_TOKEN", "TNL_LOGIN_TOKEN", "TNL_PROJECT_RUNTIME", "TNL_TUNNEL_ID", "TNL_PUBLIC_HOSTNAME", "TNL_PUBLIC_URL"} {
		if _, found := environment[name]; found {
			t.Fatalf("%s was passed to the development server", name)
		}
	}
}

func TestChildResultPreservesExitStatus(t *testing.T) {
	process, err := startDevProcess([]string{"sh", "-c", "exit 23"}, os.Environ(), nil, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	<-process.Done()
	err = childResult(process.Err())
	var exitErr *childExitError
	if !errors.As(err, &exitErr) || exitErr.code != 23 {
		t.Fatalf("exit error = %#v", err)
	}
}

func TestWaitForDevTargetStopsWhenCommandExits(t *testing.T) {
	bootstrap, err := newDevBootstrap(t.Context(), "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Close()
	process, err := startDevProcess(
		[]string{"sh", "-c", "exit 0"},
		os.Environ(),
		nil,
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := waitForDevTarget(ctx, bootstrap, process); err == nil ||
		err.Error() != "development server command exited before target registration" {
		t.Fatalf("wait error = %v", err)
	}
}

func TestDevProcessNaturalLeaderExitKillsDescendants(t *testing.T) {
	process, output, reader := startDevProcessTestCommand(t, "natural")
	waitForDevProcessDone(t, process)
	assertDevProcessExitStatus(t, process, 23)
	assertDevProcessOutputEOF(t, output, reader)
}

func TestDevProcessResponsiveStopKillsDescendantsAndPreservesExitStatus(t *testing.T) {
	process, output, reader := startDevProcessTestCommand(t, "responsive")
	stopped := make(chan error, 1)
	go func() { stopped <- process.Stop(5 * time.Second) }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop waited for its timeout after the leader exited")
	}
	assertDevProcessExitStatus(t, process, 23)
	assertDevProcessOutputEOF(t, output, reader)
}

func TestDevProcessStopEscalatesWhenLeaderIgnoresSIGTERM(t *testing.T) {
	process, output, reader := startDevProcessTestCommand(t, "ignoring")
	const timeout = 100 * time.Millisecond
	started := time.Now()
	if err := process.Stop(timeout); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < timeout {
		t.Fatalf("Stop escalated after %s, before its %s timeout", elapsed, timeout)
	}
	var exitErr *exec.ExitError
	if err := process.Err(); !errors.As(err, &exitErr) {
		t.Fatalf("leader wait error = %v", err)
	}
	status, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("leader wait status = %v", exitErr.ProcessState.Sys())
	}
	assertDevProcessOutputEOF(t, output, reader)
}

func TestDevProcessConcurrentStop(t *testing.T) {
	process, output, reader := startDevProcessTestCommand(t, "responsive")
	const callers = 8
	started := make(chan struct{})
	stopped := make(chan error, callers)
	for range callers {
		go func() {
			<-started
			stopped <- process.Stop(5 * time.Second)
		}()
	}
	close(started)
	for range callers {
		select {
		case err := <-stopped:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent Stop did not return after the leader exited")
		}
	}
	assertDevProcessExitStatus(t, process, 23)
	assertDevProcessOutputEOF(t, output, reader)
}

func TestDevProcessRepeatedStop(t *testing.T) {
	process, output, reader := startDevProcessTestCommand(t, "responsive")
	if err := process.Stop(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := process.Stop(0); err != nil {
			t.Fatalf("repeated Stop: %v", err)
		}
	}
	assertDevProcessExitStatus(t, process, 23)
	assertDevProcessOutputEOF(t, output, reader)
}

func startDevProcessTestCommand(t *testing.T, mode string) (*devProcess, *os.File, *bufio.Reader) {
	t.Helper()
	output, outputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = output.Close() })
	executable, err := os.Executable()
	if err != nil {
		_ = outputWriter.Close()
		t.Fatal(err)
	}
	process, err := startDevProcess(
		[]string{executable, "-test.run=^TestDevProcessHelper$", "--", mode},
		append(os.Environ(), "TNL_TEST_DEV_PROCESS_HELPER=1", "GORACE=atexit_sleep_ms=0"),
		nil, outputWriter, os.Stderr,
	)
	if closeErr := outputWriter.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.Stop(time.Second); err != nil {
			t.Errorf("stop development process during cleanup: %v", err)
		}
	})
	if err := output.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(output)
	if ready, err := reader.ReadString('\n'); err != nil || ready != "ready\n" {
		t.Fatalf("descendant readiness = %q, %v", ready, err)
	}
	return process, output, reader
}

func waitForDevProcessDone(t *testing.T, process *devProcess) {
	t.Helper()
	select {
	case <-process.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("development process leader did not exit")
	}
}

func assertDevProcessExitStatus(t *testing.T, process *devProcess, want int) {
	t.Helper()
	var exitErr *childExitError
	if err := childResult(process.Err()); !errors.As(err, &exitErr) || exitErr.code != want {
		t.Fatalf("leader exit result = %v, want status %d", err, want)
	}
}

func assertDevProcessOutputEOF(t *testing.T, output *os.File, reader *bufio.Reader) {
	t.Helper()
	if err := output.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("wait for descendant output EOF: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("unexpected descendant output: %q", remaining)
	}
}

func TestDevProcessHelper(t *testing.T) {
	if os.Getenv("TNL_TEST_DEV_PROCESS_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if mode == "descendant" {
		signal.Ignore(syscall.SIGTERM)
		if _, err := io.WriteString(os.Stdout, "ready\n"); err != nil {
			t.Fatal(err)
		}
		ready := os.NewFile(3, "leader-ready")
		if ready == nil {
			t.Fatal("missing leader readiness pipe")
		}
		if _, err := ready.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		if err := ready.Close(); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	var terminated chan os.Signal
	switch mode {
	case "natural":
	case "responsive":
		terminated = make(chan os.Signal, 1)
		signal.Notify(terminated, syscall.SIGTERM)
	case "ignoring":
		signal.Ignore(syscall.SIGTERM)
	default:
		t.Fatal("unknown development process helper mode")
	}
	ready, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestDevProcessHelper$", "--", "descendant")
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{readyWriter}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := readyWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ready, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := ready.Close(); err != nil {
		t.Fatal(err)
	}
	if mode == "natural" {
		os.Exit(23)
	}
	if mode == "responsive" {
		<-terminated
		os.Exit(23)
	}
	for {
		time.Sleep(time.Hour)
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
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", bootstrap.socket)
		},
	}
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
	if err != nil {
		return devHTTPResult{err: err}
	}
	return devHTTPResult{status: response.StatusCode, body: responseBody}
}

func environmentMap(environment []string) map[string]string {
	result := make(map[string]string, len(environment))
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		result[name] = value
	}
	return result
}
