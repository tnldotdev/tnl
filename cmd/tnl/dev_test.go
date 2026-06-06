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
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

func TestDevCommandPassesThroughCommandArguments(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"dev", "--name", "demo", "--", "npm", "run", "dev", "--", "--host"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "dev <command>" {
		t.Fatalf("command = %q", parsed.Command())
	}
	want := []string{"--", "npm", "run", "dev", "--", "--host"}
	if flags.Dev.Name != "demo" || !reflect.DeepEqual(flags.Dev.Command, want) {
		t.Fatalf("name = %q, command = %#v", flags.Dev.Name, flags.Dev.Command)
	}
}

func TestResolveDevCommandRemovesSeparatorAndFindsExecutable(t *testing.T) {
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
	t.Chdir(directory)
	t.Setenv("PATH", t.TempDir())

	command, err := resolveDevCommand([]string{"next", "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if command[0] != executable || !reflect.DeepEqual(command[1:], []string{"dev"}) {
		t.Fatalf("command = %#v", command)
	}
}

func TestRunDevReportsMissingFrameworkIntegration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runDev(t.Context(), devCommand{
		Command: []string{"sh", "-c", "sleep 1"}, StartupTimeout: 10 * time.Millisecond,
	}, nil, &stdout, &stderr)
	if err == nil || err.Error() != "development server did not connect to tnl; install and configure @tnldotdev/next or @tnldotdev/vite, or use --port" {
		t.Fatalf("runDev error = %v", err)
	}
}

func TestDevBootstrapConfiguresAndRegistersOneTarget(t *testing.T) {
	bootstrap, err := newDevBootstrap("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bootstrap.Close(); err != nil {
			t.Error(err)
		}
	})

	name := "agent-feature.example"
	premature := postDevRequest(bootstrap, bootstrap.token, "/v1/target", devTargetRequest{
		Protocol: 1, Framework: "vite", Port: 5173,
	})
	if premature.err != nil || premature.status != http.StatusConflict {
		t.Fatalf("premature target result = %#v", premature)
	}
	configuration := devConfigurationRequest{
		Protocol: 1, Framework: "vite",
		Options: devTunnelOptions{Name: &name, AllowCurrentIP: true},
	}
	configurationDone := make(chan devHTTPResult, 1)
	go func() {
		configurationDone <- postDevRequest(bootstrap, bootstrap.token, "/v1/configure", configuration)
	}()
	configured, err := bootstrap.Configuration(context.Background())
	if err != nil || !reflect.DeepEqual(configured, configuration) {
		t.Fatalf("configuration = %#v, err = %v", configured, err)
	}
	want := devConfigurationResponse{
		Protocol: 1, TunnelID: "tunnel_0123456789abcdef0123456789abcdef",
		Hostname: "agent-feature.example", PublicURL: "https://agent-feature.example",
	}
	bootstrap.Resolve(want, nil)
	result := <-configurationDone
	var response devConfigurationResponse
	if result.err != nil || result.status != http.StatusOK || json.Unmarshal(result.body, &response) != nil ||
		!reflect.DeepEqual(response, want) {
		t.Fatalf("configuration result = %#v, response = %#v", result, response)
	}
	result = postDevRequest(bootstrap, bootstrap.token, "/v1/configure", configuration)
	if result.err != nil || result.status != http.StatusOK {
		t.Fatalf("idempotent configuration result = %#v", result)
	}
	conflictingConfiguration := configuration
	conflictingConfiguration.Framework = "next"
	result = postDevRequest(bootstrap, bootstrap.token, "/v1/configure", conflictingConfiguration)
	if result.err != nil || result.status != http.StatusConflict {
		t.Fatalf("conflicting configuration result = %#v", result)
	}

	target := devTargetRequest{Protocol: 1, Framework: "vite", Port: 5173}
	result = postDevRequest(bootstrap, bootstrap.token, "/v1/target", target)
	if result.err != nil || result.status != http.StatusNoContent {
		t.Fatalf("target result = %#v", result)
	}
	registered, err := bootstrap.Target(context.Background())
	if err != nil || !reflect.DeepEqual(registered, target) {
		t.Fatalf("target = %#v, err = %v", registered, err)
	}
	result = postDevRequest(bootstrap, bootstrap.token, "/v1/target", target)
	if result.err != nil || result.status != http.StatusNoContent {
		t.Fatalf("idempotent target result = %#v", result)
	}
	result = postDevRequest(bootstrap, bootstrap.token, "/v1/target", devTargetRequest{
		Protocol: 1, Framework: "vite", Port: 3000,
	})
	if result.err != nil || result.status != http.StatusConflict {
		t.Fatalf("conflicting target result = %#v", result)
	}
	result = postDevRequest(bootstrap, "invalid", "/v1/target", target)
	if result.err != nil || result.status != http.StatusUnauthorized {
		t.Fatalf("unauthorized target result = %#v", result)
	}
}

func TestDevBootstrapTimesOutAndClosesIdempotently(t *testing.T) {
	bootstrap, err := newDevBootstrap("")
	if err != nil {
		t.Fatal(err)
	}
	directory := bootstrap.dir
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
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session directory still exists: %v", err)
	}
}

func TestDevEnvironmentReplacesProtocolAndRemovesAccessToken(t *testing.T) {
	t.Setenv("PORT", "9999")
	t.Setenv("TNL_ACCESS_TOKEN", "secret")
	t.Setenv("TNL_DEV_PROTOCOL", "old")
	t.Setenv("TNL_TUNNEL_ID", "stale")
	t.Setenv("TNL_PUBLIC_HOSTNAME", "stale.example")
	t.Setenv("TNL_PUBLIC_URL", "https://stale.example")
	bootstrap := &devBootstrap{socket: "/private/control.sock", token: strings.Repeat("a", 64)}
	environment := environmentMap(devEnvironment(bootstrap, 3000))
	if environment["PORT"] != "3000" || environment["TNL_DEV_PORT"] != "3000" ||
		environment["TNL_DEV_PROTOCOL"] != "1" {
		t.Fatalf("environment = %#v", environment)
	}
	for _, name := range []string{"TNL_ACCESS_TOKEN", "TNL_TUNNEL_ID", "TNL_PUBLIC_HOSTNAME", "TNL_PUBLIC_URL"} {
		if _, found := environment[name]; found {
			t.Fatalf("%s was passed to the development server", name)
		}
	}
}

func TestDevRejectsOccupiedExplicitPortBeforeStartingChild(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	marker := filepath.Join(t.TempDir(), "child-started")
	t.Setenv("TNL_TEST_CHILD_MARKER", marker)
	err = runDev(context.Background(), devCommand{
		Command: []string{"sh", "-c", `touch "$TNL_TEST_CHILD_MARKER"`},
		Port:    port, StartupTimeout: time.Second,
	}, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("occupied port error = %v", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("child process started: %v", err)
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
	bootstrap, err := newDevBootstrap("")
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

func TestDevProcessStopTerminatesProcessGroup(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	process, err := startDevProcess(
		[]string{"sh", "-c", `sleep 30 & printf '%s\n' "$!"; wait`},
		os.Environ(), nil, writer, io.Discard,
	)
	if err != nil {
		reader.Close()
		writer.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Stop(time.Second) })
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || childPID <= 0 {
		t.Fatalf("child PID = %q, error = %v", line, err)
	}
	if err := process.Stop(time.Second); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(childPID, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("development process group child %d survived shutdown", childPID)
}

type devHTTPResult struct {
	status int
	body   []byte
	err    error
}

func postDevRequest(bootstrap *devBootstrap, token, path string, value any) devHTTPResult {
	body, err := json.Marshal(value)
	if err != nil {
		return devHTTPResult{err: err}
	}
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
	request.Header.Set("Authorization", "Bearer "+token)
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
