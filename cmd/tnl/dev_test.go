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

func TestDevBootstrapRegistersOneTarget(t *testing.T) {
	var framework, registeredTarget string
	bootstrap, err := newDevBootstrap("", func(_ context.Context, gotFramework, gotTarget string) error {
		framework, registeredTarget = gotFramework, gotTarget
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bootstrap.Close(); err != nil {
			t.Error(err)
		}
	})

	if status := registerDevTarget(t, bootstrap, bootstrap.token, devTargetRequest{
		Protocol: 1, Framework: "vite", Port: 5173,
	}); status != http.StatusNoContent {
		t.Fatalf("registration status = %d", status)
	}
	target, err := bootstrap.Target(context.Background())
	if err != nil || target != "http://127.0.0.1:5173" {
		t.Fatalf("target = %q, err = %v", target, err)
	}
	if framework != "vite" || registeredTarget != target {
		t.Fatalf("registered framework = %q, target = %q", framework, registeredTarget)
	}
	if status := registerDevTarget(t, bootstrap, bootstrap.token, devTargetRequest{
		Protocol: 1, Framework: "vite", Port: 5173,
	}); status != http.StatusNoContent {
		t.Fatalf("idempotent registration status = %d", status)
	}
	if status := registerDevTarget(t, bootstrap, bootstrap.token, devTargetRequest{
		Protocol: 1, Framework: "next", Port: 3000,
	}); status != http.StatusConflict {
		t.Fatalf("conflicting registration status = %d", status)
	}
	if status := registerDevTarget(t, bootstrap, "invalid", devTargetRequest{
		Protocol: 1, Framework: "vite", Port: 5173,
	}); status != http.StatusUnauthorized {
		t.Fatalf("unauthorized registration status = %d", status)
	}
}

func TestDevBootstrapTimesOutAndClosesIdempotently(t *testing.T) {
	bootstrap, err := newDevBootstrap("", nil)
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
	if _, err := bootstrap.Target(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("target error = %v", err)
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
	bootstrap := &devBootstrap{socket: "/private/control.sock", token: strings.Repeat("a", 64)}
	environment := environmentMap(devEnvironment(
		bootstrap, "tunnel_0123456789abcdef0123456789abcdef", "demo.example", 3000,
	))
	if environment["PORT"] != "3000" || environment["TNL_DEV_PORT"] != "3000" ||
		environment["TNL_DEV_PROTOCOL"] != "1" || environment["TNL_PUBLIC_URL"] != "https://demo.example" ||
		environment["TNL_TUNNEL_ID"] != "tunnel_0123456789abcdef0123456789abcdef" {
		t.Fatalf("environment = %#v", environment)
	}
	if _, found := environment["TNL_ACCESS_TOKEN"]; found {
		t.Fatal("access token was passed to the development server")
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

func registerDevTarget(t *testing.T, bootstrap *devBootstrap, token string, registration devTargetRequest) int {
	t.Helper()
	body, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", bootstrap.socket)
		},
	}
	client := &http.Client{Transport: transport, Timeout: time.Second}
	request, err := http.NewRequest(http.MethodPost, "http://unix/v1/target", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

func environmentMap(environment []string) map[string]string {
	result := make(map[string]string, len(environment))
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		result[name] = value
	}
	return result
}
