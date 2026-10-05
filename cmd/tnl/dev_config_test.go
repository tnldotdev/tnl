package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

func TestDevCommandPassesThroughCommandArguments(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	arguments, command, err := splitDevPassthrough([]string{"dev", "web", "--name", "demo", "--", "npm", "run", "dev", "--", "--host"})
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
	if flags.Dev.Service != "web" || flags.Dev.Name != "demo" || !reflect.DeepEqual(flags.Dev.Command, want) {
		t.Fatalf("name = %q, command = %#v", flags.Dev.Name, flags.Dev.Command)
	}
}

func TestDevCommandWithoutServicePassesThroughCommandArguments(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	arguments, command, err := splitDevPassthrough([]string{"dev", "--port", "3000", "--", "node", "server.js"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse(arguments)
	if err != nil {
		t.Fatal(err)
	}
	flags.Dev.Command = command
	if parsed.Command() != "dev" || canonicalParsedCommand(parsed.Command()) != "dev <service>" {
		t.Fatalf("command = %q", parsed.Command())
	}
	if flags.Dev.Service != "" || flags.Dev.Port != 3000 || !reflect.DeepEqual(flags.Dev.Command, []string{"node", "server.js"}) {
		t.Fatalf("flags = %#v", flags.Dev)
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
	if err := os.WriteFile(filepath.Join(globalDirectory, "next"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
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

func TestRuntimeProjectMetadataUsesTheSelectedTunnelAssignment(t *testing.T) {
	metadata := projectmeta.Metadata{
		Version: projectmeta.Version, Namespace: "root.example",
		Services:           map[string]projectmeta.Service{"api": {Namespace: "configured.example", Hostname: "api.configured.example", URL: "https://api.configured.example", Paths: map[string]projectmeta.Path{"/worker": {Service: "worker", URL: "https://api.configured.example/worker"}}}},
		ServiceDirectories: map[string]string{"api": "."},
	}
	project := runtimeProjectMetadata(metadata, "api", "runtime.example", "override.runtime.example")
	if project.Namespace != "root.example" || !project.Dev || project.Services["api"].Namespace != "runtime.example" ||
		project.Services["api"].Hostname != "override.runtime.example" || project.Services["api"].URL != "https://override.runtime.example" ||
		project.Services["api"].Paths["/worker"].URL != "https://override.runtime.example/worker" ||
		metadata.Services["api"].Paths["/worker"].URL != "https://api.configured.example/worker" ||
		metadata.Services["api"].Hostname != "api.configured.example" {
		t.Fatalf("runtime project = %#v, metadata = %#v", project, metadata)
	}
}

func TestDevUsesSelectedServiceMetadataForExplicitTeamOverride(t *testing.T) {
	root := t.TempDir()
	selectedServer := "https://selected.example"
	flags := devCommand{
		Service: "api", Team: "studio", commandDir: filepath.Join(root, "apps", "api"),
		project: projectConfiguration{Project: projectconfig.Project{
			Root: root, Selection: projectconfig.Selection{Path: filepath.Join(root, "tnl.config.ts")},
			Config: config.TNL{Server: &selectedServer, Services: config.Services{
				"api": {}, "web": {},
			}},
		}},
	}
	reason, err := devMetadataPartialReason(flags, selectedServer, selectedServer)
	if err != nil || !strings.Contains(reason, "overrides") {
		t.Fatalf("explicit team metadata reason = %q, %v", reason, err)
	}
	metadata, err := selectedDevMetadata(flags, publisherServices{
		namespace: "member.example.test", hostname: "api.member.example.test",
	})
	if err != nil || metadata.Services["api"].URL != "https://api.member.example.test" ||
		metadata.ServiceDirectories["api"] != "apps/api" || len(metadata.Services) != 1 {
		t.Fatalf("selected metadata = %#v, %v", metadata, err)
	}
}

func TestDevEnvironmentReplacesProtocolAndRemovesAccessToken(t *testing.T) {
	t.Setenv("PORT", "9999")
	t.Setenv("TNL_ACCESS_TOKEN", "secret")
	t.Setenv("TNL_LOGIN_TOKEN", "test-login-token-sentinel")
	t.Setenv("TNL_DEV_PROTOCOL", "old")
	t.Setenv("TNL_TUNNEL_ID", "stale")
	t.Setenv("TNL_PUBLIC_HOSTNAME", "stale.example")
	t.Setenv("TNL_PUBLIC_URL", "https://stale.example")
	t.Setenv("TNL_PROJECT_RUNTIME", `{"namespace":"stale.example"}`)
	bootstrap := &devBootstrap{socket: "/private/control.sock"}
	projectPayload := `{"namespace":"member.example","services":{},"dev":true}`
	environment := environmentMap(devEnvironment(bootstrap, 3000, projectPayload))
	if environment["PORT"] != "3000" || environment["TNL_DEV_PORT"] != "3000" || environment["TNL_DEV_PROTOCOL"] != "1" || environment["TNL_DEV_SOCKET"] != bootstrap.socket {
		t.Fatal("development protocol environment was not replaced")
	}
	if environment["TNL_PROJECT_RUNTIME"] != projectPayload {
		t.Fatal("development project metadata was not replaced")
	}
	for _, name := range []string{"TNL_ACCESS_TOKEN", "TNL_LOGIN_TOKEN", "TNL_TUNNEL_ID", "TNL_PUBLIC_HOSTNAME", "TNL_PUBLIC_URL"} {
		if _, found := environment[name]; found {
			t.Fatalf("%s was passed to the development server", name)
		}
	}
}

func environmentMap(environment []string) map[string]string {
	result := make(map[string]string, len(environment))
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		result[name] = value
	}
	return result
}
