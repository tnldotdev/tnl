package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	projectconfig "github.com/tnldotdev/tnl/internal/config"
)

func TestConfigPathDoesNotEvaluateTypeScript(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "tnl.ts")
	markerPath := filepath.Join(directory, "evaluated")
	source := `import { writeFileSync } from "node:fs";
writeFileSync("evaluated", "yes");
export default {};`
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)

	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"config", "path"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "-- selected ") || !strings.Contains(stdout.String(), "tnl.ts") {
		t.Fatalf("config path output = %q", stdout.String())
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("config path evaluated tnl.ts: %v", err)
	}
	stdout.Reset()
	if err := run(t.Context(), []string{"config", "check"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("config check did not evaluate tnl.ts: %v", err)
	}
}

func TestProjectConfigurationAppliesPrecedenceUnits(t *testing.T) {
	t.Setenv("TNL_SERVER", "https://environment.example")
	t.Setenv("TNL_HOST", "environment.example")
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"publish", "--allow-ip", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	projectServer := "https://project.example"
	projectSubdomain := "project"
	public := true
	target := projectconfig.Target("3000")
	project := projectConfiguration{found: true, tnl: projectconfig.TNL{
		Server:  &projectServer,
		Tunnel:  &projectconfig.Tunnel{Subdomain: &projectSubdomain, Public: &public},
		Publish: &projectconfig.Publish{Target: &target},
	}}
	if err := project.applyPublish(&flags.Publish); err != nil {
		t.Fatal(err)
	}
	if flags.Publish.ServerURL != "https://environment.example" || flags.Publish.Host != "environment.example" ||
		flags.Publish.Subdomain != "" || flags.Publish.Target != "3000" || flags.Publish.Public ||
		!reflect.DeepEqual(flags.Publish.AllowIP, []string{"198.51.100.0/24"}) {
		t.Fatalf("publish flags = %#v", flags.Publish)
	}
}

func TestProjectConfigurationSetsConfiguredCommandDirectory(t *testing.T) {
	directory := t.TempDir()
	command := []string{"vite"}
	project := projectConfiguration{
		found:     true,
		selection: projectconfig.Selection{Path: filepath.Join(directory, "tnl.yml")},
		tnl:       projectconfig.TNL{Dev: &projectconfig.Dev{Command: command}},
	}
	flags := devCommand{}
	if err := project.applyDev(&flags); err != nil {
		t.Fatal(err)
	}
	if flags.commandDir != directory || !reflect.DeepEqual(flags.Command, command) {
		t.Fatalf("configured dev command = %#v in %q", flags.Command, flags.commandDir)
	}
}
