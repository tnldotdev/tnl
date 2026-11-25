package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/cliflags"
)

func TestHelpWrapsProseAndKeepsTheExampleCopyable(t *testing.T) {
	const example = "tnl example --output json --config 'project with spaces.yml'"
	cmd := &cobra.Command{
		Use: "example", Short: "A description that wraps when the terminal is narrow.",
		Example: "  # Read the result as JSON\n  " + example,
	}
	cliflags.Bind(cmd, &struct {
		Output string `name:"output" enum:"human,json" default:"human"`
	}{}, false)

	narrow, wide := clientHelp(cmd, 36), clientHelp(cmd, 100)
	if !(strings.Contains(narrow, "--output FORMAT\n    Output format.") && strings.Contains(wide, "--output FORMAT  Output format.")) {
		t.Fatalf("expected stacked and side-by-side descriptions:\n%s\n%s", narrow, wide)
	}
	for _, text := range []string{narrow, wide} {
		if !strings.Contains(text, "  # Read the result as JSON\n  "+example+"\n") {
			t.Fatalf("caption or command changed:\n%s", text)
		}
	}
	for _, line := range strings.Split(narrow, "\n") {
		if len(line) > 36 && strings.TrimSpace(line) != example {
			t.Fatalf("line exceeded the available width: %q", line)
		}
	}
}

func TestClientHelpUsesDeclaredInputs(t *testing.T) {
	// both a prepopulated option and the environment may contain credentials.
	// help must use the declaration even if the caller passes an override.
	const secret = "secret-never-shown-in-help"
	t.Setenv("TNL_HELP_TEST_TOKEN", secret)
	var opts struct {
		Mode   string   `arg:"" name:"mode" enum:"read,write" help:"Choose an operation."`
		Path   string   `name:"config" type:"path" default:"./project.yml"`
		Token  string   `name:"token" env:"TNL_HELP_TEST_TOKEN" required:"" help:"Session credential."`
		Filter []string `name:"filter" help:"Filter the results."`
		Hidden bool     `name:"internal-only" hidden:""`
	}
	opts.Token = secret
	cmd := &cobra.Command{Use: "example", Run: func(*cobra.Command, []string) {}}
	cliflags.Bind(cmd, &opts, false)
	configureClientHelp(cmd)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--help", "--token", "also-secret"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(out.String()), " ")
	for _, want := range []string{"example <mode> [flags]", "<mode> Choose an operation. Choices: read, write.", "--config PATH Default: ./project.yml.", "--token TOKEN Required. Session credential."} {
		if !strings.Contains(text, want) {
			t.Errorf("help missing %q:\n%s", want, out.String())
		}
	}
	for _, unwanted := range []string{secret, "also-secret", "internal-only", "Default: []", "Default: false"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("help contained %q", unwanted)
		}
	}
}

func TestClientHelpShorthandAndTokenScope(t *testing.T) {
	for _, tc := range []struct {
		path []string
		want []string
		omit []string
	}{
		{[]string{"connect"}, []string{"tnl connect <name>", "tnl connect <command>", "<name> Configured service name or exact service ID.", "Kubernetes:", "--listen IP:PORT"}, []string{"detached-child", "kube-credential"}},
		{[]string{"connect", "available"}, []string{"--output FORMAT", "Server and team:"}, []string{"--listen", "Kubernetes:"}},
		{[]string{"share", "token", "create"}, []string{"--name NAME Required."}, []string{"--preview", "Optional label"}},
		{[]string{"share", "link", "create"}, []string{"--preview", "Optional label"}, []string{"--name NAME Required."}},
	} {
		t.Run(strings.Join(tc.path, " "), func(t *testing.T) {
			var out bytes.Buffer
			if _, err := commandForTest(&cli{}, &out)(append(tc.path, "--help")); err != nil {
				t.Fatal(err)
			}
			text := strings.Join(strings.Fields(out.String()), " ")
			for _, want := range tc.want {
				if !strings.Contains(text, want) {
					t.Errorf("help missing %q:\n%s", want, out.String())
				}
			}
			for _, unwanted := range tc.omit {
				if strings.Contains(text, unwanted) {
					t.Errorf("help unexpectedly contained %q:\n%s", unwanted, out.String())
				}
			}
		})
	}
}
