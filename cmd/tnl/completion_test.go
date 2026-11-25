package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
)

func TestServiceCompletionUsesProjectNamesOnlyForNameSelectors(t *testing.T) {
	setupCompletionFacts(t)
	for _, test := range []struct {
		command string
		input   string
		want    bool
	}{
		{"wait", "--service or", true},
		{"wait", "or", true},
		{"status", "or", true},
		{"watch", "or", true},
		{"publish", "or", true},
		{"connect", "or", true},
		{"connect start", "or", true},
		{"audit", "or", true},
		{"audit list", "or", true},
		{"inspect", "--service or", true},
		{"inspect list", "--service or", true},
		{"inspect", "or", true},
		{"inspect list", "or", true},
		{"inspect show", "or", false},
		{"share", "--service or", true},
		{"share create", "--service or", true},
		{"share", "or", true},
		{"share create", "or", true},
		{"share link create", "or", false},
		{"publisher provision --deployment production", "--service or", true},
		{"publisher setup --deployment production", "--service or", true},
		{"publisher setup --deployment production --project-key another-project", "--service or", false},
		{"publisher setup", "--service or", false},
		{"publisher enroll", "--service or", false},
		{"publisher grant add", "--service or", false},
	} {
		t.Run(test.command+" "+test.input, func(t *testing.T) {
			out := completeForTest(t, strings.Fields(test.command+" "+test.input)...)
			if got := slices.Contains(strings.Split(out, "\n"), "orders\tpostgres"); got != test.want {
				t.Fatalf("completion = %q, want orders: %t", out, test.want)
			}
		})
	}
}

func setupCompletionFacts(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv("TNL_CONFIG", "")
	if err := os.WriteFile("tnl.yml", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(meta.DirectoryName, 0700); err != nil {
		t.Fatal(err)
	}
	facts := `{"services":{"orders":"postgres","other":"http","list":"tcp"},"deployments":["production"]}`
	if err := os.WriteFile(filepath.Join(meta.DirectoryName, "completion.json"), []byte(facts), 0600); err != nil {
		t.Fatal(err)
	}
}

func completeForTest(t *testing.T, args ...string) string {
	t.Helper()
	var out, diagnostics bytes.Buffer
	app := commandApp{flags: &cli{}, out: &out, errOut: &diagnostics}
	cmd := app.root()
	cmd.SetArgs(append([]string{"__complete"}, args...))
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err, diagnostics.String())
	}
	return out.String()
}

func TestServiceCompletionExcludesExistingSelectors(t *testing.T) {
	setupCompletionFacts(t)
	for _, command := range []string{"status", "watch", "share create", "inspect", "audit"} {
		t.Run(command, func(t *testing.T) {
			for _, args := range [][]string{
				{"orders", "ot"},
				{"--service", "orders", "ot"},
				{"orders", "--service", "ot"},
			} {
				if out := completeForTest(t, append(strings.Fields(command), args...)...); strings.Contains(out, "other\thttp") {
					t.Fatalf("completed more than one selector for %v: %q", args, out)
				}
			}
		})
	}
	for _, args := range [][]string{
		{"wait", "orders", "o"},
		{"wait", "--service", "orders", "o"},
		{"wait", "--service", "orders", "--service", "o"},
		{"wait", "orders", "--service", "o"},
	} {
		if out := completeForTest(t, args...); strings.Contains(out, "orders\t") || !strings.Contains(out, "other\thttp") {
			t.Fatalf("%v did not omit selected service: %q", args, out)
		}
	}
	if out := completeForTest(t, "--no-config", "status", "or"); strings.Contains(out, "orders\t") {
		t.Fatalf("--no-config completed a project service: %q", out)
	}
	if out := completeForTest(t, "connect", "li"); strings.Contains(out, "list\ttcp") {
		t.Fatalf("connect completed a service that would dispatch to a command: %q", out)
	}
	if out := completeForTest(t, "connect", "start", "li"); !strings.Contains(out, "list\ttcp\n") {
		t.Fatalf("explicit connect start did not complete service with a command name: %q", out)
	}
}

func TestProjectCompletionStopsAfterTerminator(t *testing.T) {
	setupCompletionFacts(t)
	for _, args := range [][]string{
		{"connect", "--", "li"},
		{"connect", "orders", "--", "--client"},
		{"connect", "start", "orders", "--", "ps"},
		{"status", "--", "or"},
		{"wait", "orders", "--", "ot"},
		{"inspect", "--", "sh"},
	} {
		if out := completeForTest(t, args...); out != ":4\n" {
			t.Fatalf("%v completed after --: %q", args, out)
		}
	}
}

func TestConnectClientCompletionUsesTheSelectorsKnownProtocol(t *testing.T) {
	setupCompletionFacts(t)
	for _, test := range []struct {
		selector string
		want     string
	}{
		{"orders", "pg_dump\npsql\n"},
		{"postgresql://orders.example.test:45432/", "pg_dump\npsql\n"},
		{"https://orders.example.test/", "curl\n"},
		{"tcp://orders.example.test:1024", "nc\n"},
		{"orders.example.test:45432", ""},
		{"svc_0123456789abcdefghijkl", ""},
		{"postgresql://orders.example.test:15432/?hostaddr=127.0.0.1", ""},
	} {
		for _, cmd := range []string{"connect", "connect start"} {
			if out := completeForTest(t, append(strings.Fields(cmd), test.selector, "--client", "")...); out != test.want+":4\n" {
				t.Fatalf("%s %s completion = %q, want %q", cmd, test.selector, out, test.want)
			}
		}
	}
}
