package main

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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
	facts := `{"services":{"orders":"postgres","orders.example":"postgres","orders/path":"postgres","other":"http","list":"tcp","available":"tcp","kube-credential":"tcp"},"deployments":["production"]}`
	if err := os.WriteFile(filepath.Join(meta.DirectoryName, "completion.json"), []byte(facts), 0600); err != nil {
		t.Fatal(err)
	}
}

func completeForTest(t *testing.T, args ...string) string {
	t.Helper()
	return completionRequestForTest(t, cobra.ShellCompRequestCmd, args...)
}

func completionRequestForTest(t *testing.T, request string, args ...string) string {
	t.Helper()
	var out, diagnostics bytes.Buffer
	app := commandApp{flags: &cli{}, out: &out, errOut: &diagnostics}
	cmd := app.root()
	cmd.SetArgs(append([]string{request}, args...))
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
	if out := completeForTest(t, "connect", "ava"); strings.Contains(out, "available\ttcp") {
		t.Fatalf("connect completed a service that would dispatch to a command: %q", out)
	}
	if out := completeForTest(t, "connect", "start", "ava"); !strings.Contains(out, "available\ttcp\n") {
		t.Fatalf("explicit connect start did not complete service with a command name: %q", out)
	}
	if out := completeForTest(t, "connect", "li"); !strings.Contains(out, "list\ttcp\n") {
		t.Fatalf("connect did not complete a service named after a retired command: %q", out)
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
		{"connect", "start", "orders", "--", "--client=ps"},
		{"status", "--", "or"},
		{"wait", "orders", "--", "ot"},
		{"inspect", "--", "sh"},
		{"help", "--", "status"},
	} {
		if out := completeForTest(t, args...); out != ":4\n" {
			t.Fatalf("%v completed after --: %q", args, out)
		}
	}
	if out := completeForTest(t, "connect", "start", "--deployment", "--", "or"); out != "orders\tpostgres\n:4\n" {
		t.Fatalf("treated a flag value as --: %q", out)
	}
}

func TestCompletionExcludesHiddenPaths(t *testing.T) {
	setupCompletionFacts(t)
	for _, args := range [][]string{
		{"ru"},
		{"connect", "kube"},
		{"connect", "kube-credential", "--pro"},
		{"runtime", "connections", "status", "--"},
		{"help", "runtime", ""},
	} {
		if out := completeForTest(t, args...); out != ":4\n" {
			t.Fatalf("%v exposed hidden path completion: %q", args, out)
		}
	}
}

func TestServiceCompletionInsertsOnlyNamesAndUsesLocalFacts(t *testing.T) {
	setupCompletionFacts(t)
	if err := os.Remove("tnl.yml"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("tnl.config.ts", []byte(`throw new Error("do not evaluate this configuration")`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_SERVER", "https://must-not-contact.invalid")
	for _, command := range [][]string{{"status"}, {"connect"}, {"connect", "start"}} {
		if out := completionRequestForTest(t, cobra.ShellCompNoDescRequestCmd, append(command, "order")...); out != "orders\n:4\n" {
			t.Fatalf("%v completed anything other than a local service name: %q", command, out)
		}
	}
	if err := os.WriteFile(filepath.Join(meta.DirectoryName, "completion.json"), []byte("not JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if out := completeForTest(t, "connect", "order"); out != ":4\n" {
		t.Fatalf("completed without local facts: %q", out)
	}
}

func TestCompletionRolesMatchShorthandAndExcludeOtherCommands(t *testing.T) {
	root := (&commandApp{flags: &cli{}}).root()
	for _, test := range []struct {
		command string
		arg     completionRole
		flags   map[string]completionRole
	}{
		{"connect", "project-service", map[string]completionRole{"client": "connect-client", "deployment": "deployment"}},
		{"connect start", "project-service", map[string]completionRole{"client": "connect-client", "deployment": "deployment"}},
		{"connect available", "", nil},
		{"connect kube-credential", "", nil},
		{"help", "command-path", nil},
		{"wait", "project-service", map[string]completionRole{"service": "project-service"}},
		{"publisher provision", "", map[string]completionRole{"service": "project-service", "deployment": "deployment"}},
		{"publisher grant add", "", nil},
	} {
		t.Run(test.command, func(t *testing.T) {
			cmd, rest, err := root.Find(strings.Fields(test.command))
			if err != nil || len(rest) != 0 {
				t.Fatalf("find %s: %v (remaining: %v)", test.command, err, rest)
			}
			arg, flags := completionRoles(cmd)
			if arg != test.arg || !maps.Equal(flags, test.flags) {
				t.Fatalf("completion roles = %q %v, want %q %v", arg, flags, test.arg, test.flags)
			}
		})
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
