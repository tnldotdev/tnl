package cli_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationCLIHelpAudiences(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	dir := t.TempDir()
	const hint = "my-automation-tool@1.0"
	helpText := func(env []string, args ...string) string {
		t.Helper()
		got := runBuiltCLI(t, dir, env, append([]string{"--config", "never-read.yml"}, args...)...)
		if got.exit != 0 || got.stderr != "" || strings.Contains(got.stdout, hint) {
			t.Fatalf("%v: %+v", args, got)
		}
		return got.stdout
	}
	checkOrder := func(text string, agentFirst bool) {
		t.Helper()
		human := strings.Index(text, "\n  tnl publish 3000\n")
		machine := strings.Index(text, "\n  tnl publish 3000 --output ndjson\n")
		if human < 0 || machine < 0 || (machine < human) != agentFirst {
			t.Fatalf("wrong example order, agent first=%v:\n%s", agentFirst, text)
		}
	}
	agentEnv := []string{"AI_AGENT= \t" + hint + " "}
	checkOrder(helpText(agentEnv, "publish", "--help"), true)
	checkOrder(helpText([]string{"AI_AGENT=\t ", "COPILOT_GITHUB_TOKEN=" + hint}, "publish", "--help"), true)
	if _, err := os.Stat("/opt/.devin"); err != nil {
		checkOrder(helpText(nil, "publish", "--help"), false)
	}
	rootAgent := helpText(agentEnv, "--help")
	rootHuman := helpText(agentEnv, "help", "--audience=human")
	for _, page := range []struct {
		text       string
		guideFirst bool
	}{{rootAgent, true}, {rootHuman, false}} {
		pub := strings.Index(page.text, "\n  tnl publish 3000\n")
		guide := strings.Index(page.text, "\n  tnl agent-guide\n")
		if pub < 0 || guide < 0 || (guide < pub) != page.guideFirst {
			t.Fatalf("wrong root example order, guide first=%v:\n%s", page.guideFirst, page.text)
		}
	}
	for _, tc := range []struct {
		env       []string
		audience  string
		wantAgent bool
	}{
		{agentEnv, "human", false},
		{nil, "agent", true},
	} {
		text := helpText(tc.env, "help", "publish", "--audience", tc.audience)
		checkOrder(text, tc.wantAgent)
		if !strings.Contains(text, "--target-ca-file PATH") {
			t.Fatalf("incomplete reference:\n%s", text)
		}
	}
	// this run-mode conflict fails before project evaluation or sign-in.
	// an audience hint must not even change how execution failures are printed.
	args := []string{"publish", "3000", "--detach", "--foreground"}
	probed := runBuiltCLI(t, dir, agentEnv, args...)
	ordinary := runBuiltCLI(t, dir, nil, args...)
	if probed != ordinary || ordinary.exit != 1 || ordinary.stdout != "" || !strings.HasPrefix(ordinary.stderr, "Error: ") {
		t.Fatalf("execution changed: with hint %+v, without hint %+v", probed, ordinary)
	}
	probed = runBuiltCLI(t, dir, agentEnv, "version")
	ordinary = runBuiltCLI(t, dir, nil, "version")
	if probed != ordinary || ordinary.exit != 0 || ordinary.stderr != "" || !strings.HasPrefix(ordinary.stdout, "tnl ") {
		t.Fatalf("version changed: with hint %+v, without hint %+v", probed, ordinary)
	}
	if _, err := os.Stat(filepath.Join(dir, "unused-state")); !os.IsNotExist(err) {
		t.Fatalf("help touched client state: %v", err)
	}
}

func TestIntegrationCLIHelpTopicErrors(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	dir := t.TempDir()
	for _, tc := range []struct{ args, want, omit string }{
		{"help share service invte extra", "tnl help share service invite", "extra"},
		{"help connect kube-credentia", "tnl help connect\n", "kube-credential"},
		{"help runtim", "tnl help\n", "runtime"},
		{"help publish invalid-topic", "tnl help publish\n", "invalid-topic"},
		{"help publish --audience robot", "Choose human, agent.", "robot"},
		{"auth logni", "tnl auth login --help", "logni"},
	} {
		t.Run(tc.args, func(t *testing.T) {
			got := runBuiltCLI(t, dir, nil, strings.Fields(tc.args)...)
			if got.exit != 1 || got.stdout != "" || strings.Count(got.stderr, "Error: ") != 1 ||
				!strings.Contains(got.stderr, tc.want) || strings.Contains(got.stderr, tc.omit) {
				t.Fatalf("want exit 1, no stdout and suggestion %q; got %+v", tc.want, got)
			}
		})
	}
	got := runBuiltCLI(t, dir, nil, "help", "runtime", "connections", "read")
	if got.exit != 0 || got.stderr != "" || !strings.Contains(got.stdout, "--handle") {
		t.Fatalf("exact hidden help topic: %+v", got)
	}
}

type cliResult struct {
	exit           int
	stdout, stderr string
}

func runBuiltCLI(t *testing.T, dir string, env []string, args ...string) cliResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, *cliBinary, args...)
	cmd.Dir = dir
	cmd.Env = append([]string{"HOME=" + dir, "PATH=", "TNL_NO_TELEMETRY=true", "TNL_STATE_DIR=" + filepath.Join(dir, "unused-state")}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
	}
	return cliResult{cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()}
}
