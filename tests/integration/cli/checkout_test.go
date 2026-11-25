package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationCLISelectsOneCheckout(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	root := t.TempDir()
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ dir, service string }{{"first checkout", "accounts"}, {"second checkout", "api"}} {
		dir := filepath.Join(root, fixture.dir)
		if err := os.MkdirAll(filepath.Join(dir, ".tnl", "local"), 0700); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string]string{
			"tnl.yml":                    "version: 1\ntnl: {}\n",
			".tnl/local/completion.json": `{"services":{"` + fixture.service + `":"http"}}`,
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	call := func(env []string, args ...string) (string, string, error) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), *cliBinary, args...)
		cmd.Dir = root
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "TNL_NO_TELEMETRY=true"}, env...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}
	for _, fixture := range []struct{ dir, service string }{
		{"first checkout", "accounts"}, {"second checkout", "api"}, {"first checkout", "accounts"},
	} {
		want := "Valid configuration: " + filepath.Join(canonical, fixture.dir, "tnl.yml") + "\n"
		if out, diag, err := call(nil, "--cwd", fixture.dir, "--config", "tnl.yml", "check"); out != want || diag != "" || err != nil {
			t.Fatalf("check: %q, %q, %v", out, diag, err)
		}
		if out, diag, err := call([]string{"TNL_CONFIG=tnl.yml"}, "--cwd", fixture.dir, "check"); out != want || diag != "" || err != nil {
			t.Fatalf("environment config: %q, %q, %v", out, diag, err)
		}
		if out, diag, err := call(nil, "__complete", "--cwd", fixture.dir, "wait", ""); out != fixture.service+"\thttp\n:4\n" || err != nil {
			t.Fatalf("completion: %q, %q, %v", out, diag, err)
		}
	}
	if out, _, err := call(nil, "--cwd", "absent", "check"); out != "" || err == nil {
		t.Fatalf("missing checkout: %q, %v", out, err)
	}
}
