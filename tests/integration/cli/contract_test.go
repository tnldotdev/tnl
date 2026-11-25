package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
)

var cliBinary = flag.String("tnl-cli-binary", "", "absolute path to the built tnl executable")

func TestIntegrationCLIContract(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"version":1,"tnl":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	// use a regular file as the state directory. operations that reach state
	// fail locally before opening a keychain or connecting to control.
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TNL_STATE_DIR=" + good,
		"TNL_NO_TELEMETRY=true", "TNL_CONFIG=" + good}
	for _, tc := range []struct {
		argv, stdout, stderr, code string
		exit                       int
	}{
		{"version", "tnl ", "", "", 0},
		{"check", "Valid configuration:", "", "", 0},
		{"--config absent.json --config good.json check", "Valid configuration:", "", "", 0},
		{"--config absent.json check", "", "Error: ", "", 1},
		{"--no-config check", "", "no project configuration file was found", "", 1},
		{"--no-config=false check", "Valid configuration:", "", "", 0},
		{"connect orders --install --foreground --output json", "", "", "TNL_CLIENT_CONNECT_MODE_INVALID", 1},
		{"connect --install --foreground orders --output=json", "", "", "TNL_CLIENT_CONNECT_MODE_INVALID", 1},
		{"connect start orders --install --foreground --output=json", "", "", "TNL_CLIENT_CONNECT_MODE_INVALID", 1},
		{"connect start list --install --foreground", "", "TNL_CLIENT_CONNECT_MODE_INVALID", "", 1},
		{"connect orders --install --client psql --output json", "", "", "TNL_CLIENT_CONNECT_MODE_INVALID", 1},
		{"connect orders --detach -- sh --output json", "", "Error: ", "", 1},
		{"share --service web --output json", "", "", "TNL_CLIENT_STATE_UNAVAILABLE", 1},
		{"share create --service web --output json", "", "", "TNL_CLIENT_STATE_UNAVAILABLE", 1},
		{"runtime connections read --help", "--handle", "", "", 0},
		{"runtime connections read", "", "", "TNL_CLIENT_INVALID_COMMAND", 1},
		{"domain list --unknown --output json", "", "", "TNL_CLIENT_DOMAIN_UNAVAILABLE", 1},
		{"domain list --unknown -- --output json", "", "TNL_CLIENT_DOMAIN_UNAVAILABLE", "", 1},
	} {
		t.Run(tc.argv, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, *cliBinary, strings.Fields(tc.argv)...)
			cmd.Dir, cmd.Env = dir, env
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			var exit *exec.ExitError
			if err != nil && !errors.As(err, &exit) {
				t.Fatal(err)
			}
			if cmd.ProcessState.ExitCode() != tc.exit {
				t.Fatalf("exit %d; stdout=%q stderr=%q", cmd.ProcessState.ExitCode(), stdout.String(), stderr.String())
			}
			checkStream := func(label, got, want string) {
				t.Helper()
				if want == "" && got != "" || !strings.Contains(got, want) {
					t.Errorf("%s = %q, expected %q", label, got, want)
				}
			}
			checkStream("stdout", stdout.String(), tc.stdout)
			if tc.code == "" {
				checkStream("stderr", stderr.String(), tc.stderr)
				return
			}
			var problem struct {
				SchemaVersion int `json:"schema_version"`
				Type, Code    string
			}
			if err := json.Unmarshal(stderr.Bytes(), &problem); err != nil || problem.SchemaVersion != 1 || problem.Type != "error" || problem.Code != tc.code {
				t.Errorf("expected a single JSON error %s, got %s", tc.code, stderr.Bytes())
			}
		})
	}
}
