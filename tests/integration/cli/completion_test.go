package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationShellCompletion(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	base := t.TempDir()
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			script := filepath.Join(base, "tnl."+shell)
			body, err := exec.CommandContext(t.Context(), *cliBinary, "completion", shell).Output()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(script, body, 0600); err != nil {
				t.Fatal(err)
			}
			for _, service := range []string{"orders", "ledger"} {
				dir := t.TempDir()
				if err := os.MkdirAll(filepath.Join(dir, ".tnl/local"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "tnl.config.ts"), []byte(`throw Error("Tab evaluated the project")`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, ".tnl/local/completion.json"), []byte(`{"services":{"`+service+`":"postgres","list":"tcp"},"deployments":["production"]}`), 0600); err != nil {
					t.Fatal(err)
				}
				var shellArgs []string
				switch shell {
				case "bash":
					shellArgs = []string{"--noprofile", "--norc", "-c", `for lib in /usr/share/bash-completion/bash_completion /opt/homebrew/share/bash-completion/bash_completion; do if [[ -r $lib ]]; then source "$lib"; break; fi; done
source "$1"; COMP_WORDS=(tnl connect ""); COMP_CWORD=2; COMP_LINE="tnl connect "; COMP_POINT=${#COMP_LINE}; __start_tnl; printf '%s\n' "${COMPREPLY[@]}"`, "bash", script}
				case "zsh":
					shellArgs = []string{"-f", "-c", `autoload -Uz compinit; compinit -D; source "$1"; words=(tnl connect ''); CURRENT=3; _describe() { print -rl -- "${completions[@]}"; }; _tnl`, "zsh", script}
				case "fish":
					shellArgs = []string{"--no-config", "-c", `source $argv[1]; complete -C "tnl connect "`, script}
				}
				cmd := exec.CommandContext(t.Context(), shell, shellArgs...)
				cmd.Dir = dir
				cmd.Env = []string{"HOME=" + dir, "PATH=" + filepath.Dir(*cliBinary) + string(os.PathListSeparator) + os.Getenv("PATH"), "TNL_STATE_DIR=" + filepath.Join(dir, "unused")}
				out, err := cmd.CombinedOutput()
				other := "ledger"
				if service == "ledger" {
					other = "orders"
				}
				if err != nil || !strings.Contains(string(out), service) || strings.Contains(string(out), other) {
					t.Fatalf("expected %s in %s completions: %s (%v)", service, shell, out, err)
				}
				for _, probe := range []struct {
					args         []string
					want, absent string
				}{
					{[]string{"connect", "start", "li"}, "list", "ledger"},
					{[]string{"connect", service, "--deployment", "pro"}, "production", "--foreground"},
					{[]string{"connect", service, "--client", ""}, "pg_dump", "kubectl"},
					{[]string{"wait", "--service", ""}, service, other},
					{[]string{"connect", service, "--", "--fore"}, "", "--foreground"},
				} {
					query := exec.CommandContext(t.Context(), *cliBinary, append([]string{"__complete"}, probe.args...)...)
					query.Dir, query.Env = dir, cmd.Env
					out, err := query.Output()
					if err != nil || !strings.Contains(string(out), probe.want) || strings.Contains(string(out), probe.absent) {
						t.Fatalf("%v -> %q (%v)", probe.args, out, err)
					}
				}
				if _, err := os.Stat(filepath.Join(dir, "unused")); !os.IsNotExist(err) {
					t.Fatal("completion touched state")
				}
			}
		})
	}
}
