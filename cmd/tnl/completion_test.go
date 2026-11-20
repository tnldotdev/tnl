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

func TestServiceFlagCompletionUsesProjectNamesOnlyForNameSelectors(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("TNL_CONFIG", "")
	if err := os.WriteFile("tnl.yml", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(meta.DirectoryName, 0700); err != nil {
		t.Fatal(err)
	}
	facts := `{"services":{"orders":"postgres"},"deployments":["production"]}`
	if err := os.WriteFile(filepath.Join(meta.DirectoryName, "completion.json"), []byte(facts), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		command string
		want    bool
	}{
		{"wait", true},
		{"inspect list", true},
		{"share", true},
		{"share create", true},
		{"publisher provision --deployment production", true},
		{"publisher setup --deployment production", true},
		{"publisher setup --deployment production --project-key another-project", false},
		{"publisher setup", false},
		{"publisher enroll", false},
		{"publisher grant add", false},
	} {
		t.Run(test.command, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			app := commandApp{flags: &cli{}, out: &out, errOut: &diagnostics}
			cmd := app.root()
			args := append([]string{"__complete"}, strings.Fields(test.command)...)
			cmd.SetArgs(append(args, "--service", "or"))
			if err := cmd.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err, diagnostics.String())
			}
			if got := slices.Contains(strings.Split(out.String(), "\n"), "orders"); got != test.want {
				t.Fatalf("completion = %q, want orders: %t", out.String(), test.want)
			}
		})
	}
}
