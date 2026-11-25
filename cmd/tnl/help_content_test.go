package main

import (
	"bytes"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestClientHelpExamplesParse(t *testing.T) {
	parse := commandForTest(&cli{}, io.Discard)
	root := (&commandApp{flags: &cli{}, out: io.Discard, errOut: io.Discard}).root()
	seen := map[string]bool{}
	var visit func(*cobra.Command)
	visit = func(cmd *cobra.Command) {
		if cmd.Hidden {
			return
		}
		if cmd.Short == "" || cmd.Example == "" {
			t.Errorf("%s has no summary or examples", cmd.CommandPath())
		}
		pages := make(map[int]string)
		for _, width := range []int{36, 68, 126} {
			pages[width] = clientHelp(cmd, width, helpView{reference: true})
		}
		for _, example := range clientHelpExamples[cmd.CommandPath()] {
			line := "tnl " + example.args
			if example.caption == "" || strings.Contains(example.args, "\n") || !strings.Contains(cmd.Example, line) {
				t.Errorf("%s: expected an intact example: %s", cmd.CommandPath(), line)
				continue
			}
			for width, page := range pages {
				if !strings.Contains(page, "\n  "+line+"\n") {
					t.Errorf("%s at width %d: example changed: %s", cmd.CommandPath(), width, line)
				}
			}
			if seen[line] {
				continue
			}
			seen[line] = true
			args := example.argv()
			for i, arg := range args {
				args[i] = os.Expand(arg, func(key string) string {
					if key == "REVISION" {
						return "42"
					}
					if key == "JOB_ID" {
						return "job_0123456789abcdefghijkl"
					}
					if key == "SHARE_ID" {
						return "shr_0123456789abcdefghijkl"
					}
					return "example-" + key
				})
			}
			selected, err := parse(args)
			if err != nil {
				t.Errorf("%s: %v", line, err)
			} else if selected.HasSubCommands() && selected.Annotations["default"] == "" {
				t.Errorf("%s selects a group instead of a command", line)
			}
		}
		for _, child := range cmd.Commands() {
			visit(child)
		}
	}
	visit(root)
	for _, recipe := range guideRecipes {
		for _, step := range recipe.steps {
			if !seen["tnl "+step.example.args] {
				t.Errorf("guide command is missing from the parser-checked examples: %s", step.example.args)
			}
		}
	}
	if got := queryExample.argv(); !slices.Equal(got[len(got)-4:], []string{"--", "-At", "-c", "select 1"}) {
		t.Fatalf("query changed the client boundary: %q", got)
	}
}

func TestBareCommandGroupsShowHelp(t *testing.T) {
	for _, tc := range []struct{ path, invalid string }{
		{"", "not-a-command"},
		{"auth", "not-a-command"},
		{"share service invite", "not-a-command"},
		{"connect", "--listen=127.0.0.1:15432"},
	} {
		t.Run("tnl "+tc.path, func(t *testing.T) {
			args := append([]string{}, strings.Fields(tc.path)...)
			var bare, help, diagnostics bytes.Buffer
			if err := run(t.Context(), args, &bare, &diagnostics); err != nil {
				t.Fatal(err)
			}
			if err := run(t.Context(), append(args, "--help"), &help, &diagnostics); err != nil {
				t.Fatal(err)
			}
			if diagnostics.Len() != 0 || !strings.Contains(bare.String(), "Examples:") || bare.String() != help.String() {
				t.Fatalf("bare command should print its help to stdout:\n%s\nstderr: %s", bare.String(), diagnostics.String())
			}
			if err := run(t.Context(), append(args, tc.invalid), io.Discard, io.Discard); err == nil {
				t.Fatal("invalid invocation printed help instead of failing")
			}
		})
	}
}
