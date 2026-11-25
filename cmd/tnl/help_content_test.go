package main

import (
	"bytes"
	"encoding/csv"
	"io"
	"os"
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
		for block := range strings.SplitSeq(cmd.Example, "\n\n") {
			caption, line, ok := strings.Cut(strings.TrimSpace(block), "\n")
			line = strings.TrimSpace(line)
			if !ok || !strings.HasPrefix(caption, "# ") || !strings.HasPrefix(line, "tnl ") || strings.Contains(line, "\n") {
				t.Errorf("%s: expected a caption and one command: %q", cmd.CommandPath(), block)
				continue
			}
			if seen[line] {
				continue
			}
			seen[line] = true
			// examples use space-separated words, with double quotes around a
			// multiword argument or a shell variable. never run a command here.
			reader := csv.NewReader(strings.NewReader(os.Expand(line, func(key string) string {
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
			})))
			reader.Comma = ' '
			words, err := reader.Read()
			if err != nil {
				t.Errorf("%s: %v", line, err)
				continue
			}
			selected, err := parse(words[1:])
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
