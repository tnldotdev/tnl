package clioutput

import (
	"os/exec"
	"strings"
	"testing"
)

func TestShellRendererMatchesGo(t *testing.T) {
	tests := []struct {
		name   string
		state  string
		footer string
		fields []Field
	}{
		{"installed", "installed", "start with: tnl publish 3000", []Field{{"version", "0.1.0-rc.40"}, {"binary", "/Users/chase/.local/bin/tnl"}}},
		{"empty", "ready", "", nil},
		{"wrapping", "installed", "", []Field{{"binary", "/tmp/" + strings.Repeat("long directory ", 20) + "/tnl"}, {"action", `export PATH="/tmp/a'b\c:$PATH"`}}},
		{"stacked labels", "ready", "", []Field{{strings.Repeat("label", 20), strings.Repeat("value", 30)}}},
		{"escaping", "ready", "", []Field{{"path", "caf\u00e9\U0001f422\x1b\t\r\n"}, {"invalid utf8", string([]byte{0xff, 0xe0, 0x80, 0x80, 0xed, 0xa0, 0x80, 0xf4, 0x90, 0x80, 0x80})}}},
		{"empty labels", "ready", "", []Field{{"", "value"}, {"", ""}}},
		{"maximum rail", strings.Repeat("s", 48), "", []Field{{"value", strings.Repeat("a", 100)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame := Frame{Command: "tnl install", State: test.state, Footer: test.footer, Blocks: []Block{Fields(test.fields...)}}
			want, err := Render(frame)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"-c", ShellFunction() + "\ntnl_frame \"$@\"", "--", frame.Command, frame.State, frame.Footer}
			for _, field := range test.fields {
				args = append(args, field.Label, field.Value)
			}
			got, err := exec.Command("sh", args...).CombinedOutput()
			if err != nil {
				t.Fatalf("shell renderer: %v\n%s", err, got)
			}
			if string(got) != want {
				t.Fatalf("shell frame:\n%s\nGo frame:\n%s", got, want)
			}
		})
	}
}

func TestShellRendererRejectsInvalidRails(t *testing.T) {
	for _, state := range []string{"", "bad\nstate", strings.Repeat("s", 100)} {
		output, err := exec.Command("sh", "-c", ShellFunction()+"\ntnl_frame \"tnl install\" \"$1\" \"\"", "--", state).CombinedOutput()
		if err == nil || len(output) != 0 {
			t.Fatalf("state %q: error=%v output=%q", state, err, output)
		}
	}
}
