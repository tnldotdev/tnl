package main

import (
	"io/fs"
	"slices"
	"testing"
)

func TestHelpAudienceIndicators(t *testing.T) {
	for _, key := range []string{
		"CURSOR_TRACE_ID", "CURSOR_AGENT", "GEMINI_CLI", "CODEX_SANDBOX", "CODEX_CI", "CODEX_THREAD_ID",
		"ANTIGRAVITY_AGENT", "AUGMENT_AGENT", "OPENCODE_CLIENT", "CLAUDECODE", "CLAUDE_CODE", "REPL_ID",
		"COPILOT_MODEL", "COPILOT_ALLOW_ALL", "COPILOT_GITHUB_TOKEN",
	} {
		t.Run(key, func(t *testing.T) {
			// fallback values count when set, even if they contain only a space.
			env := map[string]string{"AI_AGENT": " \t\uFEFF", key: " "}
			got := resolveHelpAudience("", func(key string) string { return env[key] }, func(string) error {
				t.Fatal("a matched environment indicator should skip the marker check")
				return nil
			})
			if got != helpAgent {
				t.Errorf("got %q, want agent", got)
			}
		})
	}
}

func TestHelpAudienceValuesAndDevinFallback(t *testing.T) {
	for _, tc := range []struct {
		name      string
		env       map[string]string
		markerErr error
		checked   bool
		want      helpAudience
	}{
		{name: "none", markerErr: fs.ErrNotExist, checked: true, want: helpHuman},
		{name: "custom", env: map[string]string{"AI_AGENT": " \tmy-tool@2 \n"}, want: helpAgent},
		{name: "next line is not JS whitespace", env: map[string]string{"AI_AGENT": "\u0085"}, want: helpAgent},
		{name: "empty", env: map[string]string{"AI_AGENT": ""}, markerErr: fs.ErrNotExist, checked: true, want: helpHuman},
		{name: "blank", env: map[string]string{"AI_AGENT": " \uFEFF\u00A0\u2028\t"}, markerErr: fs.ErrNotExist, checked: true, want: helpHuman},
		{name: "opencode", env: map[string]string{"OPENCODE": "1"}, want: helpAgent},
		{name: "opencode not exact", env: map[string]string{"OPENCODE": "1 "}, markerErr: fs.ErrNotExist, checked: true, want: helpHuman},
		{name: "opencode zero", env: map[string]string{"OPENCODE": "0"}, markerErr: fs.ErrNotExist, checked: true, want: helpHuman},
		{name: "cursor role", env: map[string]string{"CURSOR_EXTENSION_HOST_ROLE": "agent-exec"}, want: helpAgent},
		{name: "cursor role not exact", env: map[string]string{"CURSOR_EXTENSION_HOST_ROLE": "agent-exec "}, markerErr: fs.ErrNotExist, checked: true, want: helpHuman},
		{name: "cowork alone", env: map[string]string{"CLAUDE_CODE_IS_COWORK": "1"}, markerErr: fs.ErrNotExist, checked: true, want: helpHuman},
		{name: "cowork with claude", env: map[string]string{"CLAUDE_CODE_IS_COWORK": "1", "CLAUDECODE": "1"}, want: helpAgent},
		{name: "devin marker", env: map[string]string{"AI_AGENT": "\t"}, checked: true, want: helpAgent},
		{name: "devin marker fails", markerErr: fs.ErrPermission, checked: true, want: helpHuman},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checked := false
			got := resolveHelpAudience("", func(key string) string { return tc.env[key] }, func(path string) error {
				checked = true
				if path != "/opt/.devin" {
					t.Errorf("checked %q, want /opt/.devin", path)
				}
				return tc.markerErr
			})
			if got != tc.want || checked != tc.checked {
				t.Errorf("got %q and marker checked=%v, want %q and marker checked=%v", got, checked, tc.want, tc.checked)
			}
		})
	}
}

func TestHelpAudiencePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		explicit helpAudience
		env      map[string]string
		read     []string
		want     helpAudience
	}{
		{"explicit human", helpHuman, map[string]string{"AI_AGENT": "my-tool"}, nil, helpHuman},
		{"explicit agent", helpAgent, nil, nil, helpAgent},
		{"AI_AGENT first", "", map[string]string{"AI_AGENT": "custom@2", "CURSOR_TRACE_ID": "trace", "CURSOR_AGENT": "1"}, []string{"AI_AGENT"}, helpAgent},
		{"cursor trace first fallback", "", map[string]string{"CURSOR_TRACE_ID": "trace", "CURSOR_AGENT": "1", "CLAUDECODE": "1"}, []string{"AI_AGENT", "CURSOR_TRACE_ID"}, helpAgent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var read []string
			got := resolveHelpAudience(tc.explicit, func(key string) string {
				read = append(read, key)
				return tc.env[key]
			}, func(string) error {
				t.Fatal("should not check the marker after matching an audience")
				return nil
			})
			if got != tc.want || !slices.Equal(read, tc.read) {
				t.Errorf("got %q with lookups %v, want %q with lookups %v", got, read, tc.want, tc.read)
			}
		})
	}
}
