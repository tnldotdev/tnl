package projectconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTypeScriptOversizedResultReportsSizeError(t *testing.T) {
	for _, test := range []struct {
		name string
		size int
	}{
		{"just_over_limit", maxResultBytes},
		{"larger_than_pipe_capacity", 8 * maxResultBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "tnl.config.ts")
			// The property name and JSON punctuation put even the first case
			// over the result limit; the second cannot fit in a pipe buffer.
			source := fmt.Sprintf(`export default {server: "x".repeat(%d)};`, test.size)
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			_, err := loadTypeScript(t.Context(), path, directory, Worktree{})
			if err == nil || !strings.Contains(err.Error(), "result is too large") {
				t.Fatalf("oversized result after %s: %v; want result is too large", time.Since(started), err)
			}
		})
	}
}
