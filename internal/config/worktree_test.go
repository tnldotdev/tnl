package config

import (
	"strings"
	"testing"
)

func TestWorktreeLabelIsCanonicalAndStable(t *testing.T) {
	label := WorktreeLabel("Caf\u00e9 Feature", "/tmp/project")
	if label != WorktreeLabel("Caf\u00e9 Feature", "/tmp/project") || !strings.HasPrefix(label, "cafe-feature-") || len(label) > 63 {
		t.Fatalf("label = %q", label)
	}
}

func TestServiceWorktreeLabelIsOneStableDNSLabel(t *testing.T) {
	worktree := WorktreeLabel(strings.Repeat("long-project-", 10), "/tmp/project")
	label := ServiceWorktreeLabel("frontend", worktree)
	if !strings.HasPrefix(label, "frontend-") || !strings.HasSuffix(label, worktree[len(worktree)-7:]) ||
		len(label) > 63 || strings.Contains(label, ".") {
		t.Fatalf("service worktree label = %q", label)
	}
}
