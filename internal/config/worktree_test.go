package config

import (
	"strings"
	"testing"
)

func TestWorktreeLabelIsCanonicalAndStable(t *testing.T) {
	var salt [32]byte
	copy(salt[:], "installation-private-worktree-key")
	label := WorktreeLabel("Caf\u00e9 Feature", "/tmp/project", salt)
	if label != WorktreeLabel("Caf\u00e9 Feature", "/tmp/project", salt) ||
		!strings.HasPrefix(label, "cafe-feature-") || len(label) != len("cafe-feature-")+8 || len(label) > 63 {
		t.Fatalf("label = %q", label)
	}
	otherRoot := WorktreeLabel("Caf\u00e9 Feature", "/tmp/other-project", salt)
	salt[0]++
	otherSalt := WorktreeLabel("Caf\u00e9 Feature", "/tmp/project", salt)
	if label == otherRoot || label == otherSalt {
		t.Fatalf("labels did not distinguish roots and salts: %q, %q, %q", label, otherRoot, otherSalt)
	}
}

func TestServiceWorktreeLabelIsOneStableDNSLabel(t *testing.T) {
	worktree := WorktreeLabel(strings.Repeat("long-project-", 10), "/tmp/project", [32]byte{1})
	label := ServiceWorktreeLabel("frontend", worktree)
	other := ServiceWorktreeLabel("backend", worktree)
	if !strings.HasPrefix(label, "frontend-") || !strings.HasSuffix(label, worktree[len(worktree)-9:]) ||
		!strings.HasPrefix(other, "backend-") || !strings.HasSuffix(other, worktree[len(worktree)-9:]) ||
		label == other || len(label) > 63 || len(other) > 63 || strings.Contains(label, ".") {
		t.Fatalf("service worktree labels = %q, %q", label, other)
	}
}
