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
