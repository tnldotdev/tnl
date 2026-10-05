package checkoutmarker

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitInTest(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.CommandContext(t.Context(), "git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func TestCaptureCheckoutMarkerChangesWithLocalContent(t *testing.T) {
	root := t.TempDir()
	gitInTest(t, root, "init", "-q", "-b", "main")
	file := filepath.Join(root, "profile.ts")
	if err := os.WriteFile(file, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitInTest(t, root, "add", "profile.ts")
	gitInTest(t, root, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "first")
	if err := os.WriteFile(file, []byte("changed content"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Capture(t.Context(), root)
	if err != nil || !first.Complete || len(first.ChangedFiles) != 1 || first.ChangedFiles[0].Path != "profile.ts" ||
		first.ChangedFiles[0].ContentSha256 == nil || first.HeadCommit == "" || first.Branch != "main" {
		t.Fatalf("modified checkout marker = %+v, %v", first, err)
	}
	if err := os.WriteFile(file, []byte("changed again"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Capture(t.Context(), root)
	if err != nil || second.Fingerprint == first.Fingerprint || second.HeadCommit != first.HeadCommit {
		t.Fatalf("checkout content change = %+v, %v", second, err)
	}
	encoded, err := json.Marshal(second)
	if err != nil || strings.Contains(string(encoded), root) || strings.Contains(string(encoded), "changed again") {
		t.Fatalf("checkout marker included source or absolute path: %s, %v", encoded, err)
	}
}

func TestCaptureOutsideGitIsExplicitlyPartial(t *testing.T) {
	marker, err := Capture(context.Background(), t.TempDir())
	if err != nil || marker.Complete || marker.HeadCommit != "" || len(marker.ChangedFiles) != 0 || !strings.HasPrefix(marker.Fingerprint, "sha256:") {
		t.Fatalf("non-Git marker = %+v, %v", marker, err)
	}
}
