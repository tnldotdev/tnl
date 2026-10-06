package sourcestate

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitInTest(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(t.Context(), "git", args...)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeInTest(t *testing.T, root, path, contents string) {
	t.Helper()
	file := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sourceRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	gitInTest(t, root, "init", "-q", "-b", "main")
	writeInTest(t, root, "apps/web/profile.ts", "original")
	writeInTest(t, root, "apps/api/server.ts", "other project")
	writeInTest(t, root, ".gitignore", "ignored\n")
	gitInTest(t, root, "add", ".")
	gitInTest(t, root, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "first")
	return root
}

func TestCaptureSourceIDsAreReproducibleAndProjectRelative(t *testing.T) {
	root := sourceRepository(t)
	writeInTest(t, root, "apps/web/profile.ts", "changed content")
	writeInTest(t, root, "apps/api/server.ts", "different project change")
	project := filepath.Join(root, "apps/web")
	first, err := Capture(t.Context(), project)
	if err != nil || !first.Complete || first.ProjectPath != "apps/web" || len(first.ChangedFiles) != 1 || first.ChangedFiles[0].Path != "profile.ts" || first.Branch != "main" {
		t.Fatalf("project source state = %+v, %v", first, err)
	}
	if got, want := stringValue(first.ChangedFiles[0].BlobId), gitInTest(t, project, "hash-object", "--no-filters", "--", "profile.ts"); got != want {
		t.Fatalf("file ID = %q, reproducible Git ID = %q", got, want)
	}
	writeInTest(t, root, "apps/web/profile.ts", "changed again")
	second, err := Capture(t.Context(), project)
	if err != nil || Compare(first, second) != Different || second.HeadCommit != first.HeadCommit {
		t.Fatalf("content change = %+v, %v", second, err)
	}
	encoded, err := json.Marshal(second)
	if err != nil || strings.Contains(string(encoded), root) || strings.Contains(string(encoded), "changed again") {
		t.Fatalf("source state included source bytes or absolute path: %s, %v", encoded, err)
	}
}

func TestCaptureMatchingIgnoresBranchAndStaging(t *testing.T) {
	root := sourceRepository(t)
	writeInTest(t, root, "apps/web/profile.ts", "changed")
	writeInTest(t, root, "new file.ts", "new source")
	before, err := Capture(t.Context(), root)
	if err != nil || !before.Complete {
		t.Fatalf("initial source = %+v, %v", before, err)
	}
	gitInTest(t, root, "add", ".")
	gitInTest(t, root, "switch", "-q", "-c", "renamed-branch")
	after, err := Capture(t.Context(), root)
	if err != nil || after.Branch == before.Branch || Compare(after, before) != Matches {
		t.Fatalf("staging and branch changed comparison: %+v, %v", after, err)
	}
	// a staged deletion with the original file restored is an index-only change.
	gitInTest(t, root, "reset", "-q", "HEAD", "--", ".")
	gitInTest(t, root, "rm", "--cached", "apps/api/server.ts")
	restored, err := Capture(t.Context(), root)
	if err != nil || Compare(restored, before) != Matches {
		t.Fatalf("index-only deletion changed source comparison: %+v, %v", restored, err)
	}
}

func TestCaptureTracksDeletionsRenamesAndFileModes(t *testing.T) {
	root := sourceRepository(t)
	if err := os.Rename(filepath.Join(root, "apps/web/profile.ts"), filepath.Join(root, "apps/web/renamed.ts")); err != nil {
		t.Fatal(err)
	}
	before, err := Capture(t.Context(), root)
	if err != nil || !before.Complete || len(before.ChangedFiles) != 2 || before.ChangedFiles[0].Status != "deleted" || before.ChangedFiles[1].Status != "added" {
		t.Fatalf("rename source = %+v, %v", before, err)
	}
	gitInTest(t, root, "add", ".")
	after, err := Capture(t.Context(), root)
	if err != nil || Compare(after, before) != Matches {
		t.Fatalf("staged rename changed comparison: %+v, %v", after, err)
	}
	if err := os.Chmod(filepath.Join(root, "apps/web/renamed.ts"), 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err := Capture(t.Context(), root)
	if err != nil || Compare(executable, before) != Different || stringValue(executable.ChangedFiles[1].Mode) != "100755" {
		t.Fatalf("executable source = %+v, %v", executable, err)
	}
}

func TestCaptureDoesNotFollowSymlinksOrClaimOversizedSourcesMatch(t *testing.T) {
	root := sourceRepository(t)
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("must not be read"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	writeInTest(t, root, "too-large", strings.Repeat("x", maximumFileBytes+1))
	state, err := Capture(t.Context(), root)
	if err != nil || state.Complete || Compare(state, state) != Inconclusive {
		t.Fatalf("unsupported source must be incomplete: %+v, %v", state, err)
	}
	for _, file := range state.ChangedFiles {
		if file.BlobId != nil {
			t.Fatalf("unsupported source was hashed: %+v", file)
		}
	}
}

func TestCaptureBoundsAndIgnoredFiles(t *testing.T) {
	root := sourceRepository(t)
	writeInTest(t, root, "ignored", "not source context")
	clean, err := Capture(t.Context(), root)
	if err != nil || !clean.Complete || len(clean.ChangedFiles) != 0 {
		t.Fatalf("ignored file changed source state: %+v, %v", clean, err)
	}
	for index := 0; index <= maximumFiles; index++ {
		writeInTest(t, root, strings.Repeat("a", index+1)+".ts", "new")
	}
	bounded, err := Capture(t.Context(), root)
	if err != nil || bounded.Complete || len(bounded.ChangedFiles) > maximumFiles || Compare(bounded, bounded) != Inconclusive {
		t.Fatalf("truncated source = %+v, %v", bounded, err)
	}
	partial, err := Capture(t.Context(), t.TempDir())
	if err != nil || partial.Complete || partial.HeadCommit != "" || len(partial.ChangedFiles) != 0 || Compare(partial, partial) != Inconclusive {
		t.Fatalf("non-Git source = %+v, %v", partial, err)
	}
}
