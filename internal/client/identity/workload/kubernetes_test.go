package workload

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
)

func TestKubernetesProjectedTokenSymlinkRotation(t *testing.T) {
	directory := t.TempDir()
	for name, token := range map[string]string{"first": "first.signed.token", "second": "second.signed.token"} {
		if err := os.Mkdir(filepath.Join(directory, name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name, "token"), []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("first", filepath.Join(directory, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..data/token", filepath.Join(directory, "token")); err != nil {
		t.Fatal(err)
	}
	hints := workloadmanifest.Acquisition{Method: "token-file", TokenFile: filepath.Join(directory, "token"), Audience: "https://control.example"}
	environment := func(string) string { t.Fatal("projected source read an environment fallback"); return "" }
	source := RefreshSource(directory, hints, environment)
	if source == nil || source.TokenFile != hints.TokenFile {
		t.Fatal("refresh resolved the projected path to a stale inode")
	}
	if token, err := Acquire(t.Context(), *source, nil, environment); err != nil || token != "first.signed.token" {
		t.Fatal("initial projected proof not read", err)
	}
	if err := os.Symlink("second", filepath.Join(directory, "..data-next")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(directory, "..data-next"), filepath.Join(directory, "..data")); err != nil {
		t.Fatal(err)
	}
	if token, err := Acquire(t.Context(), *source, nil, environment); err != nil || token != "second.signed.token" {
		t.Fatal("atomic projection rotation retained the old proof", err)
	}
	if err := os.Remove(filepath.Join(directory, "second", "token")); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(t.Context(), *source, nil, environment); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("missing projected proof did not fail closed", err)
	}
}
