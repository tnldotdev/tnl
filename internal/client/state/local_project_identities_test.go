package state

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLocalProjectIdentitiesAreRandomPersistentAndCanonical(t *testing.T) {
	root, project := filepath.Join(t.TempDir(), "state"), t.TempDir()
	open := func() *Database {
		t.Helper()
		d, err := OpenWithOptions(t.Context(), root, OpenOptions{Protection: ProtectionFile})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := open()
	source, worktree, err := d.LocalProjectIdentity(t.Context(), project)
	if err != nil || len(source) != 64 || len(worktree) != 64 || source == worktree {
		t.Fatal("missing independent random identity", err)
	}
	for _, domain := range []string{"tnl-local-publication-v1\x00", "tnl-local-worktree-v1\x00", ""} {
		digest := sha256.Sum256([]byte(domain + project))
		if source == hex.EncodeToString(digest[:]) || worktree == hex.EncodeToString(digest[:]) {
			t.Fatal("local identity was derived from a path")
		}
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			a, b, err := d.LocalProjectIdentity(t.Context(), project)
			if err != nil || a != source || b != worktree {
				t.Error("concurrent lookup replaced local identity", err)
			}
		})
	}
	workers.Wait()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(project, alias); err != nil {
		t.Fatal(err)
	}
	a, b, err := d.LocalProjectIdentity(t.Context(), alias)
	if err != nil || a != source || b != worktree {
		t.Fatal("symlink selected a second identity", err)
	}
	fresh := t.TempDir()
	results := make(chan [2]string, 8)
	for range 8 {
		workers.Go(func() {
			a, b, err := d.LocalProjectIdentity(t.Context(), fresh)
			if err != nil {
				t.Error(err)
			}
			results <- [2]string{a, b}
		})
	}
	workers.Wait()
	close(results)
	var first [2]string
	for result := range results {
		if first == [2]string{} {
			first = result
		}
		if result != first || result[0] == "" || result[1] == "" || result[0] == source || result[1] == worktree {
			t.Fatal("concurrent creation did not preserve the first identity")
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d = open()
	defer d.Close()
	a, b, err = d.LocalProjectIdentity(t.Context(), project)
	if err != nil || a != source || b != worktree {
		t.Fatal("restart changed local identity", err)
	}
	a, b, err = d.LocalProjectIdentity(t.Context(), root)
	if err != nil || a == source || b == worktree {
		t.Fatal("different directories shared identity", err)
	}
	if _, _, err := d.LocalProjectIdentity(t.Context(), filepath.Base(project)); err == nil {
		t.Fatal("accepted noncanonical project directory")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.LocalProjectIdentity(t.Context(), file); err == nil {
		t.Fatal("accepted a file as a project directory")
	}
	other, err := OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), OpenOptions{Protection: ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	a, b, err = other.LocalProjectIdentity(t.Context(), project)
	if err != nil || a == source || b == worktree {
		t.Fatal("separate client state reused local identity", err)
	}
}
