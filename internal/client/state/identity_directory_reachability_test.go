package state

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateDirectoryCreationParentSyncFailurePreventsHandoffAndReopenRetries(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	parentPin, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "new-state", "identities", "scope")
	parentSyncs, mutations := 0, 0
	syncFile := func(file *os.File) error {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if os.SameFile(info, parentPin) {
			parentSyncs++
			return syscall.EIO
		}
		return file.Sync()
	}
	for attempt := range 2 {
		directory, err := openPrivateDirectory(path, syncFile)
		if err == nil {
			mutations++
			_ = directory.Write("native-key.json", []byte("must-not-authorize-a-request"))
		}
		if !errors.Is(err, syscall.EIO) || directory != nil || mutations != 0 {
			t.Fatal("uncertain ancestor creation exposed a key/challenge owner", attempt, err)
		}
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			t.Fatal("fault did not occur after mkdir", err)
		}
	}
	if parentSyncs != 2 {
		t.Fatal("existing uncertain path skipped parent synchronization")
	}
	var synced []string
	directory, err := openPrivateDirectory(path, func(file *os.File) error { synced = append(synced, file.Name()); return file.Sync() })
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{path, filepath.Dir(path), filepath.Join(parent, "new-state"), parent} {
		found := false
		for _, actual := range synced {
			if actual == required {
				found = true
			}
		}
		if !found {
			t.Fatal("creation link not synced before exposing owner", required)
		}
	}
	if err := directory.Write("native-key.json", []byte("original-key")); err != nil {
		t.Fatal(err)
	}
	data, found, err := directory.Read("native-key.json", 1024)
	if err != nil || !found || string(data) != "original-key" {
		t.Fatal("reopened synchronized owner lost its original value", err)
	}
}
