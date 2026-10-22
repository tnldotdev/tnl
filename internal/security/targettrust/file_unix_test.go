//go:build unix

package privatetrust

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProjectBundleRejectsNonregularFileEvenAfterOpen(t *testing.T) {
	directory := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(directory, "bundle.pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProjectBundle(directory, "bundle.pem"); err == nil {
		t.Fatal("FIFO accepted as a CA file")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := openProjectFile(root, "bundle.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || info.Mode().IsRegular() {
		t.Fatalf("nonblocking FIFO identity: %v", err)
	}
}
