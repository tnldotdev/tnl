package meta

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func artifactFiles(t *testing.T) map[string][]byte {
	t.Helper()
	files, err := PythonFacade(config.TNL{}, "tnl.yml")
	if err != nil {
		t.Fatal(err)
	}
	files["project.d.ts"] = []byte("// portable declarations\n")
	return files
}

func artifactDirectory(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "generated")
}

func writeArtifactFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactReadOnlyChecksAndFixedOutputs(t *testing.T) {
	files := artifactFiles(t)
	directory := artifactDirectory(t)
	if writeArtifacts(directory, files, true) == nil {
		t.Fatal("missing outputs accepted")
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("check created output directory")
	}
	if err := writeArtifacts(directory, files, false); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(directory, "project.d.ts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []bool{true, false} {
		if err := writeArtifacts(directory, files, check); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.Stat(filepath.Join(directory, "project.d.ts"))
	if err != nil || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unchanged output was rewritten", err)
	}
	writeArtifactFixture(t, filepath.Join(directory, "customer.txt"), []byte("preserve"))
	writeArtifactFixture(t, filepath.Join(directory, "project.d.ts"), []byte("edited"))
	if writeArtifacts(directory, files, true) == nil {
		t.Fatal("stale artifact accepted")
	}
	if err := writeArtifacts(directory, files, false); err != nil {
		t.Fatal(err)
	}
	writeArtifactFixture(t, filepath.Join(directory, "workloads.json"), []byte("old workload configuration"))
	if writeArtifacts(directory, files, true) == nil {
		t.Fatal("obsolete workload configuration accepted")
	}
	if err := writeArtifacts(directory, files, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "workloads.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("obsolete workload configuration remains")
	}
	if data, err := os.ReadFile(filepath.Join(directory, "customer.txt")); err != nil || string(data) != "preserve" {
		t.Fatal("unrelated file changed", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "manifest.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("generated an ownership manifest")
	}
}

func TestArtifactBounds(t *testing.T) {
	files := artifactFiles(t)
	directory := artifactDirectory(t)
	files["project.d.ts"] = bytes.Repeat([]byte("x"), maxArtifactBytes+1)
	if writeArtifacts(directory, files, false) == nil {
		t.Fatal("unbounded rendered output accepted")
	}
	files["project.d.ts"] = []byte("types")
	if err := writeArtifacts(directory, files, false); err != nil {
		t.Fatal(err)
	}
	writeArtifactFixture(t, filepath.Join(directory, "project.d.ts"), bytes.Repeat([]byte("x"), maxArtifactBytes+1))
	for _, check := range []bool{true, false} {
		if writeArtifacts(directory, files, check) == nil {
			t.Fatal("unbounded existing output accepted")
		}
	}
}

func TestArtifactRejectsSymlinks(t *testing.T) {
	for _, location := range []string{"root", "parent", "file", "optional"} {
		t.Run(location, func(t *testing.T) {
			directory := artifactDirectory(t)
			outside := t.TempDir()
			victim := filepath.Join(outside, "victim")
			writeArtifactFixture(t, victim, []byte("preserve"))
			if err := os.Mkdir(directory, 0755); err != nil {
				t.Fatal(err)
			}
			link, target := directory, outside
			switch location {
			case "root":
				if err := os.Remove(directory); err != nil {
					t.Fatal(err)
				}
			case "parent":
				link = filepath.Join(directory, "parent")
				directory = filepath.Join(link, "generated")
			case "file":
				link, target = filepath.Join(directory, "project.d.ts"), victim
			case "optional":
				link, target = filepath.Join(directory, "workloads.json"), victim
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			for _, check := range []bool{false, true} {
				if writeArtifacts(directory, artifactFiles(t), check) == nil {
					t.Fatal("followed symlink")
				}
			}
			if data, err := os.ReadFile(victim); err != nil || string(data) != "preserve" {
				t.Fatal("symlink target changed", err)
			}
		})
	}
}
