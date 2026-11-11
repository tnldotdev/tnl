package meta

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxArtifactBytes = 1 << 20

// generatedFiles is the complete set of portable outputs owned by tnl.
var generatedFiles = [...]string{
	"project.d.ts",
	"python/pyproject.toml",
	"python/tnl_project/__init__.py",
	"python/tnl_project/py.typed",
	"workloads.json",
}

// writeArtifacts compares or atomically replaces fixed tool-owned outputs.
// a nil entry means the optional output must be absent; other files are untouched.
func writeArtifacts(directory string, files map[string][]byte, check bool) error {
	root, err := openDirectory(directory, !check)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range generatedFiles {
		content := files[name]
		if len(content) > maxArtifactBytes {
			return fmt.Errorf("generated artifact %s exceeds its size bound", name)
		}
		parent, err := descend(root, filepath.Dir(name), !check && content != nil)
		if err != nil {
			return err
		}
		err = writeArtifact(parent, filepath.Base(name), content, check)
		parent.Close()
		if err != nil {
			return fmt.Errorf("generated artifact %s: %w", name, err)
		}
	}
	return nil
}

// openDirectory pins each real parent before descending, so replacing an
// ancestor cannot redirect later file operations through a symlink.
func openDirectory(directory string, create bool) (*os.Root, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	base := filepath.VolumeName(absolute) + string(filepath.Separator)
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return descend(root, strings.TrimPrefix(absolute, base), create)
}

func descend(root *os.Root, directory string, create bool) (*os.Root, error) {
	current, err := root.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(filepath.ToSlash(directory), "/") {
		if part == "" || part == "." {
			continue
		}
		if create {
			if err := current.Mkdir(part, 0755); err != nil && !errors.Is(err, os.ErrExist) {
				current.Close()
				return nil, err
			}
		}
		info, err := current.Lstat(part)
		if err != nil {
			current.Close()
			return nil, err
		}
		if !info.IsDir() {
			current.Close()
			return nil, errors.New("generated directories must not be symlinks or non-directories")
		}
		next, err := current.OpenRoot(part)
		current.Close()
		if err != nil {
			return nil, err
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			next.Close()
			return nil, errors.New("generated directory changed while opening it")
		}
		current = next
	}
	return current, nil
}

func writeArtifact(parent *os.Root, name string, content []byte, check bool) error {
	info, err := parent.Lstat(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() > maxArtifactBytes {
			return errors.New("output must be a bounded regular file, not a symlink")
		}
		file, err := parent.Open(name)
		if err != nil {
			return err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, opened) {
			file.Close()
			return errors.New("generated file changed while opening it")
		}
		previous, readErr := io.ReadAll(io.LimitReader(file, maxArtifactBytes+1))
		err = errors.Join(readErr, file.Close())
		if err != nil {
			return err
		}
		if len(previous) > maxArtifactBytes {
			return errors.New("output exceeds its size bound")
		}
		if content != nil && bytes.Equal(previous, content) {
			return nil
		}
	} else if content == nil {
		return nil
	}
	if check {
		return errors.New("output is stale; run tnl generate")
	}
	if content == nil {
		return parent.Remove(name)
	}
	temporary := ".tnl-" + rand.Text() + ".tmp"
	file, err := parent.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer parent.Remove(temporary)
	_, writeErr := file.Write(content)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return parent.Rename(temporary, name)
}
