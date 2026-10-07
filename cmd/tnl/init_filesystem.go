package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const initReadLimit = 1 << 20

func readInitFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, initReadLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > initReadLimit {
		return nil, fmt.Errorf("refusing to edit %s: file exceeds %d bytes", path, initReadLimit)
	}
	return data, nil
}

func createInitFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".tnl-init-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return fmt.Errorf("set temporary file permissions for %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	return nil
}

func replaceRecognizedInitFile(path string, expected, replacement []byte) error {
	if expected == nil {
		return createInitFile(path, replacement)
	}
	current, err := readInitFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf("refusing to overwrite %s because it changed during initialization", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to overwrite %s because it is not a regular file", path)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".tnl-init-*")
	if err != nil {
		return fmt.Errorf("create temporary replacement for %s: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		temporary.Close()
		return fmt.Errorf("set temporary replacement permissions for %s: %w", path, err)
	}
	if _, err := temporary.Write(replacement); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary replacement for %s: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary replacement for %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary replacement for %s: %w", path, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("update %s: %w", path, err)
	}
	return nil
}
