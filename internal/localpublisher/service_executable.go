//go:build linux || darwin

package localpublisher

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func serviceExecutable() string { return filepath.Join(ServiceStateRoot(), "tnl") }

func installServiceExecutable() error {
	source, err := os.Executable()
	if err != nil || !filepath.IsAbs(source) {
		return errors.New("publisher service needs an absolute executable path")
	}
	directory := filepath.Dir(serviceExecutable())
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create publisher service executable directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("publisher service executable directory must be owned by root")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.CreateTemp(directory, ".tnl-executable-")
	if err != nil {
		return err
	}
	defer os.Remove(output.Name())
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Chmod(0o755); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	return os.Rename(output.Name(), serviceExecutable())
}

func writeServiceConfig(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".tnl-service-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
