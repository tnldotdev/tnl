package meta

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/client/filelock"
)

const (
	DirectoryName = ".tnl/local"
	JSONName      = "project.json"
	MaxFileBytes  = 64 << 10
)

// Render serializes runtime values only. portable declarations use Declarations.
func Render(metadata Metadata) ([]byte, error) {
	if err := metadata.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("generated project metadata exceeds %d bytes", MaxFileBytes)
	}
	return data, nil
}

// Write atomically replaces runtime JSON, leaving every declaration untouched.
func Write(ctx context.Context, projectRoot string, metadata Metadata) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	data, err := Render(metadata)
	if err != nil {
		return err
	}
	return writeLocalJSON(ctx, projectRoot, JSONName, data, nil)
}

func writeLocalJSON(ctx context.Context, projectRoot, name string, data []byte, outcomes *[]ArtifactOutcome) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if !filepath.IsAbs(projectRoot) {
		return errors.New("project metadata root must be absolute")
	}
	root, err := os.OpenRoot(projectRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range []string{".tnl", DirectoryName} {
		if err := root.Mkdir(name, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("project metadata directories must not be symlinks")
		}
	}
	local, err := root.OpenRoot(DirectoryName)
	if err != nil {
		return err
	}
	defer local.Close()
	lock, err := filelock.AcquireContext(ctx, filepath.Join(projectRoot, DirectoryName, "project.lock"), os.Geteuid())
	if err != nil {
		return err
	}
	defer lock.Close()
	info, err := local.Lstat(name)
	if err == nil && !info.Mode().IsRegular() {
		return errors.New("project metadata must be a regular file")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	record := func(status string) {
		if outcomes != nil {
			*outcomes = append(*outcomes, ArtifactOutcome{Path: filepath.Join(projectRoot, DirectoryName, name), Status: status})
		}
	}
	if info != nil && info.Size() == int64(len(data)) {
		previous, err := local.ReadFile(name)
		if err == nil && bytes.Equal(previous, data) {
			record("unchanged")
			return nil
		}
	}
	temporary := ".project-" + rand.Text()
	file, err := local.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer local.Remove(temporary)
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := local.Rename(temporary, name); err != nil {
		return err
	}
	if info == nil {
		record("created")
	} else {
		record("updated")
	}
	return nil
}
