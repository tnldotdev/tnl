package projectmeta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/filelock"
)

const (
	DirectoryName    = ".tnl"
	JSONName         = "project.json"
	DeclarationsName = "project.d.ts"
	MaxFileBytes     = 64 << 10
)

// Write validates project metadata and replaces both generated files while
// holding the writer lock. Each file replacement is atomic, but both files do
// not become visible at the same instant. If the second replacement fails,
// Write tries to restore the first file.
func Write(ctx context.Context, projectRoot string, metadata Metadata) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if !filepath.IsAbs(projectRoot) {
		return errors.New("project metadata root must be absolute")
	}
	jsonData, declarations, err := Render(metadata)
	if err != nil {
		return err
	}
	directory := filepath.Join(filepath.Clean(projectRoot), DirectoryName)
	if err := prepareDirectory(directory); err != nil {
		return err
	}
	lock, err := filelock.AcquireContext(ctx, filepath.Join(directory, "project.lock"), os.Geteuid())
	if err != nil {
		return fmt.Errorf("lock project metadata: %w", err)
	}
	defer lock.Close()
	declarationsPath := filepath.Join(directory, DeclarationsName)
	jsonPath := filepath.Join(directory, JSONName)
	if err := validateOutputPath(declarationsPath); err != nil {
		return err
	}
	if err := validateOutputPath(jsonPath); err != nil {
		return err
	}
	declarationWrite, err := stageWrite(declarationsPath, declarations)
	if err != nil {
		return err
	}
	defer declarationWrite.cleanup()
	jsonWrite, err := stageWrite(jsonPath, jsonData)
	if err != nil {
		return err
	}
	defer jsonWrite.cleanup()
	if err := declarationWrite.commit(); err != nil {
		return err
	}
	if err := jsonWrite.commit(); err != nil {
		return errors.Join(err, declarationWrite.restore())
	}
	return nil
}

func validateOutputPath(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect generated project metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("generated project metadata path %s must be a regular file", path)
	}
	return nil
}

func Render(metadata Metadata) ([]byte, []byte, error) {
	if err := metadata.Validate(); err != nil {
		return nil, nil, err
	}
	jsonData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("encode project metadata: %w", err)
	}
	jsonData = append(jsonData, '\n')
	declarations := renderDeclarations(metadata)
	if len(jsonData) > MaxFileBytes || len(declarations) > MaxFileBytes {
		return nil, nil, fmt.Errorf("generated project metadata exceeds %d bytes", MaxFileBytes)
	}
	return jsonData, declarations, nil
}

func renderDeclarations(metadata Metadata) []byte {
	var output strings.Builder
	output.WriteString("import \"@tnldotdev/tnl\";\n\ndeclare module \"@tnldotdev/tnl\" {\n")
	output.WriteString("  interface TnlProjectMetadata {\n")
	output.WriteString("    readonly namespace: ")
	if commonNamespace(metadata) {
		output.WriteString(typeScriptString(metadata.Namespace))
	} else {
		output.WriteString("string")
	}
	output.WriteString(";\n    readonly services: {\n")
	names := make([]string, 0, len(metadata.Services))
	for name := range metadata.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		service := metadata.Services[name]
		output.WriteString("      readonly ")
		output.WriteString(typeScriptPropertyName(name))
		output.WriteString(": {\n        readonly namespace: ")
		output.WriteString(typeScriptString(service.Namespace))
		output.WriteString(";\n        readonly hostname: ")
		output.WriteString(typeScriptString(service.Hostname))
		output.WriteString(";\n        readonly url: ")
		output.WriteString(typeScriptString(service.URL))
		output.WriteString(";\n      };\n")
	}
	output.WriteString("    };\n  }\n}\n")
	return []byte(output.String())
}

func commonNamespace(metadata Metadata) bool {
	for _, service := range metadata.Services {
		if service.Namespace != metadata.Namespace {
			return false
		}
	}
	return true
}

func typeScriptString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func typeScriptPropertyName(value string) string {
	if strings.Contains(value, "-") {
		return typeScriptString(value)
	}
	return value
}

func prepareDirectory(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("project metadata directory must be a real directory")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect project metadata directory: %w", err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		return fmt.Errorf("create project metadata directory: %w", err)
	}
	return nil
}

type stagedWrite struct {
	path        string
	temporary   string
	previous    []byte
	hadPrevious bool
	changed     bool
}

func stageWrite(path string, data []byte) (*stagedWrite, error) {
	write := &stagedWrite{path: path}
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		return write, nil
	} else if err == nil {
		write.previous, write.hadPrevious = current, true
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read generated project metadata: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".project-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary project metadata: %w", err)
	}
	write.temporary = temporary.Name()
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		write.cleanup()
		return nil, fmt.Errorf("set project metadata permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		write.cleanup()
		return nil, fmt.Errorf("write project metadata: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		write.cleanup()
		return nil, fmt.Errorf("sync project metadata: %w", err)
	}
	if err := temporary.Close(); err != nil {
		write.cleanup()
		return nil, fmt.Errorf("close project metadata: %w", err)
	}
	write.changed = true
	return write, nil
}

func (w *stagedWrite) commit() error {
	if !w.changed {
		return nil
	}
	if err := os.Rename(w.temporary, w.path); err != nil {
		return fmt.Errorf("replace project metadata: %w", err)
	}
	w.temporary = ""
	return nil
}

func (w *stagedWrite) restore() error {
	if !w.changed || w.temporary != "" {
		return nil
	}
	if !w.hadPrevious {
		if err := os.Remove(w.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("restore generated project metadata: %w", err)
		}
		return nil
	}
	restore, err := stageWrite(w.path, w.previous)
	if err != nil {
		return fmt.Errorf("restore generated project metadata: %w", err)
	}
	defer restore.cleanup()
	if err := restore.commit(); err != nil {
		return fmt.Errorf("restore generated project metadata: %w", err)
	}
	return nil
}

func (w *stagedWrite) cleanup() {
	if w != nil && w.temporary != "" {
		_ = os.Remove(w.temporary)
		w.temporary = ""
	}
}
