package publisherdeployment

import (
	"bytes"
	"crypto/rand"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// openDirectory rejects symlink components before opening a rooted filesystem.
// all subsequent operations stay beneath that root, including during renames.
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
	// pin each checked parent before descending. a replaced path must not redirect
	// subsequent directory creation or file replacement through a symlink.
	for _, part := range strings.Split(strings.TrimPrefix(absolute, base), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		if create {
			if err := root.Mkdir(part, 0755); err != nil && !errors.Is(err, fs.ErrExist) {
				root.Close()
				return nil, err
			}
		}
		next, err := openChild(root, part)
		root.Close()
		if err != nil {
			return nil, err
		}
		root = next
	}
	return root, nil
}

func openChild(root *os.Root, name string) (*os.Root, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("generated directories must not contain symlinks or non-directories")
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := child.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		child.Close()
		return nil, errors.New("generated directory changed while opening it")
	}
	return child, nil
}

// fileParent returns a separately owned, pinned directory for a canonical path.
func fileParent(root *os.Root, name string) (*os.Root, string, error) {
	directory, base := filepath.Split(filepath.FromSlash(name))
	if directory == "" {
		parent, err := root.OpenRoot(".")
		return parent, base, err
	}
	parent, err := openChild(root, strings.TrimSuffix(directory, string(filepath.Separator)))
	return parent, base, err
}

func readFile(root *os.Root, name string, limit int64) ([]byte, error) {
	if err := regularPath(root, name); err != nil {
		return nil, err
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("generated file exceeds its size bound or is not regular")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(data) > int(limit) {
		return nil, errors.New("generated file exceeds its size bound")
	}
	return data, err
}

func regularPath(root *os.Root, name string) error {
	parts := strings.Split(name, "/")
	for i := range parts {
		info, err := root.Lstat(strings.Join(parts[:i+1], "/"))
		if err != nil {
			return err
		}
		if i < len(parts)-1 && !info.IsDir() || i == len(parts)-1 && !info.Mode().IsRegular() {
			return errors.New("generated paths must be regular files and directories, without symlinks")
		}
	}
	return nil
}

func readManifest(root *os.Root) (Manifest, error) {
	var m Manifest
	data, err := readFile(root, ManifestPath, MaxManifestBytes)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m, json.RejectUnknownMembers(true)); err != nil {
		return m, errors.New("invalid publisher manifest JSON")
	}
	return m, m.Validate()
}

func (m Manifest) hashes() map[string]string {
	result := map[string]string{}
	if m.DeclarationsSHA256 != "" {
		result["project.d.ts"] = m.DeclarationsSHA256
	}
	if m.WorkloadsSHA256 != "" {
		result["workloads.json"] = m.WorkloadsSHA256
	}
	if m.DocumentationPath != "" {
		result[m.DocumentationPath] = m.DocumentationSHA256
	}
	for _, p := range m.Publishers {
		result[p.TemplatePath], result[p.ParametersExamplePath] = p.TemplateSHA256, p.ParametersExampleSHA256
	}
	return result
}

// Read performs bounded, read-only manifest and artifact validation. use Validate
// as well when current source/configuration are available; hashes are not trust.
func Read(outputDir string) (Manifest, error) {
	root, err := openDirectory(outputDir, false)
	if err != nil {
		return Manifest{}, err
	}
	defer root.Close()
	m, err := readManifest(root)
	if err != nil {
		return m, err
	}
	for _, name := range slices.Sorted(maps.Keys(m.hashes())) {
		data, err := readFile(root, name, MaxArtifactBytes)
		if err != nil {
			return m, fmt.Errorf("read generated artifact %s: %w", name, err)
		}
		if digest(data) != m.hashes()[name] {
			return m, fmt.Errorf("generated artifact %s is stale; run tnl generate", name)
		}
	}
	return m, nil
}

// Check never creates directories or temporary artifacts and compares every
// owned output byte, including the manifest's ownership list.
func (b Bundle) Check(outputDir string) error {
	if err := b.validate(); err != nil {
		return err
	}
	root, err := openDirectory(outputDir, false)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range slices.Sorted(maps.Keys(b.Files)) {
		data, err := readFile(root, name, MaxArtifactBytes)
		if err != nil {
			return fmt.Errorf("read generated artifact %s: %w", name, err)
		}
		if !bytes.Equal(data, b.Files[name]) {
			return fmt.Errorf("generated artifact %s is stale; run tnl generate", name)
		}
	}
	return nil
}

// Write replaces only declared outputs. removed publishers are cleaned up only
// when their old files still match their manifest hashes. unrelated files stay.
func (b Bundle) Write(outputDir string) error {
	if err := b.validate(); err != nil {
		return err
	}
	root, err := openDirectory(outputDir, true)
	if err != nil {
		return err
	}
	defer root.Close()
	old, err := readManifest(root)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	owned := old.hashes()
	// preflight all paths before writing or removing any artifacts.
	for name, hash := range owned {
		if _, keep := b.Files[name]; keep {
			continue
		}
		data, err := readFile(root, name, MaxArtifactBytes)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if digest(data) != hash {
			return fmt.Errorf("retired generated artifact %s was edited; move it before generating", name)
		}
	}
	for name, expected := range b.Files {
		data, err := readFile(root, name, MaxArtifactBytes)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if _, exists := owned[name]; name != ManifestPath && !exists && !bytes.Equal(data, expected) {
			return fmt.Errorf("output %s is not owned by the manifest; move it before generating", name)
		}
	}
	if err := root.Mkdir("aws", 0755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := root.Lstat("aws")
	if err != nil || !info.IsDir() {
		return errors.New("aws output directory must not be a symlink")
	}
	for _, name := range slices.Sorted(maps.Keys(b.Files)) {
		if name == ManifestPath {
			continue
		}
		if err := replaceFile(root, name, b.Files[name]); err != nil {
			return err
		}
	}
	for name := range owned {
		if _, keep := b.Files[name]; !keep {
			parent, base, err := fileParent(root, name)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			err = parent.Remove(base)
			parent.Close()
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return replaceFile(root, ManifestPath, b.Files[ManifestPath])
}

func (b Bundle) validate() error {
	if err := b.Manifest.Validate(); err != nil {
		return err
	}
	hashes := b.Manifest.hashes()
	if len(b.Files) != len(hashes)+1 {
		return errors.New("bundle file ownership differs from manifest")
	}
	for name, hash := range hashes {
		if len(b.Files[name]) > MaxArtifactBytes || digest(b.Files[name]) != hash {
			return errors.New("bundle artifact differs from manifest")
		}
	}
	data, err := encode(b.Manifest)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, b.Files[ManifestPath]) {
		return errors.New("bundle manifest bytes differ")
	}
	return nil
}

func replaceFile(root *os.Root, name string, data []byte) error {
	if previous, err := readFile(root, name, MaxArtifactBytes); err == nil && bytes.Equal(previous, data) {
		return nil
	}
	parent, base, err := fileParent(root, name)
	if err != nil {
		return err
	}
	defer parent.Close()
	// exclusive creation and rename avoid following an existing destination link.
	temporary := ".tnl-" + rand.Text() + ".tmp"
	f, err := parent.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer parent.Remove(temporary)
	_, writeErr := f.Write(data)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		return err
	}
	return parent.Rename(temporary, base)
}
