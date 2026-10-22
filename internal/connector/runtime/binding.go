package connectionruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// Binding is portable operator-applied scope, not authorization. authority still
// verifies the job's claims and exact team/project policy during exchange.
type Binding struct {
	Schema     int    `json:"schema"`
	Server     string `json:"server"`
	Team       string `json:"team"`
	TeamID     string `json:"team_id"`
	ProjectKey string `json:"project_key"`
	SourceID   string `json:"source_id"`
}

const BindingPath = ".tnl/generated/connections.json"

func bindingParents(root string, create bool) error {
	for _, relative := range []string{".tnl", ".tnl/generated"} {
		path := filepath.Join(root, relative)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && create {
			if err = os.Mkdir(path, 0o755); err != nil {
				return err
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
	}
	return nil
}
func ReadBinding(root string) (Binding, error) {
	var binding Binding
	if bindingParents(root, false) != nil {
		return binding, ErrTeam
	}
	path := filepath.Join(root, BindingPath)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxBytes {
		return binding, ErrTeam
	}
	f, err := os.Open(path)
	if err != nil {
		return binding, ErrTeam
	}
	defer f.Close()
	if ReadJSON(f, &binding) != nil || binding.Schema != Schema || !opaqueid.Valid(binding.TeamID, opaqueid.TeamPrefix) {
		return Binding{}, ErrTeam
	}
	return binding, nil
}
func WriteBinding(root string, binding Binding) error {
	if binding.Schema != Schema || !opaqueid.Valid(binding.TeamID, opaqueid.TeamPrefix) {
		return ErrInvalid
	}
	if err := bindingParents(root, true); err != nil {
		return err
	}
	path := filepath.Join(root, BindingPath)
	if _, err := os.Lstat(path); err == nil {
		old, err := ReadBinding(root)
		if err != nil || old.ProjectKey != binding.ProjectKey || old.SourceID != binding.SourceID {
			return ErrInvalid
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(binding, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), ".connections-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(f.Name(), 0o644); err != nil {
		return err
	}
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(data, current) {
		return nil
	}
	return os.Rename(f.Name(), path)
}
