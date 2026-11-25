package meta

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
)

type Completion struct {
	Services    map[string]string `json:"services"`
	Deployments []string          `json:"deployments"`
}

const completionName = "completion.json"

func WriteCompletion(ctx context.Context, project clientproject.Project) error {
	return writeCompletion(ctx, project, nil)
}

func writeCompletion(ctx context.Context, project clientproject.Project, outcomes *[]ArtifactOutcome) error {
	if project.Declared == nil {
		return nil
	}
	facts := Completion{Services: map[string]string{}, Deployments: slices.Sorted(maps.Keys(project.Declared.Deployments))}
	for name, service := range project.Declared.Services {
		facts.Services[name] = config.DeclaredProtocol(service)
	}
	data, err := json.Marshal(facts)
	if err != nil {
		return err
	}
	return writeLocalJSON(ctx, project.Root, completionName, data, outcomes)
}

// ReadCompletion reads only regular, bounded worktree files. Older worktrees
// may have endpoint metadata but no declaration index yet.
func ReadCompletion(directory string) Completion {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return Completion{}
	}
	defer root.Close()
	read := func(name string) []byte {
		path := filepath.Join(DirectoryName, name)
		info, err := root.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > MaxFileBytes {
			return nil
		}
		f, err := root.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
		if err != nil || len(data) > MaxFileBytes {
			return nil
		}
		return data
	}
	var facts Completion
	if err := json.Unmarshal(read(completionName), &facts); err != nil {
		m, err := Parse(read(JSONName))
		if err != nil {
			return Completion{}
		}
		facts = Completion{Services: map[string]string{}}
		for name, service := range m.Services {
			facts.Services[name] = service.Protocol
		}
	}
	for name, protocol := range facts.Services {
		if !naming.ValidServiceName(name) || !config.ValidProtocol(protocol) {
			delete(facts.Services, name)
		}
	}
	facts.Deployments = slices.DeleteFunc(facts.Deployments, func(name string) bool { return !naming.ValidServiceName(name) })
	return facts
}
