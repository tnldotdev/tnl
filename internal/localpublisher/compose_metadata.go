package localpublisher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publishertarget"
)

// ComposeSetup contains host-selected placement facts, not credentials. only a
// host CLI with Docker exec access installs it in the owner's private state.
type ComposeSetup struct {
	Placement   publishertarget.Placement `json:"placement"`
	Project     string                    `json:"project"`
	File        string                    `json:"file"`
	Service     string                    `json:"service"`
	Port        int                       `json:"port"`
	ProjectRoot string                    `json:"project_root"`
	Apps        map[string]ComposeApp     `json:"apps"`
}

type ComposeApp struct {
	Service  string `json:"service"`
	Endpoint string `json:"endpoint"`
}

var ErrComposePlacementStale = errors.New("compose publisher placement changed")

func (s ComposeSetup) Validate(ctx context.Context, docker publishertarget.Runner) error {
	if s.Port < 1 || s.Port > 65535 || !filepath.IsAbs(s.ProjectRoot) || filepath.Clean(s.ProjectRoot) != s.ProjectRoot || !filepath.IsAbs(s.Placement.ProjectRoot) || !filepath.IsAbs(s.File) || s.Placement.Worktree.Label.FullLabel == "" {
		return errors.New("invalid compose publisher placement")
	}
	if err := publishertarget.Local(ctx, docker); err != nil {
		return err
	}
	owner, err := publishertarget.ComposeContainer(ctx, docker, s.Placement.ProjectRoot, s.File, s.Project, s.Service, s.Placement.Worktree.Label.FullLabel)
	if err != nil {
		return err
	}
	if owner.ID != s.Placement.OwnerID {
		return ErrComposePlacementStale
	}
	if len(owner.NetworkSettings.Ports[strconv.Itoa(s.Port)+"/tcp"]) != 0 {
		return errors.New("compose publisher API port must not be published on the host")
	}
	network, err := ComposeNetwork(ctx, docker, owner, s.Placement.Worktree.Label.FullLabel)
	if err != nil || network != s.Placement.NetworkID {
		if err != nil {
			return err
		}
		return ErrComposePlacementStale
	}
	for name, app := range s.Apps {
		if name == "" || !validComposeService(app.Service) || !filepath.IsAbs(app.Endpoint) || filepath.Clean(app.Endpoint) != app.Endpoint || strings.ContainsAny(app.Endpoint, "\x00\r\n") {
			return errors.New("invalid compose app endpoint mapping")
		}
	}
	return nil
}

func (s ComposeSetup) Boundary(docker publishertarget.Runner, stateRoot string) ComposeBoundary {
	return ComposeBoundary{Docker: docker, Placement: s.Placement, Project: s.Project, File: s.File, Service: s.Service, Port: s.Port, StateRoot: stateRoot}
}

// Apply preserves the host's salted worktree identity even when the container
// has its own client state and a different project mount path.
func (s ComposeSetup) Apply(project projectconfig.Project) (projectconfig.Project, error) {
	if project.Root != s.ProjectRoot {
		return project, errors.New("compose project root does not match host placement metadata")
	}
	if s.Placement.PrimaryRoot == "" {
		return project, errors.New("host worktree restoration is required for compose placement")
	}
	worktree, err := projectconfig.RestoreHostWorktree(s.Placement.Worktree, s.Placement.ProjectRoot, s.Placement.PrimaryRoot)
	if err != nil {
		return project, err
	}
	containerLabel := project.Worktree.Label.FullLabel
	project.Worktree = worktree
	// project resolution filled implicit compose project names before the
	// host's worktree salt arrived. keep explicit project selections intact.
	for name, service := range project.Config.Services {
		if target := service.Target; target != nil && target.Type == "compose" && target.Project != nil && *target.Project == containerLabel {
			copy := *target
			label := worktree.Label.FullLabel
			copy.Project = &label
			service.Target = &copy
			project.Config.Services[name] = service
		}
	}
	return project, nil
}

func (s ComposeSetup) WriteApps(ctx context.Context, docker publishertarget.Runner, stateRoot string, capabilities *privateprotocol.Capabilities) error {
	if err := s.Validate(ctx, docker); err != nil {
		return err
	}
	apps := make([]AppEndpointMount, 0, len(s.Apps))
	for name, definition := range s.Apps {
		container, err := publishertarget.ComposeContainer(ctx, docker, s.Placement.ProjectRoot, s.File, s.Project, definition.Service, s.Placement.Worktree.Label.FullLabel)
		if err != nil {
			return err
		}
		apps = append(apps, AppEndpointMount{Service: name, Path: definition.Endpoint, Container: container})
	}
	if len(apps) == 0 {
		return nil
	}
	return WriteComposeAppEndpoints(ctx, s.Boundary(docker, stateRoot), capabilities, apps)
}

func WriteComposeSetup(root string, setup ComposeSetup) error {
	directory, err := privateprotocol.RuntimeDir(root)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "compose-placement.json")
	if info, err := os.Lstat(path); err == nil {
		if err := clientstate.ValidatePrivateFile(info, false); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(directory, ".placement-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := json.NewEncoder(file).Encode(setup); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func ReadComposeSetup(root string) (ComposeSetup, error) {
	directory, err := privateprotocol.RuntimeDir(root)
	if err != nil {
		return ComposeSetup{}, err
	}
	file, err := clientstate.OpenPrivateFile(filepath.Join(directory, "compose-placement.json"))
	if err != nil {
		return ComposeSetup{}, err
	}
	defer file.Close()
	return DecodeComposeSetup(file)
}

func DecodeComposeSetup(input io.Reader) (ComposeSetup, error) {
	data, err := io.ReadAll(io.LimitReader(input, privateprotocol.MaxBytes+1))
	var setup ComposeSetup
	if err != nil || len(data) > privateprotocol.MaxBytes || strictJSON(data, &setup) != nil {
		return setup, errors.New("invalid compose placement metadata")
	}
	return setup, nil
}
