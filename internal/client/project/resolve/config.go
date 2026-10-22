// package resolve composes project selection with client state and current
// server facts. static evaluation remains in projectconfig.
package resolve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
)

// Options selects configuration without depending on a command's flags.
// an empty Directory uses the current working directory.
type Options struct {
	Directory       string
	ConfigPath      string
	EnvironmentPath string
	NoConfig        bool
}

func Select(ctx context.Context, options Options) (projectconfig.Selection, string, error) {
	cwd := options.Directory
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return projectconfig.Selection{}, "", failure.Wrap("read working directory", failure.CurrentDirectoryUnavailable, err)
		}
	}
	selection, err := projectconfig.SelectProjectConfig(ctx, cwd, options.ConfigPath, options.EnvironmentPath, options.NoConfig)
	return selection, cwd, failure.Wrap("select project configuration", failure.ProjectConfigInvalid, err)
}

func Load(ctx context.Context, options Options, stateRoot string) (projectconfig.Project, error) {
	state, err := clientstate.Open(ctx, stateRoot)
	if err != nil {
		return projectconfig.Project{}, failure.Wrap("open client state", failure.ClientStateUnavailable, err)
	}
	salt, err := state.WorktreeHashSalt(ctx)
	closeErr := state.Close()
	if err != nil {
		return projectconfig.Project{}, failure.Wrap("read worktree identity", failure.ClientStateUnavailable, err)
	}
	if closeErr != nil {
		return projectconfig.Project{}, failure.Wrap("close client state", failure.ClientStateUnavailable, closeErr)
	}
	return LoadWithSalt(ctx, options, salt)
}

func LoadWithSalt(ctx context.Context, options Options, salt [32]byte) (projectconfig.Project, error) {
	selection, cwd, err := Select(ctx, options)
	if err != nil {
		return projectconfig.Project{}, err
	}
	project, err := projectconfig.Resolve(ctx, selection, cwd, salt)
	if err != nil {
		return projectconfig.Project{}, failure.Wrap("load project configuration", failure.ProjectConfigInvalid, err)
	}
	return project, nil
}

// Root selects the canonical project directory without evaluating configuration.
func Root(ctx context.Context, options Options) (string, error) {
	selection, cwd, err := Select(ctx, options)
	if err != nil {
		return "", err
	}
	if selection.Path != "" {
		return filepath.EvalSymlinks(filepath.Dir(selection.Path))
	}
	worktree, err := projectconfig.ResolveWorktree(ctx, cwd)
	if err != nil {
		return "", fmt.Errorf("resolve project worktree: %w", err)
	}
	return worktree.Root, nil
}

func DefaultService(services config.Services) (string, error) {
	if len(services) == 0 {
		return "", nil
	}
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	slices.Sort(names)
	if len(names) == 1 {
		return names[0], nil
	}
	message := fmt.Sprintf("service is required; configured services: %s", strings.Join(names, ", "))
	return "", diagnostic.WrapMessage(diagnostic.ServiceAmbiguous, message, errors.New(message))
}

// Server preserves explicit selection and its provenance. a project must not
// choose the destination for an explicitly supplied credential.
func Server(selected string, project *string, token string) (server string, fromProject bool, err error) {
	if selected != "" || project == nil {
		return selected, false, nil
	}
	if token != "" {
		return "", false, errors.New("an explicit access token with a project-provided server requires --server or TNL_SERVER")
	}
	return *project, true, nil
}

func TeamForServer(server string, configuredServer, configuredTeam *string) (string, error) {
	if configuredTeam == nil {
		return "", nil
	}
	if server != "" && configuredServer != nil {
		selected, err := clientstate.CanonicalServer(server)
		if err != nil {
			return "", err
		}
		project, err := clientstate.CanonicalServer(*configuredServer)
		if err != nil {
			return "", err
		}
		if selected != project {
			return "", nil
		}
	}
	return *configuredTeam, nil
}
