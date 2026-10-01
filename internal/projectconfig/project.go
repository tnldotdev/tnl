package projectconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
)

// Project is a selected and resolved project configuration.
type Project struct {
	Selection                  Selection
	Config                     config.TNL
	Worktree                   Worktree
	Root                       string
	ServiceDirectories         map[string]string
	RelativeServiceDirectories map[string]string
}

// Resolve loads a selected project configuration and resolves its worktree and
// configured service directories. an empty selection still resolves cwd as a
// project so commands without a configuration file share the same identity.
func Resolve(ctx context.Context, selection Selection, cwd string, salt [32]byte) (Project, error) {
	worktree, err := ResolveWorktree(ctx, cwd)
	if err != nil {
		return Project{}, fmt.Errorf("resolve project worktree: %w", err)
	}
	project := Project{
		Selection:                  selection,
		Worktree:                   ApplyWorktreeHashSalt(worktree, worktree.Root, salt),
		Root:                       worktree.Root,
		ServiceDirectories:         make(map[string]string),
		RelativeServiceDirectories: make(map[string]string),
	}
	if selection.Path == "" {
		return project, nil
	}

	project.Root = filepath.Dir(selection.Path)
	project.Worktree, err = ResolveWorktree(ctx, project.Root)
	if err != nil {
		return Project{}, fmt.Errorf("resolve project worktree: %w", err)
	}
	project.Worktree = ApplyWorktreeHashSalt(project.Worktree, project.Root, salt)
	if strings.EqualFold(filepath.Ext(selection.Path), ".ts") {
		project.Config, err = loadTypeScript(ctx, selection.Path, cwd, project.Worktree)
	} else {
		var document config.Document
		document, err = config.LoadDocument(selection.Path)
		if err == nil && document.TNL != nil {
			project.Config = *document.TNL
		}
	}
	if err != nil {
		return Project{}, err
	}

	names := make([]string, 0, len(project.Config.Services))
	for name := range project.Config.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		directory, relative, resolveErr := project.ServiceDirectory(name)
		if resolveErr != nil {
			return Project{}, fmt.Errorf("service %q: %w", name, resolveErr)
		}
		project.ServiceDirectories[name] = directory
		project.RelativeServiceDirectories[name] = relative
	}
	return project, nil
}

// Found reports whether the project has a selected configuration file.
func (p Project) Found() bool { return p.Selection.Path != "" }

// ServiceDirectory resolves a service's existing directory and rejects
// symlink traversal outside the project root.
func (p Project) ServiceDirectory(name string) (string, string, error) {
	if err := config.ValidateTNL(p.Config); err != nil {
		return "", "", err
	}
	value := "."
	if name != "" {
		service, found := p.Config.Services[name]
		if !found {
			return "", "", fmt.Errorf("service %q is not configured", name)
		}
		if service.Directory != nil {
			value = *service.Directory
		}
	}
	root, err := filepath.Abs(p.Root)
	if err != nil {
		return "", "", fmt.Errorf("resolve project root: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", fmt.Errorf("resolve project root: %w", err)
	}
	relative := filepath.Clean(value)
	path := filepath.Join(root, relative)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", "", fmt.Errorf("resolve service directory %q: %w", value, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", "", fmt.Errorf("inspect service directory %q: %w", value, err)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("service directory %q is not a directory", value)
	}
	inside, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("service directory %q resolves outside the project root", value)
	}
	return filepath.Clean(path), filepath.ToSlash(relative), nil
}

// EffectiveService merges one named service over the root defaults.
func (p Project) EffectiveService(name string) (config.TNL, error) {
	base := p.Config
	result := config.TNL{
		Server: base.Server, Team: base.Team,
		Tunnel: cloneTunnel(base.Tunnel), Publish: clonePublish(base.Publish), Dev: cloneDev(base.Dev),
	}
	if name == "" {
		return result, nil
	}
	service, found := base.Services[name]
	if !found {
		return config.TNL{}, fmt.Errorf("service %q is not configured", name)
	}
	if service.Server != nil {
		result.Server = service.Server
	}
	if service.Team != nil {
		result.Team = service.Team
	}
	result.Tunnel = mergeTunnel(result.Tunnel, service.Tunnel)
	result.Publish = mergePublish(result.Publish, service.Publish)
	result.Dev = mergeDev(result.Dev, service.Dev)
	return result, nil
}

func mergeTunnel(base, override *config.Tunnel) *config.Tunnel {
	result := cloneTunnel(base)
	if override == nil {
		return result
	}
	if result == nil {
		result = &config.Tunnel{}
	}
	if override.Host != nil {
		result.Host, result.Subdomain = override.Host, nil
	}
	if override.Subdomain != nil {
		result.Subdomain, result.Host = override.Subdomain, nil
	}
	if override.AllowIP != nil {
		result.AllowIP = slices.Clone(override.AllowIP)
		result.AllowAllIPs = nil
	}
	if override.AllowProviders != nil {
		result.AllowProviders = slices.Clone(override.AllowProviders)
		result.AllowAllIPs = nil
	}
	if override.AllowAllIPs != nil {
		result.AllowAllIPs = override.AllowAllIPs
		if *override.AllowAllIPs {
			result.AllowIP = nil
			result.AllowProviders = nil
		}
	}
	if override.Ephemeral != nil {
		result.Ephemeral = override.Ephemeral
	}
	if override.RequestLimit != nil {
		result.RequestLimit = override.RequestLimit
	}
	return result
}

func mergePublish(base, override *config.Publish) *config.Publish {
	result := clonePublish(base)
	if override == nil {
		return result
	}
	if result == nil {
		result = &config.Publish{}
	}
	if override.Target != nil {
		result.Target = override.Target
	}
	return result
}

func mergeDev(base, override *config.Dev) *config.Dev {
	result := cloneDev(base)
	if override == nil {
		return result
	}
	if result == nil {
		result = &config.Dev{}
	}
	if override.Command != nil {
		result.Command = slices.Clone(override.Command)
	}
	if override.Port != nil {
		result.Port = override.Port
	}
	if override.StartupTimeout != nil {
		result.StartupTimeout = override.StartupTimeout
	}
	return result
}

func cloneTunnel(value *config.Tunnel) *config.Tunnel {
	if value == nil {
		return nil
	}
	result := *value
	result.AllowIP = slices.Clone(value.AllowIP)
	result.AllowProviders = slices.Clone(value.AllowProviders)
	return &result
}

func clonePublish(value *config.Publish) *config.Publish {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneDev(value *config.Dev) *config.Dev {
	if value == nil {
		return nil
	}
	result := *value
	result.Command = slices.Clone(value.Command)
	return &result
}
