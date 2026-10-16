package projectconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
)

// Project is a selected and resolved project configuration.
type Project struct {
	Selection Selection
	Config    config.TNL
	Worktree  Worktree
	Root      string
}

// Resolve loads a selected project configuration and resolves its worktree and
// configuration. an empty selection still resolves cwd as a
// project so commands without a configuration file share the same identity.
func Resolve(ctx context.Context, selection Selection, cwd string, salt [32]byte) (Project, error) {
	worktree, err := ResolveWorktree(ctx, cwd)
	if err != nil {
		return Project{}, fmt.Errorf("resolve project worktree: %w", err)
	}
	project := Project{
		Selection: selection,
		Worktree:  ApplyWorktreeHashSalt(worktree, worktree.Root, salt),
		Root:      worktree.Root,
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
	config.NormalizePublicURLs(&project.Config)

	names := make([]string, 0, len(project.Config.Services))
	for name := range project.Config.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if target := project.Config.Services[name].Target; target != nil && target.Type == "compose" {
			file, resolveErr := project.ComposeFile(name)
			if resolveErr != nil {
				return Project{}, resolveErr
			}
			if target.File == nil || target.Project == nil {
				service := project.Config.Services[name]
				resolved := *target
				if resolved.File == nil {
					root, err := filepath.EvalSymlinks(project.Root)
					if err != nil {
						return Project{}, err
					}
					relative, err := filepath.Rel(root, file)
					if err != nil {
						return Project{}, err
					}
					resolved.File = &relative
				}
				if resolved.Project == nil {
					label := project.Worktree.Label.FullLabel
					resolved.Project = &label
				}
				service.Target = &resolved
				project.Config.Services[name] = service
			}
		}
	}
	return project, nil
}

// Found reports whether the project has a selected configuration file.
func (p Project) Found() bool { return p.Selection.Path != "" }

// AppService selects a configured app target. cwd identifies the project only;
// when more than one app is configured, the caller must select one by name.
func (p Project) AppService(cwd, selected string) (string, error) {
	if err := config.ValidateTNL(p.Config); err != nil {
		return "", err
	}
	directory, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", fmt.Errorf("resolve app directory: %w", err)
	}
	root, err := filepath.EvalSymlinks(p.Root)
	if err != nil || !pathWithin(directory, root) {
		return "", errors.New("app directory must be inside the project")
	}
	if selected != "" {
		service, found := p.Config.Services[selected]
		if !found || config.TargetType(service) != "app" {
			return "", fmt.Errorf("service %q is not an app service", selected)
		}
		return selected, nil
	}
	name := ""
	for candidate, service := range p.Config.Services {
		if config.TargetType(service) != "app" {
			continue
		}
		if name != "" {
			return "", errors.New("select an app service explicitly when more than one is configured")
		}
		name = candidate
	}
	if name == "" {
		return "", errors.New("no configured app service")
	}
	return name, nil
}

// EffectiveService merges one named service over the root defaults.
func (p Project) EffectiveService(name string) (config.TNL, error) {
	base := p.Config
	result := config.TNL{
		Server: base.Server, Team: base.Team, Feedback: base.Feedback, OAuth: base.OAuth, Publisher: base.Publisher,
		Inspection: config.MergeInspection(base.Inspection, nil),
		Webhooks:   base.Webhooks, Tunnel: cloneTunnel(base.Tunnel), Publish: config.ServicePublish(config.Service{}),
	}
	if name == "" {
		return result, nil
	}
	service, found := base.Services[name]
	if !found {
		return config.TNL{}, fmt.Errorf("service %q is not configured", name)
	}
	result.Inspection = config.MergeInspection(result.Inspection, service.Inspection)
	if config.Protocol(service) == "tcp" {
		if service.Tunnel != nil {
			return config.TNL{}, fmt.Errorf("service %q: private tcp cannot use public tunnel settings", name)
		}
		// private services never inherit public URL policy, even when the
		// project also publishes HTTP or SSH services.
		result.Tunnel = nil
	} else {
		result.Tunnel = mergeTunnel(result.Tunnel, service.Tunnel)
	}
	result.Publish = config.ServicePublish(service)
	if service.HTTP != nil {
		result.Readiness = service.HTTP.Readiness
		if service.HTTP.Open != nil {
			if result.Tunnel == nil {
				result.Tunnel = &config.Tunnel{}
			}
			result.Tunnel.Open = service.HTTP.Open
		}
	}
	return result, nil
}

// ResolvePublish finishes private discovery and resolves a relative target CA
// path against the selected configuration's directory, independent of cwd.
func (p Project) ResolvePublish(name, discovered string) (*config.Publish, error) {
	service, found := p.Config.Services[name]
	if !found {
		return nil, fmt.Errorf("service %q is not configured", name)
	}
	result, err := config.ResolveServiceTarget(service, discovered)
	if err != nil {
		return nil, err
	}
	if result.TargetCAFile != nil && !filepath.IsAbs(*result.TargetCAFile) {
		path, err := filepath.Abs(filepath.Join(p.Root, *result.TargetCAFile))
		if err != nil {
			return nil, err
		}
		result.TargetCAFile = &path
	}
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
	if override.Domain != nil {
		result.Domain = override.Domain
	}
	if override.Name != nil {
		result.Name, result.PublicURL = override.Name, nil
	}
	if override.PublicURL != nil {
		result.PublicURL, result.Name = override.PublicURL, nil
	}
	if override.Open != nil {
		result.Open = override.Open
	}
	if override.Access != nil {
		access := *override.Access
		access.IP = slices.Clone(access.IP)
		result.Access = &access
	}
	if override.Ephemeral != nil {
		result.Ephemeral = override.Ephemeral
	}
	result.Limits = config.MergeLimits(result.Limits, override.Limits)
	return result
}

func cloneTunnel(value *config.Tunnel) *config.Tunnel {
	if value == nil {
		return nil
	}
	result := *value
	if value.Access != nil {
		access := *value.Access
		access.IP = slices.Clone(access.IP)
		result.Access = &access
	}
	result.Limits = config.MergeLimits(value.Limits, nil)
	return &result
}

// ComposeProject derives a worktree-specific Compose project name unless the
// target explicitly selects an existing project.
func (p Project) ComposeProject(name string) (string, error) {
	service, found := p.Config.Services[name]
	if !found || service.Target == nil || service.Target.Type != "compose" {
		return "", fmt.Errorf("service %q has no compose target", name)
	}
	if service.Target.Project != nil {
		return *service.Target.Project, nil
	}
	return p.Worktree.Label.FullLabel, nil
}

// PublisherComposeFile resolves the selected project's Compose file.
func (p Project) PublisherComposeFile() (string, error) {
	if p.Config.Publisher == nil || p.Config.Publisher.Type != "compose" {
		return "", errors.New("publisher has no compose placement")
	}
	return p.resolveComposeFile(p.Config.Publisher.File)
}

// ComposeFile resolves a configured Compose file and rejects symlink escapes.
// the runtime receives an absolute file path for its explicit project command.
func (p Project) ComposeFile(name string) (string, error) {
	service, found := p.Config.Services[name]
	if !found || service.Target == nil || service.Target.Type != "compose" {
		return "", fmt.Errorf("service %q has no compose target", name)
	}
	if err := config.ValidateTNL(p.Config); err != nil {
		return "", err
	}
	return p.resolveComposeFile(service.Target.File)
}

func (p Project) resolveComposeFile(selected *string) (string, error) {
	root, err := filepath.EvalSymlinks(p.Root)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	relativeFile := ""
	if selected != nil {
		relativeFile = *selected
	} else {
		for _, candidate := range []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"} {
			if _, err := os.Lstat(filepath.Join(root, candidate)); err == nil {
				relativeFile = candidate
				break
			}
		}
		if relativeFile == "" {
			return "", errors.New("compose file is missing; add compose.yaml or select file explicitly")
		}
	}
	file, err := filepath.EvalSymlinks(filepath.Join(root, relativeFile))
	if err != nil {
		return "", fmt.Errorf("resolve compose file: %w", err)
	}
	relative, err := filepath.Rel(root, file)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("compose file resolves outside project")
	}
	info, err := os.Stat(file)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("compose file must be a regular file")
	}
	return file, nil
}
