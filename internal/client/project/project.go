package project

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
)

// Project is a selected and resolved project configuration.
type Project struct {
	Selection  Selection
	Config     config.TNL
	Declared   *config.Project
	Deployment string
	Worktree   Worktree
	Root       string
}

// Resolve loads a selected project configuration and resolves its worktree and
// configuration. an empty selection still resolves cwd as a
// project so commands without a configuration file share the same identity.
func Resolve(ctx context.Context, selection Selection, cwd string, salt [32]byte) (Project, error) {
	directory := cwd
	if selection.Path != "" {
		path, err := absolutePath(cwd, selection.Path)
		if err != nil {
			return Project{}, err
		}
		directory, err = filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return Project{}, fmt.Errorf("resolve selected project directory: %w", err)
		}
		selection.Path = filepath.Join(directory, filepath.Base(path))
	}
	worktree, err := ResolveWorktree(ctx, directory)
	if err != nil {
		return Project{}, fmt.Errorf("resolve project worktree: %w", err)
	}
	root := worktree.Root
	if selection.Path != "" {
		root = directory
	}
	project := Project{
		Selection: selection,
		Worktree:  ApplyWorktreeHashSalt(worktree, root, salt),
		Root:      root,
	}
	if selection.Path == "" {
		if selection.Workload != "" || selection.Deployment != "" && selection.Deployment != "local" {
			return Project{}, errors.New("selected deployment or workload requires project configuration")
		}
		project.Deployment = "local"
		project.Selection.Deployment = "local"
		return project, nil
	}

	var declared config.Project
	if strings.EqualFold(filepath.Ext(selection.Path), ".ts") {
		declared, err = loadTypeScript(ctx, selection.Path, cwd, project.Worktree)
	} else {
		var document config.Document
		document, err = config.LoadDocument(selection.Path)
		if err == nil && document.TNL != nil {
			declared = *document.TNL
		}
	}
	if err != nil {
		return Project{}, err
	}
	// retain evaluated declarations before resolving worktree-local defaults.
	project.Declared = &declared
	name := selection.Deployment
	if selection.Workload != "" {
		policy, found := declared.Workloads[selection.Workload]
		if !found || name != "" && name != policy.Deployment {
			return Project{}, errors.New("selected workload is missing or belongs to another deployment")
		}
		name = policy.Deployment
	}
	return project.SelectDeployment(name)
}

// SelectDeployment materializes one captured selection without changing another
// handle or evaluating configuration again. local discovery defaults stay local.
func (project Project) SelectDeployment(name string) (Project, error) {
	if name == "" {
		name = "local"
	}
	if project.Declared == nil {
		return Project{}, errors.New("project declarations have not been loaded")
	}
	var err error
	project.Config, err = config.ResolveDeployment(*project.Declared, name)
	if err != nil {
		return Project{}, err
	}
	project.Deployment = name
	project.Selection.Deployment = name
	project.Config.Services = maps.Clone(project.Config.Services)

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

// ResolvedService contains inherited settings for one service, not a parsed
// project document. target discovery and trust resolution happen separately.
type ResolvedService struct {
	config.Service
	Server   *string
	Team     *string
	Feedback *bool
	OAuth    bool
	Publish  *config.Publish
	Webhooks map[string]config.Webhook
}

// EffectiveService selects one binding with project identity and local settings.
func (p Project) EffectiveService(name string) (ResolvedService, error) {
	if err := config.ValidateTNL(p.Config); err != nil {
		return ResolvedService{}, err
	}
	base := p.Config
	var service config.Service
	if name != "" {
		var found bool
		service, found = base.Services[name]
		if !found {
			return ResolvedService{}, fmt.Errorf("service %q is not configured", name)
		}
	}
	result := ResolvedService{
		Service: service, Server: base.Server, Team: base.Team,
		Publish: config.ServicePublish(service),
	}
	result.Name = base.Name
	if name != "" {
		savedName := config.ServiceName(name, service)
		result.Name = &savedName
	}
	if config.Protocol(service) == "http" {
		result.Feedback, result.OAuth, result.Webhooks = base.Feedback, base.OAuth, base.Webhooks
		result.Inspection = config.MergeInspection(base.Inspection, service.Inspection)
	} else {
		result.Inspection = config.MergeInspection(nil, service.Inspection)
	}
	if service.HTTP != nil {
		http := *service.HTTP
		http.Paths = maps.Clone(http.Paths)
		if http.Access != nil {
			access := *http.Access
			access.IP = slices.Clone(access.IP)
			http.Access = &access
		}
		if http.Limits != nil {
			limits := *http.Limits
			if limits.Rate != nil {
				rate := *limits.Rate
				limits.Rate = &rate
			}
			http.Limits = &limits
		}
		result.HTTP = &http
	}
	if service.Traffic != nil {
		traffic := *service.Traffic
		result.Traffic = &traffic
	}
	return result, nil
}

// ResolvePublish finishes target discovery for the captured deployment.
func (p Project) ResolvePublish(name, discovered string) (*config.Publish, error) {
	service, found := p.Config.Services[name]
	if !found {
		return nil, fmt.Errorf("service %q is not configured", name)
	}
	result, err := config.ResolveServiceTarget(service, discovered)
	if err != nil {
		return nil, err
	}
	return result, nil
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
