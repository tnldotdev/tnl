package publishertarget

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

type Resolver struct {
	Docker Runner
}

func (r Resolver) DockerCLI() Runner {
	if r.Docker != nil {
		return r.Docker
	}
	return CLI{}
}

func (r Resolver) ResolveTarget(ctx context.Context, project projectconfig.Project, name string) (string, error) {
	address, _, err := r.ResolveTargetIdentity(ctx, project, name)
	return address, err
}

// ResolveTargetIdentity fences readiness if a new container reuses an address.
func (r Resolver) ResolveTargetIdentity(ctx context.Context, project projectconfig.Project, name string) (string, string, error) {
	c, port, err := r.targetContainer(ctx, project, name)
	if err != nil {
		return "", "", err
	}
	address, err := published(c, port)
	if err != nil {
		return "", "", err
	}
	return address, c.ID + "/" + strconv.Itoa(port) + "/" + address, nil
}

func (r Resolver) targetContainer(ctx context.Context, project projectconfig.Project, name string) (Container, int, error) {
	service, found := project.Config.Services[name]
	if !found || service.Target == nil {
		return Container{}, 0, errors.New("select a configured container target")
	}
	target := service.Target
	if target.Port == nil || *target.Port < 1 || *target.Port > 65535 {
		return Container{}, 0, errors.New("container target requires a valid TCP port")
	}
	docker := r.DockerCLI()
	if err := Local(ctx, docker); err != nil {
		return Container{}, 0, err
	}
	var c Container
	var err error
	switch target.Type {
	case "compose":
		if target.Project == nil || target.File == nil || target.Service == nil {
			return Container{}, 0, errors.New("compose target requires project, file, and service")
		}
		file, fileErr := project.ComposeFile(name)
		if fileErr != nil {
			return Container{}, 0, fileErr
		}
		c, err = ComposeContainer(ctx, docker, project.Root, file, *target.Project, *target.Service, project.Worktree.Label.FullLabel)
	case "docker":
		if target.Container == nil || !config.ValidDockerIdentifier(*target.Container) {
			return Container{}, 0, errors.New("docker target requires an exact container identifier")
		}
		c, err = Inspect(ctx, docker, *target.Container)
	default:
		return Container{}, 0, errors.New("target is not a compose or docker target")
	}
	if err != nil {
		return Container{}, 0, err
	}
	if c.Config.Labels[WorktreeLabel] == "" || c.Config.Labels[WorktreeLabel] != project.Worktree.Label.FullLabel {
		return Container{}, 0, errors.New("container does not belong to the current worktree")
	}
	return c, *target.Port, nil
}

// ComposeContainer verifies ps output against immutable inspect identity and
// all placement labels. no generated container name or ID prefix is accepted.
func ComposeContainer(ctx context.Context, docker Runner, root, file, project, service, worktree string) (Container, error) {
	if !validIdentifier(project) || !validIdentifier(service) || worktree == "" || !filepath.IsAbs(root) || !filepath.IsAbs(file) {
		return Container{}, errors.New("compose discovery requires exact project, file, service, and worktree")
	}
	args := ComposeArgs(root, file, project)
	args = append(args, "ps", "--status", "running", "--quiet", service)
	data, err := docker.Run(ctx, nil, args...)
	if err != nil {
		return Container{}, err
	}
	ids := strings.Fields(string(data))
	if len(ids) != 1 || len(ids[0]) != 64 || !validHex(ids[0]) {
		return Container{}, errors.New("compose service must have exactly one running container")
	}
	c, err := Inspect(ctx, docker, ids[0])
	if err != nil {
		return Container{}, err
	}
	labels := c.Config.Labels
	if !ComposeFilesMatch(file, labels["com.docker.compose.project.config_files"]) || labels[WorktreeLabel] != worktree || labels["com.docker.compose.project"] != project || labels["com.docker.compose.service"] != service || strings.ToLower(labels["com.docker.compose.oneoff"]) != "false" || labels["com.docker.compose.project.working_dir"] != root {
		return Container{}, errors.New("compose container placement labels do not match this project")
	}
	return c, nil
}

// ComposeFilesMatch accepts only the selected Compose file.
func ComposeFilesMatch(file, configFiles string) bool {
	return configFiles == file
}

func ComposeArgs(root, file, project string) []string {
	return []string{"compose", "--project-directory", root, "--file", file, "--project-name", project}
}

// ComposeFile validates host-owned paths, including symlinks, before an exec.
func ComposeFile(root, relative string) (string, error) {
	if filepath.IsAbs(relative) || relative == "" {
		return "", errors.New("compose file must be project-relative")
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	file, err := filepath.EvalSymlinks(filepath.Join(canonicalRoot, relative))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(canonicalRoot, file)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("compose file resolves outside the project")
	}
	info, err := os.Stat(file)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("compose file must be a regular file")
	}
	return file, nil
}
