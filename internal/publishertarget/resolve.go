package publishertarget

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

// Placement is host-validated metadata carried into an owner container. its
// worktree identity must not be recomputed from that container's client state.
type Placement struct {
	ProjectRoot string                 `json:"project_root"`
	Worktree    projectconfig.Worktree `json:"worktree"`
	PrimaryRoot string                 `json:"primary_root"`
	OwnerID     string                 `json:"owner_container_id"`
	NetworkID   string                 `json:"network_id"`
}

type Resolver struct {
	Docker    Runner
	Placement *Placement
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
	address, err := r.address(ctx, c, port)
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
		root := project.Root
		if r.Placement != nil {
			root = r.Placement.ProjectRoot
		}
		file := filepath.Join(root, *target.File)
		if r.Placement == nil {
			file, err = project.ComposeFile(name)
			if err != nil {
				return Container{}, 0, err
			}
		}
		c, err = ComposeContainer(ctx, docker, root, file, *target.Project, *target.Service, r.worktree(project))
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
	if c.Config.Labels[WorktreeLabel] == "" || c.Config.Labels[WorktreeLabel] != r.worktree(project) {
		return Container{}, 0, errors.New("container does not belong to the current worktree")
	}
	return c, *target.Port, nil
}

func (r Resolver) worktree(project projectconfig.Project) string {
	if r.Placement != nil {
		return r.Placement.Worktree.Label.FullLabel
	}
	return project.Worktree.Label.FullLabel
}

func (r Resolver) address(ctx context.Context, c Container, port int) (string, error) {
	if r.Placement == nil {
		return published(c, port)
	}
	owner, err := Inspect(ctx, r.DockerCLI(), r.Placement.OwnerID)
	if err != nil {
		return "", err
	}
	if owner.Config.Labels[WorktreeLabel] != r.Placement.Worktree.Label.FullLabel {
		return "", errors.New("publisher container worktree changed")
	}
	addresses := map[netip.Addr]bool{}
	for _, network := range c.NetworkSettings.Networks {
		if network.NetworkID != r.Placement.NetworkID || network.NetworkID == "" {
			continue
		}
		shared := false
		for _, candidate := range owner.NetworkSettings.Networks {
			shared = shared || candidate.NetworkID == network.NetworkID
		}
		if !shared {
			return "", errors.New("target is outside the publisher's private network")
		}
		// one deterministic family avoids silently selecting between addresses.
		address, err := netip.ParseAddr(network.IPAddress)
		if err != nil || address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() {
			return "", errors.New("target has no private network IPv4 address")
		}
		addresses[address] = true
	}
	if len(addresses) != 1 {
		return "", errors.New("target must have one address on the selected private network")
	}
	for address := range addresses {
		return netip.AddrPortFrom(address, uint16(port)).String(), nil
	}
	panic("unreachable")
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
	if !ComposeFilesMatch(root, file, labels["com.docker.compose.project.config_files"]) || labels[WorktreeLabel] != worktree || labels["com.docker.compose.project"] != project || labels["com.docker.compose.service"] != service || strings.ToLower(labels["com.docker.compose.oneoff"]) != "false" || labels["com.docker.compose.project.working_dir"] != root {
		return Container{}, errors.New("compose container placement labels do not match this project")
	}
	return c, nil
}

// ComposeFilesMatch accepts only the selected file and its generated override.
func ComposeFilesMatch(root, file, configFiles string) bool {
	generated := filepath.Join(root, ".tnl", "compose.generated.yaml")
	return configFiles == file || configFiles == file+","+generated
}

func ComposeArgs(root, file, project string) []string {
	args := []string{"compose", "--project-directory", root, "--file", file}
	if extra := filepath.Join(root, ".tnl", "compose.generated.yaml"); extra != file {
		if info, err := os.Lstat(extra); err == nil && info.Mode().IsRegular() {
			args = append(args, "--file", extra)
		}
	}
	return append(args, "--project-name", project)
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

// ResolveApp maps only the reported port, never an app-supplied address, onto
// its configured Compose service. owner and pid are lease identifiers only.
func (r Resolver) ResolveApp(ctx context.Context, project projectconfig.Project, composeProject, file, composeService, reported string) (string, error) {
	address, _, err := r.ResolveAppIdentity(ctx, project, composeProject, file, composeService, reported)
	return address, err
}

func (r Resolver) ResolveAppIdentity(ctx context.Context, project projectconfig.Project, composeProject, file, composeService, reported string) (string, string, error) {
	u, err := url.Parse(reported)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return "", "", errors.New("app listener must be an HTTP origin")
	}
	address, err := netip.ParseAddr(u.Hostname())
	port, portErr := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || portErr != nil || port == 0 || address.Zone() != "" || !address.IsLoopback() && !address.IsUnspecified() {
		return "", "", errors.New("app listener must report a loopback or wildcard address and explicit port")
	}
	root := project.Root
	if r.Placement != nil {
		root = r.Placement.ProjectRoot
	}
	if err := Local(ctx, r.DockerCLI()); err != nil {
		return "", "", err
	}
	c, err := ComposeContainer(ctx, r.DockerCLI(), root, file, composeProject, composeService, r.worktree(project))
	if err != nil {
		return "", "", err
	}
	private, err := r.address(ctx, c, int(port))
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("%s://%s", u.Scheme, private), c.ID + "/" + strconv.FormatUint(port, 10) + "/" + private, nil
}
