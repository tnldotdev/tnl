package dockertarget

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

type Container struct {
	Name     string
	Networks []string
	Bindings map[string][]HostBinding
}

type HostBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type inspectedContainer struct {
	Name  string `json:"Name"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	NetworkSettings struct {
		Ports    map[string][]HostBinding   `json:"Ports"`
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
}

// SelectContainer uses one exact selector and checks that the running
// container still belongs to the selected worktree before returning it.
func SelectContainer(ctx context.Context, root, worktree string, selected config.DockerSelection) (Container, error) {
	if !filepath.IsAbs(root) || worktree == "" || selected.ContainerPort == nil || *selected.ContainerPort < 1 || *selected.ContainerPort > 65535 {
		return Container{}, errors.New("select Docker container: invalid project or private port")
	}
	var identifier string
	if compose := selected.Compose; compose != nil {
		if compose.Project != worktree {
			return Container{}, errors.New("compose project differs from this worktree label")
		}
		file, err := composeFile(root, compose.File)
		if err != nil {
			return Container{}, err
		}
		arguments := []string{"compose", "--project-directory", root, "--file", file, "--project-name", worktree}
		data, err := dockerCommand(ctx, root, 512<<10, append(slices.Clone(arguments), "config", "--format", "json")...)
		if err != nil {
			return Container{}, fmt.Errorf("render selected Compose file: %w", err)
		}
		var rendered struct {
			Services map[string]struct {
				ContainerName string `json:"container_name"`
				Ports         []struct {
					Target   int    `json:"target"`
					Protocol string `json:"protocol"`
				} `json:"ports"`
			} `json:"services"`
		}
		if err := json.Unmarshal(data, &rendered); err != nil {
			return Container{}, fmt.Errorf("decode rendered Compose file: %w", err)
		}
		definition, found := rendered.Services[compose.Service]
		if !found {
			return Container{}, fmt.Errorf("compose service %q is not declared in %s", compose.Service, compose.File)
		}
		if definition.ContainerName != "" {
			return Container{}, errors.New("compose service has a fixed container_name; remove it to isolate worktrees")
		}
		_ = definition
		data, err = dockerCommand(ctx, root, 512, append(arguments, "ps", "-q", compose.Service)...)
		if err != nil {
			return Container{}, fmt.Errorf("inspect selected Compose service: %w", err)
		}
		identifier, err = singleContainerID(data)
		if err != nil {
			return Container{}, err
		}
	} else if selected.Container != nil {
		identifier = *selected.Container
	} else {
		arguments := []string{"ps", "--filter", "label=tnl.worktree=" + worktree, "--format", "{{.ID}}"}
		keys := make([]string, 0, len(selected.Labels))
		for key := range selected.Labels {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			arguments = append(arguments, "--filter", "label="+key+"="+selected.Labels[key])
		}
		data, err := dockerCommand(ctx, root, 512, arguments...)
		if err != nil {
			return Container{}, fmt.Errorf("select labeled Docker container: %w", err)
		}
		identifier, err = singleContainerID(data)
		if err != nil {
			return Container{}, err
		}
	}
	data, err := dockerCommand(ctx, root, 64<<10, "inspect", identifier)
	if err != nil {
		return Container{}, fmt.Errorf("inspect selected Docker container: %w", err)
	}
	var containers []inspectedContainer
	if err := json.Unmarshal(data, &containers); err != nil || len(containers) != 1 {
		return Container{}, errors.New("docker did not return one inspected container")
	}
	container := containers[0]
	if !container.State.Running {
		return Container{}, errors.New("selected Docker container is not running")
	}
	if compose := selected.Compose; compose != nil {
		labels := container.Config.Labels
		if labels["com.docker.compose.project"] != worktree || labels["com.docker.compose.service"] != compose.Service {
			return Container{}, errors.New("selected container is not in the configured Compose project and service")
		}
		file, _ := composeFile(root, compose.File)
		canonicalRoot, err := filepath.EvalSymlinks(root)
		if err != nil || !slices.Contains(strings.Split(labels["com.docker.compose.project.config_files"], ","), file) ||
			labels["com.docker.compose.project.working_dir"] != canonicalRoot {
			return Container{}, errors.New("selected container was created from another Compose file or worktree")
		}
	} else {
		if container.Config.Labels["tnl.worktree"] != worktree {
			return Container{}, errors.New("selected Docker container has no matching tnl.worktree label")
		}
		for key, value := range selected.Labels {
			if container.Config.Labels[key] != value {
				return Container{}, errors.New("selected Docker container does not match the configured labels")
			}
		}
	}
	name := strings.TrimPrefix(container.Name, "/")
	if name == "" {
		return Container{}, errors.New("selected Docker container has no network name")
	}
	networks := make([]string, 0, len(container.NetworkSettings.Networks))
	for network := range container.NetworkSettings.Networks {
		networks = append(networks, network)
	}
	slices.Sort(networks)
	return Container{Name: name, Networks: networks, Bindings: container.NetworkSettings.Ports}, nil
}

func HostPort(container Container, port int, publisher bool) (string, error) {
	bindings := container.Bindings[strconv.Itoa(port)+"/tcp"]
	if len(bindings) != 1 {
		return "", errors.New("selected Docker container needs exactly one published TCP binding")
	}
	address, err := parsePort(net.JoinHostPort(bindings[0].HostIP, bindings[0].HostPort))
	if err != nil {
		return "", err
	}
	if publisher {
		ip := net.ParseIP(bindings[0].HostIP)
		if ip == nil || !ip.IsLoopback() {
			return "", errors.New("publisher API port must bind host loopback")
		}
	}
	return address, nil
}

func composeFile(root, name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return "", errors.New("compose file must be relative to the project")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, name))
	if err != nil {
		return "", fmt.Errorf("resolve Compose file: %w", err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve project directory: %w", err)
	}
	relative, err := filepath.Rel(canonicalRoot, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("compose file is outside the selected worktree")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("compose file must be a regular project file")
	}
	return resolved, nil
}

func singleContainerID(data []byte) (string, error) {
	lines := strings.Fields(string(data))
	if len(lines) != 1 || !validDockerID(lines[0]) {
		return "", errors.New("expected exactly one running selected Docker container")
	}
	return lines[0], nil
}

func validDockerID(value string) bool {
	if len(value) < 12 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func dockerCommand(ctx context.Context, root string, limit int, args ...string) ([]byte, error) {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(callCtx, "docker", args...)
	command.Dir = root
	command.Stderr = io.Discard
	output := &boundedOutput{limit: limit}
	command.Stdout = output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("docker command failed: %w", err)
	}
	if output.tooLarge {
		return nil, errors.New("docker response exceeds its limit")
	}
	return bytes.Clone([]byte(output.String())), nil
}
