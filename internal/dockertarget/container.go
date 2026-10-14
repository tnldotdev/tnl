package dockertarget

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

const maxInspectOutput = 64 << 10

type hostBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type inspectedContainer struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	NetworkSettings struct {
		Ports map[string][]hostBinding `json:"Ports"`
	} `json:"NetworkSettings"`
}

// ContainerPort resolves a running, worktree-labeled container's current host
// binding for one private TCP port. a changed name or missing binding fails closed.
func ContainerPort(ctx context.Context, root, worktree, identifier string, port int) (string, error) {
	if !filepath.IsAbs(root) || worktree == "" || !config.ValidContainerSelector(identifier) || port < 1 || port > 65535 {
		return "", errors.New("docker target requires a project root, worktree label, exact container ID or name, and private port")
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("inspect project root: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case lookups <- struct{}{}:
		defer func() { <-lookups }()
	case <-ctx.Done():
		return "", fmt.Errorf("wait to inspect Docker container: %w", ctx.Err())
	}
	command := exec.CommandContext(ctx, "docker", "container", "inspect", identifier)
	command.Dir = base
	output := &inspectOutput{}
	command.Stdout = output
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("inspect Docker container: %w", ctx.Err())
		}
		return "", fmt.Errorf("inspect Docker container %q: %w", identifier, err)
	}
	if output.overflow {
		return "", errors.New("docker container inspection exceeds 64 KiB")
	}
	var containers []inspectedContainer
	if err := json.Unmarshal(output.Bytes(), &containers); err != nil || len(containers) != 1 {
		return "", errors.New("docker did not return one inspected container")
	}
	container := containers[0]
	if isContainerID(identifier) {
		if !strings.HasPrefix(container.ID, identifier) || len(container.ID) != 64 || !isContainerID(container.ID) {
			return "", errors.New("inspected Docker container ID does not match the selected ID")
		}
	} else if container.Name != "/"+identifier {
		return "", errors.New("inspected Docker container name does not match the selected name")
	}
	if !container.State.Running || container.Config.Labels["tnl.worktree"] != worktree {
		return "", errors.New("selected Docker container must be running with this worktree's tnl.worktree label")
	}
	bindings := container.NetworkSettings.Ports[strconv.Itoa(port)+"/tcp"]
	if len(bindings) != 1 {
		return "", errors.New("selected Docker container needs exactly one published TCP binding for its private port")
	}
	return parsePort(net.JoinHostPort(bindings[0].HostIP, bindings[0].HostPort))
}

func isContainerID(value string) bool {
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

type inspectOutput struct {
	bytes.Buffer
	overflow bool
}

func (o *inspectOutput) Write(data []byte) (int, error) {
	n := len(data)
	available := maxInspectOutput - o.Len()
	if available > 0 {
		_, _ = o.Buffer.Write(data[:min(n, available)])
	}
	if n > available {
		o.overflow = true
	}
	return n, nil
}
