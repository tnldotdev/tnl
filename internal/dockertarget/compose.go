package dockertarget

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxPortOutput = 256

var composeName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// ComposePort finds the current host binding for one Compose service's private
// TCP port. a caller must resolve it again after a container replacement.
func ComposePort(ctx context.Context, projectRoot, projectLabel, service string, privatePort int) (string, error) {
	if !filepath.IsAbs(projectRoot) || !composeName.MatchString(projectLabel) || !composeName.MatchString(service) ||
		privatePort < 1 || privatePort > 65535 {
		return "", errors.New("docker target requires an absolute project directory, a Compose project and service name, and a TCP port from 1 to 65535")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", "compose", "--project-directory", projectRoot,
		"--project-name", projectLabel, "port", service, strconv.Itoa(privatePort))
	command.Dir = projectRoot
	command.Stderr = io.Discard
	output := &boundedOutput{limit: maxPortOutput}
	command.Stdout = output
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("inspect Compose service %q: %w", service, ctx.Err())
		}
		return "", fmt.Errorf("inspect Compose service %q host port: %w", service, err)
	}
	if output.tooLarge {
		return "", fmt.Errorf("inspect Compose service %q: port output is too large", service)
	}
	address, err := parsePort(output.String())
	if err != nil {
		return "", fmt.Errorf("inspect Compose service %q: %w", service, err)
	}
	return address, nil
}

type boundedOutput struct {
	strings.Builder
	limit    int
	tooLarge bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	size := len(data)
	remaining := b.limit - b.Len()
	if remaining > 0 {
		if remaining < size {
			_, _ = b.Builder.Write(data[:remaining])
		} else {
			_, _ = b.Builder.Write(data)
		}
	}
	if size > remaining {
		b.tooLarge = true
	}
	return size, nil
}

func parsePort(output string) (string, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 1 {
		return "", errors.New("expected exactly one published TCP port")
	}
	host, portText, err := net.SplitHostPort(strings.TrimSpace(lines[0]))
	if err != nil {
		return "", errors.New("expected one host:port binding")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("published TCP port is invalid")
	}
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() && !address.IsUnspecified() {
		return "", errors.New("published TCP port must bind loopback or all interfaces")
	}
	if address.IsUnspecified() {
		if address.To4() != nil {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
