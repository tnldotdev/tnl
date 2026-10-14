package dockertarget

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var name = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
var lookups = make(chan struct{}, 8)

// ComposePort resolves one explicitly selected worktree's current host binding.
func ComposePort(ctx context.Context, root, file, project, service string, port int) (string, error) {
	if !filepath.IsAbs(root) || !name.MatchString(project) || !name.MatchString(service) || port < 1 || port > 65535 ||
		file == "" || filepath.IsAbs(file) || filepath.Clean(file) != file || file == "." || file == ".." || strings.HasPrefix(file, ".."+string(filepath.Separator)) {
		return "", errors.New("compose target requires an absolute project root, relative file, project, service, and private port")
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("inspect Compose project directory: %w", err)
	}
	selected, err := filepath.EvalSymlinks(filepath.Join(base, file))
	if err != nil {
		return "", fmt.Errorf("inspect Compose file: %w", err)
	}
	relative, err := filepath.Rel(base, selected)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("compose file resolves outside the project directory")
	}
	info, err := os.Stat(selected)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("compose file must be a regular file")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case lookups <- struct{}{}:
		defer func() { <-lookups }()
	case <-ctx.Done():
		return "", fmt.Errorf("wait to inspect Compose port: %w", ctx.Err())
	}
	command := exec.CommandContext(ctx, "docker", "compose", "--project-directory", base, "--file", selected,
		"--project-name", project, "port", "--protocol", "tcp", service, strconv.Itoa(port))
	command.Dir = base
	command.Stderr = nil
	output := &portOutput{}
	command.Stdout = output
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("inspect Compose port: %w", ctx.Err())
		}
		return "", fmt.Errorf("inspect Compose port for %s: %w", service, err)
	}
	if output.overflow {
		return "", errors.New("compose port output exceeds 256 bytes")
	}
	return parsePort(output.String())
}

type portOutput struct {
	strings.Builder
	overflow bool
}

func (o *portOutput) Write(data []byte) (int, error) {
	n := len(data)
	available := 256 - o.Len()
	if available > 0 {
		_, _ = o.Builder.Write(data[:min(n, available)])
	}
	if n > available {
		o.overflow = true
	}
	return n, nil
}

func parsePort(output string) (string, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 1 {
		return "", errors.New("expected exactly one published TCP port")
	}
	host, text, err := net.SplitHostPort(strings.TrimSpace(lines[0]))
	if err != nil {
		return "", errors.New("expected one host:port binding")
	}
	port, err := strconv.Atoi(text)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("published TCP port is invalid")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() && !ip.IsUnspecified() {
		return "", errors.New("published TCP port must bind loopback or all interfaces")
	}
	if ip.IsUnspecified() {
		if ip.To4() != nil {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
