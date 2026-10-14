package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// composeOwnerCommand runs an observation inside the selected publisher, where
// the owner credential and project runtime state live. apps mount only their
// own endpoint volumes; the host never exports the owner credential.
func composeOwnerCommand(ctx context.Context, project projectConfiguration, output io.Writer, args ...string) error {
	publisher := project.Config.Publisher
	if publisher == nil || publisher.Type != "compose" {
		return fmt.Errorf("project has no Compose publisher")
	}
	commandArgs := []string{"compose", "--project-directory", project.Root, "--project-name", project.Worktree.Label.FullLabel,
		"exec", "-T", "-e", "TNL_PUBLISHER_INTERNAL=1", "--workdir", publisher.ProjectRoot, publisher.Service,
		"tnl"}
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, "docker", commandArgs...)
	command.Dir = project.Root
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("run tnl in Compose publisher %q: %w", publisher.Service, err)
	}
	return nil
}

func selectedComposePublisher(project projectConfiguration) bool {
	return os.Getenv("TNL_PUBLISHER_INTERNAL") != "1" && project.Config.Publisher != nil && project.Config.Publisher.Type == "compose"
}

func composeWaitArgs(flags waitCommand) []string {
	args := []string{"wait", "--output", flags.Output, "--timeout", flags.Timeout.String()}
	for _, service := range flags.Service {
		args = append(args, "--service", service)
	}
	return args
}

func composeWatchArgs(flags watchCommand) []string {
	args := []string{"watch", "--output", flags.Output}
	if flags.After != "" {
		args = append(args, "--after", flags.After)
	}
	return args
}

func composeStatusArgs(flags statusCommand) []string {
	return []string{"status", "--output", string(flags.Output)}
}

func validateComposeAppVolumes(endpoints map[string]string, projectRoot, stateRoot string) error {
	for name, path := range endpoints {
		directory := filepath.Dir(path)
		if pathInside(directory, projectRoot) || pathInside(directory, stateRoot) {
			return fmt.Errorf("publisher.app_endpoints.%s must use a separate volume outside the project and owner state", name)
		}
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("publisher.app_endpoints.%s: %w", name, err)
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || owner.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("publisher.app_endpoints.%s must be a user-owned private directory (0700)", name)
		}
	}
	return nil
}
