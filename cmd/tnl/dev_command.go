package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/diagnostic"
)

func devCommandRecursion(command []string, directory string) string {
	if len(command) == 0 {
		return ""
	}
	if filepath.Base(command[0]) == "tnl" && len(command) >= 2 && command[1] == "dev" {
		return "dev.command starts tnl dev instead of the local service"
	}
	label := packageDevCommandLabel(command)
	if label == "" {
		return ""
	}
	data, err := readInitFile(filepath.Join(directory, "package.json"))
	if err != nil {
		return ""
	}
	var project struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(data, &project) != nil || !scriptStartsTnlDev(project.Scripts["dev"]) {
		return ""
	}
	return fmt.Sprintf("dev.command runs %s, but package.json scripts.dev starts tnl dev; set dev.command to start the local service directly", label)
}

func packageDevCommandLabel(command []string) string {
	if len(command) < 2 {
		return ""
	}
	switch filepath.Base(command[0]) {
	case "pnpm", "yarn":
		if command[1] == "dev" {
			return filepath.Base(command[0]) + " dev"
		}
		if len(command) >= 3 && command[1] == "run" && command[2] == "dev" {
			return filepath.Base(command[0]) + " run dev"
		}
	case "bun":
		if command[1] == "dev" {
			return "bun dev"
		}
		if len(command) >= 3 && command[1] == "run" && command[2] == "dev" {
			return "bun run dev"
		}
	case "npm":
		if len(command) >= 3 && command[1] == "run" && command[2] == "dev" {
			return "npm run dev"
		}
	}
	return ""
}

func configuredDevCommandLabel(command []string, service string) string {
	if label := packageDevCommandLabel(command); label != "" {
		return "the configured command " + label
	}
	if service != "" {
		return "services." + service + ".dev.command"
	}
	return "dev.command"
}

func nestedDevSession(projectRoot, service string) bool {
	socket := os.Getenv("TNL_DEV_SOCKET")
	if socket == "" {
		return false
	}
	dir, err := devRuntimeDirectory()
	return err == nil && socket == filepath.Join(dir, "dev-"+devSocketDigest(projectRoot, service)+".sock")
}

func devBootstrapError(err error, projectRoot, service string, command []string) error {
	// only a child that inherited the matching socket and encountered a held lock is recursive.
	if !errors.Is(err, errDevLockHeld) || !nestedDevSession(projectRoot, service) {
		return err
	}
	detail := fmt.Sprintf("%s started another tnl dev for this project service; set dev.command to start the local service directly", configuredDevCommandLabel(command, service))
	return diagnostic.WrapMessage(diagnostic.DevCommandRecursion, detail, err)
}

func rejectNestedDevSession(projectRoot, service string, command []string) error {
	if !nestedDevSession(projectRoot, service) {
		return nil
	}
	dir, err := devRuntimeDirectory()
	if err != nil {
		return err
	}
	lock, err := acquireDevLock(filepath.Join(dir, "dev-"+devSocketDigest(projectRoot, service)+".lock"))
	if err != nil {
		return devBootstrapError(err, projectRoot, service, command)
	}
	return lock.Close()
}

func resolveDevCommand(command []string, directories ...string) ([]string, error) {
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 {
		return nil, nil
	}
	path := ""
	var err error
	if filepath.Base(command[0]) == command[0] {
		directory := ""
		if len(directories) != 0 {
			directory = directories[0]
		}
		localPath, pathErr := filepath.Abs(filepath.Join(directory, "node_modules", ".bin", command[0]))
		if pathErr == nil {
			path, err = exec.LookPath(localPath)
		}
	}
	if path == "" {
		path, err = exec.LookPath(command[0])
	}
	if err != nil {
		return nil, fmt.Errorf("find development server command %q: %w", command[0], err)
	}
	resolved := append([]string(nil), command...)
	resolved[0] = path
	return resolved, nil
}

func devEnvironment(bootstrap *devBootstrap, port int, projectPayload string) []string {
	replacements := map[string]string{
		"TNL_DEV_PROTOCOL":    devProtocolVersion,
		"TNL_DEV_SOCKET":      bootstrap.socket,
		"TNL_PROJECT_RUNTIME": projectPayload,
	}
	if port != 0 {
		replacements["TNL_DEV_PORT"] = strconv.Itoa(port)
		replacements["PORT"] = strconv.Itoa(port)
	}
	blocked := map[string]struct{}{
		"TNL_ACCESS_TOKEN": {}, "TNL_LOGIN_TOKEN": {}, "TNL_PROJECT_RUNTIME": {}, "TNL_TUNNEL_ID": {},
		"TNL_PUBLIC_HOSTNAME": {}, "TNL_PUBLIC_URL": {},
	}
	for key := range replacements {
		blocked[key] = struct{}{}
	}
	environment := make([]string, 0, len(os.Environ())+len(replacements))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, found := blocked[key]; !found && !strings.HasPrefix(key, "TNL_DEV_") {
			environment = append(environment, entry)
		}
	}
	for key, value := range replacements {
		environment = append(environment, key+"="+value)
	}
	return environment
}
