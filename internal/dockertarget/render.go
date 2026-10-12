package dockertarget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
)

// ComposeServiceDeclared checks a service before an app container has started.
// its publisher endpoint can be exported without guessing a container name.
func ComposeServiceDeclared(ctx context.Context, root, project, file, service string) error {
	if !filepath.IsAbs(root) || project == "" || service == "" {
		return errors.New("compose project and service are required")
	}
	selected, err := composeFile(root, file)
	if err != nil {
		return err
	}
	data, err := dockerCommand(ctx, root, 512<<10, "compose", "--project-directory", root, "--file", selected,
		"--project-name", project, "config", "--format", "json")
	if err != nil {
		return fmt.Errorf("render selected Compose file: %w", err)
	}
	var rendered struct {
		Services map[string]struct {
			ContainerName string `json:"container_name"`
		} `json:"services"`
	}
	if err := json.Unmarshal(data, &rendered); err != nil {
		return fmt.Errorf("decode rendered Compose file: %w", err)
	}
	definition, found := rendered.Services[service]
	if !found {
		return fmt.Errorf("compose service %q is not declared in %s", service, file)
	}
	if definition.ContainerName != "" {
		return errors.New("compose service has a fixed container_name; remove it to isolate worktrees")
	}
	return nil
}
