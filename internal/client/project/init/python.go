package init

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// uv records an editable project-local dependency so runtime imports and type
// checkers resolve the same generated package. it never installs a global tnl.
func wirePythonProject(ctx context.Context, root string, noInstall bool) (bool, []string, error) {
	if _, err := os.Stat(filepath.Join(root, "pyproject.toml")); errors.Is(err, os.ErrNotExist) {
		return false, nil, nil
	} else if err != nil {
		return false, nil, err
	}
	command := []string{"uv", "add", "--editable", "./.tnl/generated/python"}
	if _, err := exec.LookPath("uv"); noInstall || err != nil {
		return false, []string{"run in the Python project: " + shellCommand(command)}, nil
	}
	if err := runInitInstall(ctx, root, command); err != nil {
		return false, nil, err
	}
	return true, nil, nil
}
