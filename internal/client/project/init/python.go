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
func (plan Plan) PythonInstallCommand() ([]string, error) {
	if _, err := os.Stat(filepath.Join(plan.Root, "pyproject.toml")); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return []string{"uv", "add", "--editable", "./.tnl/generated/python"}, nil
}

func wirePythonProject(ctx context.Context, root string, noInstall bool) (bool, []string, error) {
	command, err := (Plan{Root: root}).PythonInstallCommand()
	if err != nil || len(command) == 0 {
		return false, nil, err
	}
	if _, err := exec.LookPath("uv"); noInstall || err != nil {
		return false, []string{"run in the Python project: " + shellCommand(command)}, nil
	}
	if err := runInitInstall(ctx, root, command); err != nil {
		return false, nil, err
	}
	return true, nil, nil
}
