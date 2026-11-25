package init

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// uv records an editable project-local dependency so runtime imports and type
// checkers resolve the same generated package. it never installs a global tnl.
func (plan Plan) PythonInstall(noInstall bool) (Install, error) {
	if _, err := os.Stat(filepath.Join(plan.Root, "pyproject.toml")); errors.Is(err, os.ErrNotExist) {
		return Install{}, nil
	} else if err != nil {
		return Install{}, err
	}
	args := []string{"uv", "add", "--editable", "./.tnl/generated/python"}
	_, err := exec.LookPath(args[0])
	return Install{Command: shellCommand(args), Manual: noInstall || err != nil, args: args, manualArgs: args}, nil
}
