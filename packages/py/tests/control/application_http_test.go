package control_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/applicationhttp"
)

func TestIntegrationApplicationHTTPPythonAgainstControl(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "application_python_http")
	applicationhttp.Qualify(t, databaseURL, func(input applicationhttp.Inputs, mode string) {
		t.Helper()
		python := filepath.Join(input.Directory, "packages/py/.venv/bin/python")
		command := exec.CommandContext(t.Context(), python, "packages/py/tests/application_http_control.py", input.CredentialFile, input.ResourceID, input.Origin, mode, input.CAFile)
		command.Dir = input.Directory
		command.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(input.Directory, "packages/py/src"))
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("Python SDK authority check %s: %v\n%s", mode, err, output)
		}
	})
}
