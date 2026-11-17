//go:build !unix

package daemon

import (
	"os/exec"
	"testing"
)

func isolateIntegrationCommand(t *testing.T, _ *exec.Cmd) func() {
	t.Helper()
	t.Fatal("runtime integration requires Unix process-group isolation")
	return func() {}
}
