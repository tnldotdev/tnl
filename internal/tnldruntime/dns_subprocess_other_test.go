//go:build !unix

package tnldruntime

import (
	"os/exec"
	"testing"
)

func isolateIntegrationDNSProcess(t *testing.T, _ *exec.Cmd) func() {
	t.Helper()
	t.Fatal("runtime DNS integration requires Unix process-group isolation")
	return func() {}
}
