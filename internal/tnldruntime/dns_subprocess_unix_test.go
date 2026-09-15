//go:build unix

package tnldruntime

import (
	"os/exec"
	"syscall"
	"testing"
)

func isolateIntegrationDNSProcess(_ *testing.T, command *exec.Cmd) func() {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return func() {
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
	}
}
