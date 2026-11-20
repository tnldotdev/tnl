//go:build !darwin && !linux

package connector

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func prepareClientProcess(*exec.Cmd) func() error { return func() error { return nil } }

func stopClientProcess(process *os.Process) clientStop {
	err := process.Signal(syscall.SIGTERM)
	if errors.Is(err, os.ErrProcessDone) {
		return clientStop{}
	}
	return clientStop{terminated: err == nil, err: err}
}
