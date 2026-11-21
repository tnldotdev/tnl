//go:build darwin || linux

package connector

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var clientTerminalRestore sync.Mutex

func prepareClientProcess(cmd *exec.Cmd) func() error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	owner := unix.Getpgrp()
	for _, stream := range []any{cmd.Stdin, cmd.Stdout, cmd.Stderr} {
		file, ok := stream.(*os.File)
		if !ok {
			continue
		}
		fd := int(file.Fd())
		group, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		if err != nil || group != owner {
			continue
		}
		// the child takes the foreground before exec, so interactive clients
		// can read the original terminal and receive its input signals.
		cmd.SysProcAttr.Foreground, cmd.SysProcAttr.Ctty = true, fd
		return func() error {
			if group, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP); err == nil && group == owner {
				return nil
			}
			clientTerminalRestore.Lock()
			defer clientTerminalRestore.Unlock()
			// the OS otherwise stops a background process reclaiming its tty.
			if !signal.Ignored(syscall.SIGTTOU) {
				signal.Ignore(syscall.SIGTTOU)
				defer signal.Reset(syscall.SIGTTOU)
			}
			if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, owner); err != nil && !errors.Is(err, unix.ENOTTY) {
				return fmt.Errorf("restore client terminal: %w", err)
			}
			return nil
		}
	}
	return func() error { return nil }
}

func stopClientProcess(process *os.Process) clientStop {
	group := -process.Pid
	if err := unix.Kill(group, unix.SIGTERM); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return clientStop{}
		}
		return clientStop{err: fmt.Errorf("terminate client process group: %w", err)}
	}
	result := clientStop{terminated: true}
	deadline := time.NewTimer(clientStopGrace)
	defer deadline.Stop()
	probe := time.NewTicker(20 * time.Millisecond)
	defer probe.Stop()
	for {
		select {
		case <-probe.C:
			if errors.Is(unix.Kill(group, 0), unix.ESRCH) {
				return result
			}
		case <-deadline.C:
			err := unix.Kill(group, unix.SIGKILL)
			if err == nil {
				result.killed = true
			} else if !errors.Is(err, unix.ESRCH) {
				result.err = fmt.Errorf("kill client process group: %w", err)
			}
			return result
		}
	}
}
