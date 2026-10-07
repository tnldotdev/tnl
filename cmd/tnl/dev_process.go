package main

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
)

type devProcess struct {
	command *exec.Cmd
	done    chan struct{}
	stop    chan time.Duration
	err     error

	stopOnce   sync.Once
	cleanupErr error
}

func startDevProcess(command, environment []string, stdin io.Reader, stdout, stderr io.Writer, directories ...string) (*devProcess, error) {
	process := &devProcess{done: make(chan struct{}), stop: make(chan time.Duration, 1)}
	if len(command) == 0 {
		return process, nil
	}
	process.command = exec.Command(command[0], command[1:]...)
	if len(directories) != 0 {
		process.command.Dir = directories[0]
	}
	process.command.Env = environment
	process.command.Stdin = stdin
	process.command.Stdout = stdout
	process.command.Stderr = stderr
	process.command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := process.command.Start(); err != nil {
		return nil, failure.Wrap("start development server command", failure.DevProcessFailed, err)
	}
	processGroupID := process.command.Process.Pid
	leaderExited, watcherErr := watchDevProcessExit(processGroupID)
	go process.run(processGroupID, leaderExited, watcherErr)
	if watcherErr != nil {
		<-process.done
		return nil, process.cleanupErr
	}
	return process, nil
}

func (p *devProcess) Done() <-chan struct{} { return p.done }

func (p *devProcess) Err() error {
	<-p.done
	return p.err
}

func (p *devProcess) run(processGroupID int, leaderExited <-chan error, watcherSetupErr error) {
	var watcherFailure, signalFailure error
	if watcherSetupErr != nil {
		watcherFailure = fmt.Errorf("watch development server command: %w", watcherSetupErr)
		signalFailure = signalDevProcessGroup(processGroupID, syscall.SIGKILL)
	} else {
		select {
		case watcherErr := <-leaderExited:
			watcherFailure = devProcessWatcherError(watcherErr)
			signalFailure = signalDevProcessGroup(processGroupID, syscall.SIGKILL)
		case timeout := <-p.stop:
			signalFailure = signalDevProcessGroup(processGroupID, syscall.SIGTERM)
			timer := time.NewTimer(timeout)
			select {
			case watcherErr := <-leaderExited:
				if !timer.Stop() {
					<-timer.C
				}
				watcherFailure = devProcessWatcherError(watcherErr)
				signalFailure = errors.Join(signalFailure, signalDevProcessGroup(processGroupID, syscall.SIGKILL))
			case <-timer.C:
				signalFailure = errors.Join(signalFailure, signalDevProcessGroup(processGroupID, syscall.SIGKILL))
			}
		}
	}
	p.err = p.command.Wait()
	// on macOS a group containing only its unreaped leader can report EPERM
	// instead of ESRCH. retry after Wait reaps the leader; persistent EPERM
	// still reports a real failure to stop the remaining group members.
	if errors.Is(signalFailure, syscall.EPERM) {
		signalFailure = signalDevProcessGroup(processGroupID, syscall.SIGKILL)
	}
	p.cleanupErr = errors.Join(watcherFailure, signalFailure)
	close(p.done)
}

func devProcessWatcherError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("watch development server command: %w", err)
}

func signalDevProcessGroup(processGroupID int, signal syscall.Signal) error {
	err := syscall.Kill(-processGroupID, signal)
	if err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return fmt.Errorf("send %s to development server process group: %w", signal, err)
}

func (p *devProcess) Stop(timeout time.Duration) error {
	if p == nil || p.command == nil || p.command.Process == nil {
		return nil
	}
	p.stopOnce.Do(func() {
		p.stop <- timeout
	})
	<-p.done
	return p.cleanupErr
}

func childResult(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		if code < 1 || code > 255 {
			code = 1
		}
		return &childExitError{code: code}
	}
	return failure.Wrap("wait for development server command", failure.DevProcessFailed, err)
}
