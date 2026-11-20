package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
)

func ClientNames(protocol string) []string {
	switch protocol {
	case "postgres":
		return []string{"pg_dump", "psql"}
	case "http":
		return []string{"curl"}
	case "tcp":
		return []string{"nc"}
	case "kubernetes":
		return []string{"kubectl"}
	}
	return nil
}

func clientArgv(p Profile, client string, args []string) ([]string, error) {
	if client == "" && len(args) > 0 {
		return args, nil
	}
	if !slices.Contains(ClientNames(string(p.Protocol)), client) || len(p.Command) < 2 {
		return nil, publisherCLIError(fmt.Sprintf("client %q does not support %s", client, p.Protocol))
	}
	var argv []string
	switch client {
	case "kubectl":
		if p.Kubeconfig == nil {
			return nil, errors.New("missing prepared Kubernetes context")
		}
		argv = []string{client, "--kubeconfig", p.Kubeconfig.File, "--context", p.Kubeconfig.Context}
	case "pg_dump":
		argv = []string{client, "--dbname", p.Command[1]}
	default:
		argv = slices.Clone(p.Command)
	}
	return append(argv, args...), nil
}

// ClientExit preserves the foreground client's status after both sides join.
type ClientExit struct{ Code int }

func (e *ClientExit) Error() string { return fmt.Sprintf("client exited with status %d", e.Code) }

func foregroundClient(parent context.Context, client string, args []string, stdin io.Reader, stdout, stderr io.Writer, serve func(context.Context, func(Profile) error) error) error {
	ctx, stop := context.WithCancelCause(parent)
	defer stop(nil)
	var once sync.Once
	var startErr, childErr error
	var child sync.WaitGroup
	childDone := errors.New("client exited")
	ready := func(p Profile) error {
		once.Do(func() {
			argv, err := clientArgv(p, client, args)
			if err != nil {
				startErr = err
				return
			}
			profile, err := json.Marshal(p)
			if err != nil {
				startErr = err
				return
			}
			cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
			cmd.Env = append(cmd.Environ(), "TNL_CONNECTION_PROFILE="+string(profile))
			cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
			wait, err := startClientProcess(cmd)
			if err != nil {
				startErr = err
				return
			}
			child.Go(func() {
				childErr = wait()
				stop(childDone)
			})
		})
		return startErr
	}
	serveErr := serve(ctx, ready)
	stop(nil)
	child.Wait()
	if context.Cause(ctx) == childDone && (failure.Only(serveErr, context.Canceled) || failure.Only(serveErr, childDone)) {
		serveErr = nil
	}
	return errors.Join(serveErr, childErr)
}

const clientStopGrace = 2 * time.Second

type clientStop struct {
	terminated, killed bool
	err                error
}

func startClientProcess(cmd *exec.Cmd) (func() error, error) {
	restore := prepareClientProcess(cmd)
	var stopped *clientStop
	cmd.Cancel = func() error {
		result := stopClientProcess(cmd.Process)
		stopped = &result
		// cmd.Wait must report the actual process status, not inject ctx.Err().
		// the connector reports its own cancellation, and we join cleanup errors.
		return os.ErrProcessDone
	}
	cmd.WaitDelay = clientStopGrace
	if err := cmd.Start(); err != nil {
		return nil, errors.Join(err, restore())
	}
	return func() error {
		err := cmd.Wait()
		// Wait joins Cmd.Cancel. if the process exited first, stop any remaining
		// workers before releasing the connector or handing the terminal back.
		if stopped == nil {
			return errors.Join(clientResult(err, clientStop{}), stopClientProcess(cmd.Process).err, restore())
		}
		return errors.Join(clientResult(err, *stopped), stopped.err, restore())
	}, nil
}

func clientResult(err error, stopped clientStop) error {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return err
	}
	if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		switch status.Signal() {
		case syscall.SIGTERM:
			if stopped.terminated {
				return nil
			}
		case syscall.SIGKILL:
			if stopped.killed {
				return nil
			}
		}
		return &ClientExit{Code: 128 + int(status.Signal())}
	}
	return &ClientExit{Code: exit.ExitCode()}
}
