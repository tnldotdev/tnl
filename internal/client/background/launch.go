package background

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"golang.org/x/sys/unix"
)

const (
	startLimit = 30 * time.Second
	stopGrace  = 2 * time.Second

	bootstrapEnv = "TNL_INTERNAL_JOB_BOOTSTRAP"
	bootstrapFD  = 3
	listenerFD   = 4
	commitByte   = '+'
)

type LaunchOptions struct {
	StateDir string
	Binary   string
	Args     []string // fixed private entry point, not the public command argv
	Kind     Kind
	Payload  json.RawMessage
}

// Bootstrap carries the canonical state root and the operation's validated
// startup payload on an inherited, private channel, never in the child's argv.
type Bootstrap struct {
	JobID    string          `json:"job_id"`
	StateDir string          `json:"state_dir"`
	Kind     Kind            `json:"kind"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

type startup struct {
	Bootstrap
	Deadline time.Time `json:"deadline"`
}

type startupReply struct {
	Entry   Entry          `json:"job"`
	Failure failure.Reason `json:"failure,omitempty"`
}

// Launch starts one child in its own session. the receipt callback is
// synchronous and shares the handoff deadline; use ReceiptWriter for its
// output. a failed receipt or canceled startup stops and reaps the child.
func Launch(ctx context.Context, opts LaunchOptions, receipt func(context.Context, Entry) error) (result error) {
	ctx, finish := observability.ClientOperation(ctx, "client.background.launch")
	defer func() { finish(result) }()
	return launch(ctx, opts, startLimit, receipt)
}

func launch(ctx context.Context, opts LaunchOptions, limit time.Duration, receipt func(context.Context, Entry) error) (result error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if !opts.Kind.valid() || opts.Binary == "" || receipt == nil {
		return startFailed(errors.New("invalid background launch options"))
	}
	root, err := selectStateRoot(opts.StateDir, true)
	if err != nil {
		return err
	}
	dir, err := scopeDirectory(root, true)
	if err != nil {
		return err
	}
	id, err := opaqueid.New(opaqueid.JobPrefix)
	if err != nil {
		return startFailed(err)
	}
	reservation, listener, err := reserveSocket(dir, id)
	if err != nil {
		return startFailed(err)
	}
	handedOff := false
	defer func() {
		_ = listener.Close()
		if !handedOff {
			result = errors.Join(result, reservation.remove())
		}
	}()
	child, boot, err := startProcess(ctx, opts, listener)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return handoffError(ctx, cause)
		}
		return startFailed(err)
	}
	_ = listener.Close() // only the child's inherited listener remains
	closeOnCancel := context.AfterFunc(ctx, func() { _ = boot.Close() })
	defer func() {
		closeOnCancel()
		_ = boot.Close()
		if !handedOff {
			result = errors.Join(result, child.stopAndReap())
		}
	}()
	deadline, _ := ctx.Deadline()
	_ = boot.SetDeadline(deadline)
	spec := startup{
		Bootstrap: Bootstrap{JobID: id, StateDir: root, Kind: opts.Kind, Payload: opts.Payload},
		Deadline:  deadline,
	}
	if err := awaitReceipt(ctx, child, boot, spec, receipt); err != nil {
		return err
	}
	handedOff = true
	return nil
}

func awaitReceipt(ctx context.Context, child *childProcess, boot net.Conn, spec startup, receipt func(context.Context, Entry) error) error {
	if err := writeFrame(boot, spec); err != nil {
		return handoffError(ctx, err)
	}
	reader := frameReader(boot)
	var reply startupReply
	if err := readFrame(reader, &reply); err != nil {
		return handoffError(ctx, err)
	}
	if err := context.Cause(ctx); err != nil {
		return handoffError(ctx, err)
	}
	entry := reply.Entry
	if reason := reply.Failure; reason != "" {
		if !entry.valid(spec.JobID) || entry.Kind != spec.Kind || entry.PID != child.cmd.Process.Pid ||
			entry.State != StateStarting {
			return startFailed(errors.New("failure did not come from the launched job"))
		}
		if _, known := failure.DefinitionFor(reason); known {
			return failure.Wrap("start background job", reason, errors.New("serving operation failed before readiness"))
		}
		return startFailed(errors.New("background job failed before readiness"))
	}
	if !entry.valid(spec.JobID) || entry.Kind != spec.Kind || entry.PID != child.cmd.Process.Pid || entry.State != StateReady {
		return startFailed(errors.New("readiness did not come from the launched job"))
	}
	select {
	case <-child.done:
		return startFailed(errors.New("background job exited before handoff"))
	default:
	}
	entry.StateDir = spec.StateDir
	if err := receipt(ctx, entry); err != nil {
		return errors.Join(err, context.Cause(ctx))
	}
	if err := context.Cause(ctx); err != nil {
		return handoffError(ctx, err)
	}
	if _, err := boot.Write([]byte{commitByte}); err != nil {
		return handoffError(ctx, err)
	}
	child.commitSent = true
	if err := readCommit(reader); err != nil {
		return handoffError(ctx, err)
	}
	if err := context.Cause(ctx); err != nil {
		return handoffError(ctx, err)
	}
	return nil
}

func startFailed(err error) error {
	return failure.Wrap("start background job", failure.BackgroundStartFailed, err)
}

func handoffError(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	deadline, _ := ctx.Deadline()
	if errors.Is(context.Cause(ctx), context.DeadlineExceeded) || !deadline.IsZero() && !time.Now().Before(deadline) {
		return startFailed(errors.Join(errors.New("background job did not complete startup before the deadline"), context.DeadlineExceeded))
	}
	if errors.Is(err, io.EOF) {
		err = errors.New("background job exited before handoff")
	}
	return startFailed(err)
}

type childProcess struct {
	cmd        *exec.Cmd
	done       chan struct{}
	waitErr    error
	commitSent bool
}

func startProcess(ctx context.Context, opts LaunchOptions, listener *net.UnixListener) (*childProcess, net.Conn, error) {
	parent, inherited, err := bootstrapPair()
	if err != nil {
		return nil, nil, err
	}
	defer inherited.Close()
	socket, err := listener.File()
	if err != nil {
		parent.Close()
		return nil, nil, err
	}
	defer socket.Close()
	cmd := exec.Command(opts.Binary, opts.Args...)
	cmd.Env = append(observability.LaunchEnvironment(ctx, os.Environ()), bootstrapEnv+"=1")
	cmd.ExtraFiles = []*os.File{inherited, socket}
	// nil uses the null device directly, not pipes tied to the launcher.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := ctx.Err(); err != nil {
		parent.Close()
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		parent.Close()
		return nil, nil, err
	}
	child := &childProcess{cmd: cmd, done: make(chan struct{})}
	go func() {
		child.waitErr = cmd.Wait()
		close(child.done)
	}()
	return child, parent, nil
}

func (c *childProcess) stopAndReap() error {
	// closing the bootstrap channel cancels the pre-handoff worker. only
	// signal it if it may already have acted on the commit but the ack failed.
	select {
	case <-c.done:
		return c.waitErr
	default:
	}
	var signalErr error
	waitErr := func() error { return c.waitErr }
	if c.commitSent {
		signalErr = c.cmd.Process.Signal(syscall.SIGTERM)
		waitErr = func() error { return ignoreSignalExit(c.waitErr, syscall.SIGTERM) }
	}
	timer := time.NewTimer(stopGrace)
	defer timer.Stop()
	select {
	case <-c.done:
		return errors.Join(ignoreProcessDone(signalErr), waitErr())
	case <-timer.C:
		killErr := c.cmd.Process.Kill()
		<-c.done
		if killErr == nil {
			return errors.Join(ignoreProcessDone(signalErr), ignoreSignalExit(waitErr(), syscall.SIGKILL))
		}
		return errors.Join(ignoreProcessDone(signalErr), ignoreProcessDone(killErr), waitErr())
	}
}

func ignoreProcessDone(err error) error {
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func ignoreSignalExit(err error, signals ...syscall.Signal) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			for _, signal := range signals {
				if status.Signal() == signal {
					return nil
				}
			}
		}
	}
	return err
}

func bootstrapPair() (net.Conn, *os.File, error) {
	// Darwin does not support SOCK_CLOEXEC. prevent a concurrent exec from
	// inheriting either endpoint before we mark both close-on-exec.
	syscall.ForkLock.RLock()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(pair[0])
		syscall.CloseOnExec(pair[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, err
	}
	first := os.NewFile(uintptr(pair[0]), "job bootstrap launcher")
	defer first.Close()
	second := os.NewFile(uintptr(pair[1]), "job bootstrap child")
	conn, err := net.FileConn(first)
	if err != nil {
		second.Close()
		return nil, nil, err
	}
	return conn, second, nil
}

func readCommit(reader io.ByteReader) error {
	got, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if got != commitByte {
		return errors.New("invalid background handoff confirmation")
	}
	return nil
}
