package background

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// RunChild serves one private bootstrap invocation. run must join its work
// before returning, whether it stops by request or process cancellation.
func RunChild(ctx context.Context, run func(context.Context, Bootstrap) error) (result error) {
	if os.Getenv(bootstrapEnv) != "1" {
		return errors.New("background jobs must be started by the launcher")
	}
	_ = os.Unsetenv(bootstrapEnv)
	syscall.CloseOnExec(bootstrapFD)
	syscall.CloseOnExec(listenerFD)
	channel := os.NewFile(bootstrapFD, "job bootstrap")
	boot, err := net.FileConn(channel)
	_ = channel.Close()
	if err != nil {
		_ = syscall.Close(listenerFD)
		return err
	}
	defer boot.Close()
	stopClosing := context.AfterFunc(ctx, func() { _ = boot.Close() })
	defer stopClosing()
	socket := os.NewFile(listenerFD, "job control listener")
	listener, err := net.FileListener(socket)
	_ = socket.Close()
	if err != nil {
		return err
	}
	defer listener.Close()
	if _, ok := boot.(*net.UnixConn); !ok {
		return errors.New("invalid background bootstrap channel")
	}

	deadline := time.Now().Add(startLimit)
	_ = boot.SetDeadline(deadline)
	reader := frameReader(boot)
	var spec startup
	if err := readFrame(reader, &spec); err != nil {
		return err
	}
	if !opaqueid.Valid(spec.JobID, opaqueid.JobPrefix) || !spec.Kind.valid() || spec.StateDir == "" || spec.Deadline.IsZero() {
		return errors.New("invalid background startup facts")
	}
	if spec.Deadline.Before(deadline) {
		_ = boot.SetDeadline(spec.Deadline)
	}
	scope, err := scopeDirectory(spec.StateDir, false)
	if err != nil {
		return err
	}
	dir, path := jobPaths(scope, spec.JobID)
	if listener.Addr().Network() != "unix" || listener.Addr().String() != path {
		return errors.New("background job has the wrong control listener")
	}
	if err := privateDirectory(dir, false); err != nil {
		return err
	}
	if err := privateSocket(path); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	reservation := socketReservation{dir: dir, path: path, info: info}
	defer func() { result = errors.Join(result, reservation.remove()) }()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	control := &jobControl{
		entry:  Entry{JobID: spec.JobID, Kind: spec.Kind, State: StateStarting, PID: os.Getpid()},
		runCtx: runCtx, cancel: cancel, boot: boot, joined: make(chan struct{}),
	}
	bootDone := make(chan struct{})
	go func() {
		defer close(bootDone)
		defer boot.Close()
		if readCommit(reader) != nil || !control.commit() {
			cancel()
			return
		}
		if _, err := boot.Write([]byte{commitByte}); err != nil {
			cancel()
		}
	}()
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		control.serve(listener)
	}()
	defer func() {
		close(control.joined)
		_ = listener.Close()
		_ = boot.Close()
		<-bootDone
		<-controlDone
	}()
	result = run(context.WithValue(runCtx, controlKey{}, control), spec.Bootstrap)
	control.mu.Lock()
	if !control.ready && runCtx.Err() == nil && result != nil {
		reason, known := failure.ReasonOf(result)
		if !known {
			reason = failure.BackgroundStartFailed
		}
		// never pass error strings, configuration values, or arguments.
		_ = writeFrame(boot, startupReply{Entry: control.entry, Failure: reason})
	}
	control.mu.Unlock()
	return result
}

func (c *jobControl) commit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ready || c.handoffLost || c.runCtx.Err() != nil || c.entry.State != StateStarting {
		return false
	}
	c.entry.State = StateReady
	return true
}
