package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

type stdioOperationKey struct{}

type stdioContext struct {
	context.Context
	caller context.Context
}

func (c stdioContext) Deadline() (time.Time, bool) { return c.caller.Deadline() }

// stdioOperation orders the caller's abort before local and stream cleanup.
// the retained connector stays alive until the selected copy has joined.
type stdioOperation struct {
	caller          context.Context
	ctx             context.Context
	cancel          context.CancelCauseFunc
	local           net.Conn
	stopParent      func() bool
	parentDone      chan struct{}
	abortDone       chan struct{}
	mu              sync.Mutex
	stopping        bool
	cause           error
	expected        bool
	selected        *stdioStream
	active          bool
	interrupted     bool
	resetStarted    bool
	resetDone       chan struct{}
	resetErr        error
	resetOK         bool
	localClosing    bool
	failures        []error
	stoppedAt       time.Time
	cleanup         *connectorCleanup
	abortTerminal   func() error
	terminalOnce    sync.Once
	terminalErr     error
	terminalStarted bool
	terminalOK      bool
}

func newStdioOperation(caller context.Context, local net.Conn) *stdioOperation {
	life, cancel := context.WithCancelCause(context.WithoutCancel(caller))
	o := &stdioOperation{caller: caller, cancel: cancel, cleanup: newConnectorCleanup(caller, nil), parentDone: make(chan struct{}), abortDone: make(chan struct{})}
	o.local = &stdioLocalConn{Conn: local, owner: o}
	o.ctx = stdioContext{Context: context.WithValue(life, stdioOperationKey{}, o), caller: caller}
	o.stopParent = context.AfterFunc(caller, func() {
		defer close(o.parentDone)
		o.stop(context.Cause(caller), true)
	})
	return o
}

func stdioOperationFor(ctx context.Context) *stdioOperation {
	o, _ := ctx.Value(stdioOperationKey{}).(*stdioOperation)
	return o
}

func (o *stdioOperation) serve(config Config) (result error) {
	defer func() { result = o.finish(result) }()
	return serveConnections(o.ctx, config, func(ctx context.Context, forward func(context.Context, net.Conn) error) error {
		defer o.complete()
		return forward(ctx, o.local)
	})
}

func (o *stdioOperation) forward(connection *connectorConnection) (result error) {
	defer func() { result = o.finish(result) }()
	defer o.complete()
	return connection.Forward(o.ctx, o.local)
}

func (o *stdioOperation) stop(cause error, caller bool) {
	o.mu.Lock()
	if o.stopping {
		o.mu.Unlock()
		return
	}
	o.stopping, o.cause, o.expected = true, cause, caller && cause == context.Canceled
	o.stoppedAt = time.Now()
	// interruption can wake a copy worker that closes local before stop returns.
	// publish ownership before either worker can observe that close.
	o.localClosing = true
	selected, active := o.selected, o.active
	o.interrupted = active && selected != nil && selected.closeDone == nil && !selected.physicalClosing
	interrupt := o.interrupted
	cleanup, stoppedAt := o.cleanup, o.stoppedAt
	o.mu.Unlock()
	if cleanup != nil && caller {
		cleanup.beginAt(stoppedAt)
		_ = cleanup.context() // capture the caller's original cleanup bound now.
	}
	if interrupt {
		// wake only local i/o. the publisher must receive authenticated Abort
		// before a stream reset can become its admission's first stop cause.
		err := selected.interrupt()
		o.mu.Lock()
		if err != nil {
			o.failures = append(o.failures, err)
		}
		o.mu.Unlock()
		if err != nil {
			// retain failed interruption even if reset must wake the workers.
			_ = o.reset()
		}
	}
	var closeErr error
	if local, ok := o.local.(*stdioLocalConn); ok {
		closeErr = local.abort(cause)
	} else {
		closeErr = o.local.Close()
	}
	o.mu.Lock()
	if closeErr != nil {
		o.failures = append(o.failures, closeErr)
	}
	o.mu.Unlock()
	close(o.abortDone)
	if !active {
		o.cancel(cause)
	}
}

func (o *stdioOperation) complete() {
	o.mu.Lock()
	o.active = false
	stopping, cause := o.stopping, o.cause
	o.mu.Unlock()
	if stopping {
		<-o.abortDone
		o.cancel(cause)
	}
}

func (o *stdioOperation) finish(result error) error {
	defer o.cleanup.close()
	if !o.stopParent() {
		<-o.parentDone
	}
	o.stop(nil, false)
	<-o.abortDone
	// forwarding has joined its authenticated terminal exchange before reset.
	_ = o.reset()
	o.cancel(o.cause)
	o.mu.Lock()
	result = errors.Join(append([]error{result, o.terminalErr, o.cause}, o.failures...)...)
	expected := o.expected && (!o.resetStarted || o.resetOK)
	o.mu.Unlock()
	if expected && context.Cause(o.caller) == context.Canceled && o.abortOnly(result) {
		return nil
	}
	return result
}

func (o *stdioOperation) bindCleanup(parent *connectorCleanup) {
	if parent == nil {
		return
	}
	parent.mu.Lock()
	authority, source := parent.authority, parent.source
	parent.mu.Unlock()
	cleanup := newConnectorCleanup(o.caller, source)
	cleanup.observe(authority)
	o.mu.Lock()
	o.cleanup = cleanup
	stoppedAt := o.stoppedAt
	o.mu.Unlock()
	if !stoppedAt.IsZero() {
		cleanup.beginAt(stoppedAt)
		_ = cleanup.context()
	}
}

func (o *stdioOperation) cleanupBound(until time.Time) time.Time {
	o.mu.Lock()
	cleanup := o.cleanup
	o.mu.Unlock()
	return cleanup.bound(until)
}

func (o *stdioOperation) reset() error {
	o.mu.Lock()
	if !o.interrupted {
		o.mu.Unlock()
		return nil
	}
	if o.resetStarted {
		done := o.resetDone
		o.mu.Unlock()
		<-done
		return o.resetErr
	}
	o.resetStarted = true
	o.resetDone = make(chan struct{})
	selected := o.selected
	o.mu.Unlock()
	err := selected.Stream.Reset(0)
	o.mu.Lock()
	o.resetErr = err
	o.resetOK = err == nil
	if err != nil {
		o.failures = append(o.failures, err)
	}
	close(o.resetDone)
	o.mu.Unlock()
	return err
}

func (o *stdioOperation) bind(stream muxsession.Stream) (*stdioStream, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopping || o.selected != nil {
		return nil, errors.Join(ErrServiceConnection, context.Cause(o.caller))
	}
	selected := &stdioStream{Stream: stream, owner: o}
	o.selected = selected
	return selected, nil
}

func (o *stdioOperation) activate(stream *stdioStream) error {
	return o.activateWithAbort(stream, nil)
}

func (o *stdioOperation) activateWithAbort(stream *stdioStream, abort func() error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopping || stream == nil || o.selected != stream {
		return errors.Join(ErrServiceConnection, context.Cause(o.caller))
	}
	o.active = true
	o.abortTerminal = abort
	return nil
}

func (o *stdioOperation) terminalUse(operation error, exchange func(error) error) error {
	// caller abort and natural EOF join one exact visitor exchange, rather than
	// issuing competing terminal numbers or turning a failed ack into success.
	o.terminalOnce.Do(func() {
		o.mu.Lock()
		abort := o.abortTerminal
		stopped := o.expected && o.interrupted && abort != nil
		o.terminalStarted = stopped
		o.mu.Unlock()
		if stopped {
			o.terminalErr = abort()
		} else {
			o.terminalErr = exchange(operation)
		}
		o.mu.Lock()
		o.terminalOK = stopped && o.terminalErr == nil
		o.mu.Unlock()
	})
	return errors.Join(operation, o.terminalErr)
}

type stdioAbortError struct {
	owner  *stdioOperation
	stream *stdioStream
	cause  error
}

func (*stdioAbortError) Error() string   { return "the selected stdio stream was aborted by its caller" }
func (e *stdioAbortError) Unwrap() error { return e.cause }

type stdioInterruptError struct {
	owner  *stdioOperation
	stream *stdioStream
	cause  error
}

func (*stdioInterruptError) Error() string {
	return "the selected stdio stream's local i/o was interrupted by its caller"
}
func (e *stdioInterruptError) Unwrap() error { return e.cause }

type stdioLocalAbortError struct {
	owner *stdioOperation
	cause error
}

func (*stdioLocalAbortError) Error() string   { return "the stdio input/output was closed by its caller" }
func (e *stdioLocalAbortError) Unwrap() error { return e.cause }

type stdioPreparedAbortError struct {
	owner  *stdioOperation
	stream *stdioStream
}

func (*stdioPreparedAbortError) Error() string {
	return "the selected stdio copy stopped after its caller's abort"
}
func (*stdioPreparedAbortError) Unwrap() error { return ErrServiceConnection }

type stdioLocalConn struct {
	net.Conn
	owner *stdioOperation
}

func (c *stdioLocalConn) abort(cause error) error {
	if aborter, ok := c.Conn.(interface{ Abort(error) error }); ok {
		return aborter.Abort(cause)
	}
	return c.Conn.Close()
}

func (c *stdioLocalConn) Close() error {
	o := c.owner
	o.mu.Lock()
	expected, cause := o.expected && o.localClosing, o.cause
	o.mu.Unlock()
	if expected {
		return c.abort(cause)
	}
	return c.Conn.Close()
}

func stdioLocalClosed(err error) bool {
	for range 16 {
		switch typed := err.(type) {
		case *net.OpError:
			if typed == nil {
				return false
			}
			err = typed.Err
		case *os.PathError:
			if typed == nil {
				return false
			}
			err = typed.Err
		case *os.SyscallError:
			if typed == nil {
				return false
			}
			err = typed.Err
		default:
			return err == net.ErrClosed || err == os.ErrClosed || err == io.ErrClosedPipe
		}
	}
	return false
}

func (c *stdioLocalConn) result(err error, output bool) error {
	if !stdioLocalClosed(err) {
		return err
	}
	o := c.owner
	o.mu.Lock()
	expected := o.expected && o.localClosing
	o.mu.Unlock()
	if output {
		owner, ok := c.Conn.(interface{ OwnsAbortError(error) bool })
		expected = expected && ok && owner.OwnsAbortError(err)
	}
	if expected {
		return &stdioLocalAbortError{owner: o, cause: err}
	}
	return err
}

func (c *stdioLocalConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	return n, c.result(err, false)
}
func (c *stdioLocalConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	return n, c.result(err, true)
}
func (c *stdioLocalConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return c.result(writer.CloseWrite(), true)
	}
	return errors.ErrUnsupported
}

type stdioStream struct {
	muxsession.Stream
	owner            *stdioOperation
	foreignReset     atomic.Bool
	closeDone        chan struct{}
	closeErr         error
	readDeadline     time.Time
	writeDeadline    time.Time
	interruptAt      time.Time
	readInterrupted  bool
	writeInterrupted bool
	physicalClosing  bool
	released         bool
}

func (s *stdioStream) interrupt() error {
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	at := time.Now()
	s.interruptAt = at
	readErr := s.Stream.SetReadDeadline(at)
	writeErr := s.Stream.SetWriteDeadline(at)
	s.readInterrupted = readErr == nil && (s.readDeadline.IsZero() || s.readDeadline.After(at))
	s.writeInterrupted = writeErr == nil && (s.writeDeadline.IsZero() || s.writeDeadline.After(at))
	return errors.Join(readErr, writeErr)
}

// exact deadline leaves, not arbitrary Timeout or Is implementations, identify
// the transport's local deadline. an earlier deadline is never owned by stop.
func stdioDeadlineOnly(err error) bool {
	for range 16 {
		switch err {
		case os.ErrDeadlineExceeded, yamux.ErrTimeout:
			return true
		case nil:
			return false
		}
		switch typed := err.(type) {
		case *CleanupError, *tunnel.SessionCleanupError, *muxsession.QUICTransportCloseError, *failure.Error:
			return false
		case interface{ Unwrap() error }:
			err = typed.Unwrap()
		default:
			return false
		}
	}
	return false
}

func (s *stdioStream) ioResult(err error, read bool) error {
	completed := time.Now()
	if stdioDeadlineOnly(err) && !s.foreignReset.Load() {
		o := s.owner
		o.mu.Lock()
		owned := s.writeInterrupted
		if read {
			owned = s.readInterrupted
		}
		expected := owned && o.expected && o.interrupted && o.selected == s && !s.interruptAt.After(completed)
		o.mu.Unlock()
		if expected {
			return &stdioInterruptError{owner: o, stream: s, cause: err}
		}
	}
	return s.result(err)
}

func stdioLocalZeroAbort(err error) bool {
	switch typed := err.(type) {
	case *quic.StreamError:
		return typed != nil && !typed.Remote && typed.ErrorCode == 0
	case *yamux.StreamError:
		return typed != nil && !typed.Remote && typed.ErrorCode == 0
	}
	return false
}

func stdioRemoteZeroAbort(err error) bool {
	switch typed := err.(type) {
	case *quic.StreamError:
		return typed != nil && typed.Remote && typed.ErrorCode == 0
	case *yamux.StreamError:
		return typed != nil && typed.Remote && typed.ErrorCode == 0
	}
	return false
}

func (o *stdioOperation) ownsStreamAbortLocked(cause error) bool {
	return stdioLocalZeroAbort(cause) || o.terminalStarted && o.terminalOK && stdioRemoteZeroAbort(cause)
}

func (s *stdioStream) result(err error) error {
	if (stdioLocalZeroAbort(err) || stdioRemoteZeroAbort(err)) && !s.foreignReset.Load() {
		o := s.owner
		o.mu.Lock()
		expected := o.stopping && o.expected && o.resetStarted && o.selected == s &&
			(stdioLocalZeroAbort(err) || o.terminalStarted && stdioRemoteZeroAbort(err))
		o.mu.Unlock()
		if expected {
			return &stdioAbortError{owner: o, stream: s, cause: err}
		}
	}
	return err
}

func (s *stdioStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	return n, s.ioResult(err, true)
}
func (s *stdioStream) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	return n, s.ioResult(err, false)
}
func (s *stdioStream) CloseWrite() error { return s.result(s.Stream.CloseWrite()) }
func (s *stdioStream) SetDeadline(at time.Time) error {
	return errors.Join(s.SetReadDeadline(at), s.SetWriteDeadline(at))
}
func (s *stdioStream) SetReadDeadline(at time.Time) error {
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	s.readInterrupted = false
	s.readDeadline = at
	return s.Stream.SetReadDeadline(at)
}
func (s *stdioStream) SetWriteDeadline(at time.Time) error {
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	s.writeInterrupted = false
	s.writeDeadline = at
	return s.Stream.SetWriteDeadline(at)
}
func (s *stdioStream) Reset(code uint32) error {
	s.foreignReset.Store(true)
	return s.Stream.Reset(code)
}
func (s *stdioStream) Close() error {
	o := s.owner
	o.mu.Lock()
	if o.selected == s && o.interrupted {
		released := s.released
		o.mu.Unlock()
		if released {
			return o.reset()
		}
		return nil
	}
	if s.closeDone != nil {
		done := s.closeDone
		o.mu.Unlock()
		<-done
		return s.closeErr
	}
	s.closeDone = make(chan struct{})
	o.mu.Unlock()
	err := s.result(s.Stream.Close())
	o.mu.Lock()
	s.closeErr = err
	close(s.closeDone)
	o.mu.Unlock()
	return err
}

// tls may send its close alert after this exact stdio stream was reset. only
// wrappers around that owned write result belong to the successful local reset;
// joined failures, foreign resets and unrelated close results remain failures.
func (s *stdioStream) tlsCloseResult(err error) error {
	o := s.owner
	o.mu.Lock()
	expected := o.expected && o.resetStarted && o.resetOK && o.selected == s
	o.mu.Unlock()
	if !expected {
		return err
	}
	cause := err
	for range 16 {
		switch typed := cause.(type) {
		case *stdioAbortError:
			o.mu.Lock()
			owned := typed != nil && typed.owner == o && typed.stream == s && o.ownsStreamAbortLocked(typed.cause)
			o.mu.Unlock()
			if owned {
				return nil
			}
			return err
		case interface{ Unwrap() error }:
			cause = typed.Unwrap()
		default:
			return err
		}
	}
	return err
}

// abortOnly inspects every leaf without invoking custom Is methods. errors
// from another stream, an output writer, permission, or cleanup are not aborts.
func (o *stdioOperation) abortOnly(err error) bool {
	if err == nil {
		return true
	}
	pending := []error{err}
	for checked := 0; len(pending) != 0; checked++ {
		if checked == 64 {
			return false
		}
		cause := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		switch cause {
		case context.Canceled:
			continue
		case nil:
			return false
		}
		switch typed := cause.(type) {
		case *CleanupError, *tunnel.SessionCleanupError, *muxsession.QUICTransportCloseError, *failure.Error:
			return false
		case *stdioPreparedAbortError:
			if typed == nil || typed.owner != o || typed.stream != o.selected {
				return false
			}
		case *stdioLocalAbortError:
			if typed == nil || typed.owner != o || !stdioLocalClosed(typed.cause) {
				return false
			}
		case *stdioAbortError:
			o.mu.Lock()
			owned := typed != nil && typed.owner == o && typed.stream == o.selected && o.ownsStreamAbortLocked(typed.cause)
			o.mu.Unlock()
			if !owned {
				return false
			}
		case *stdioInterruptError:
			if typed == nil || typed.owner != o || typed.stream != o.selected || !stdioDeadlineOnly(typed.cause) {
				return false
			}
		case *net.OpError:
			if typed == nil || typed.Err == nil {
				return false
			}
			pending = append(pending, typed.Err)
		case *os.PathError:
			if typed == nil || typed.Err == nil {
				return false
			}
			pending = append(pending, typed.Err)
		case *os.SyscallError:
			if typed == nil || typed.Err == nil {
				return false
			}
			pending = append(pending, typed.Err)
		case interface{ Unwrap() []error }:
			children := typed.Unwrap()
			if len(children) == 0 || len(children)+len(pending) > 64 {
				return false
			}
			pending = append(pending, children...)
		case interface{ Unwrap() error }:
			child := typed.Unwrap()
			if child == nil {
				return false
			}
			pending = append(pending, child)
		default:
			return false
		}
	}
	return true
}
