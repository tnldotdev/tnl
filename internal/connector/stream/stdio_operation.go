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
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
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
	caller       context.Context
	ctx          context.Context
	cancel       context.CancelCauseFunc
	local        net.Conn
	stopParent   func() bool
	parentDone   chan struct{}
	abortDone    chan struct{}
	mu           sync.Mutex
	stopping     bool
	cause        error
	expected     bool
	selected     *stdioStream
	active       bool
	resetStarted bool
	resetOK      bool
	localClosing bool
	failures     []error
}

func newStdioOperation(caller context.Context, local net.Conn) *stdioOperation {
	life, cancel := context.WithCancelCause(context.WithoutCancel(caller))
	o := &stdioOperation{caller: caller, cancel: cancel, parentDone: make(chan struct{}), abortDone: make(chan struct{})}
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

func (o *stdioOperation) stop(cause error, caller bool) {
	o.mu.Lock()
	if o.stopping {
		o.mu.Unlock()
		return
	}
	o.stopping, o.cause, o.expected = true, cause, caller && cause == context.Canceled
	selected, active := o.selected, o.active
	o.resetStarted = active && selected != nil && selected.closeDone == nil
	o.mu.Unlock()
	if o.resetStarted {
		// only this exact stream's successful local reset may be considered an
		// ordinary abort; remote and nonzero resets retain their own causes.
		err := selected.Stream.Reset(0)
		o.mu.Lock()
		o.resetOK = err == nil
		if err != nil {
			o.failures = append(o.failures, err)
		}
		o.mu.Unlock()
	}
	o.mu.Lock()
	o.localClosing = true
	o.mu.Unlock()
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
	if !o.stopParent() {
		<-o.parentDone
	}
	o.stop(nil, false)
	<-o.abortDone
	o.cancel(o.cause)
	o.mu.Lock()
	result = errors.Join(append([]error{result}, o.failures...)...)
	expected := o.expected && (!o.resetStarted || o.resetOK)
	o.mu.Unlock()
	if expected && context.Cause(o.caller) == context.Canceled && o.abortOnly(result) {
		return nil
	}
	return result
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
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopping || stream == nil || o.selected != stream {
		return errors.Join(ErrServiceConnection, context.Cause(o.caller))
	}
	o.active = true
	return nil
}

type stdioAbortError struct {
	owner  *stdioOperation
	stream *stdioStream
	cause  error
}

func (*stdioAbortError) Error() string   { return "the selected stdio stream was aborted by its caller" }
func (e *stdioAbortError) Unwrap() error { return e.cause }

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
	owner        *stdioOperation
	foreignReset atomic.Bool
	closeDone    chan struct{}
	closeErr     error
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

func (s *stdioStream) result(err error) error {
	if stdioLocalZeroAbort(err) && !s.foreignReset.Load() {
		o := s.owner
		o.mu.Lock()
		expected := o.stopping && o.expected && o.resetStarted && o.selected == s
		o.mu.Unlock()
		if expected {
			return &stdioAbortError{owner: o, stream: s, cause: err}
		}
	}
	return err
}

func (s *stdioStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	return n, s.result(err)
}
func (s *stdioStream) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	return n, s.result(err)
}
func (s *stdioStream) CloseWrite() error { return s.result(s.Stream.CloseWrite()) }
func (s *stdioStream) Reset(code uint32) error {
	s.foreignReset.Store(true)
	return s.Stream.Reset(code)
}
func (s *stdioStream) Close() error {
	o := s.owner
	o.mu.Lock()
	if o.selected == s && o.resetStarted {
		done := o.abortDone
		o.mu.Unlock()
		<-done
		o.mu.Lock()
		if o.resetOK {
			o.mu.Unlock()
			return nil
		}
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
		case *stdioPreparedAbortError:
			if typed == nil || typed.owner != o || typed.stream != o.selected {
				return false
			}
		case *stdioLocalAbortError:
			if typed == nil || typed.owner != o || !stdioLocalClosed(typed.cause) {
				return false
			}
		case *stdioAbortError:
			if typed == nil || typed.owner != o || typed.stream != o.selected || !stdioLocalZeroAbort(typed.cause) {
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
