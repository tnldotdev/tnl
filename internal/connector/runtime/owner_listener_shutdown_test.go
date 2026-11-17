package runtime

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type shutdownOwnerListener struct {
	net.Listener
	accepting     chan struct{}
	acceptStopped chan struct{}
	acceptRelease chan struct{}
	closeFailure  error
	closes        atomic.Int32
}

func (l *shutdownOwnerListener) Accept() (net.Conn, error) {
	close(l.accepting)
	conn, err := l.Listener.Accept()
	if err != nil {
		// keep Serve registered with http.Server after the raw listener closes,
		// so Shutdown must join that exact accept instead of winning a race.
		close(l.acceptStopped)
		<-l.acceptRelease
	}
	return conn, err
}

func (l *shutdownOwnerListener) Close() error {
	l.closes.Add(1)
	return errors.Join(l.Listener.Close(), l.closeFailure)
}

type listenerShutdownBackend struct {
	fixtureBackend
	closing chan context.Context
	release chan struct{}
	failure error
}

func (b *listenerShutdownBackend) Close(ctx context.Context) error {
	b.closing <- ctx
	<-b.release
	b.closed.Store(true)
	return errors.Join(b.failure, context.Cause(ctx))
}

func TestConnectionOwnerListenerShutdown(t *testing.T) {
	closeFailure := errors.New("independent raw listener close failure")
	backendFailure := errors.New("independent backend cleanup failure")
	operationFailure := errors.New("independent owner operation failure")
	for _, test := range []struct {
		name         string
		close        error
		backend      error
		operation    error
		spent        bool
		acceptJoined bool
	}{
		{name: "clean"},
		{name: "raw-close", close: closeFailure},
		{name: "raw-closed", close: net.ErrClosed},
		{name: "raw-joined-close", close: errors.Join(net.ErrClosed, closeFailure)},
		{name: "raw-close-after-accept", close: closeFailure, acceptJoined: true},
		{name: "raw-closed-after-accept", close: net.ErrClosed, acceptJoined: true},
		{name: "mixed", close: closeFailure, backend: backendFailure, operation: operationFailure},
		{name: "spent", spent: true},
		{name: "spent-mixed", close: closeFailure, backend: backendFailure, operation: operationFailure, spent: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				scope := fixtureScope(t)
				directory, err := NewDirectory(scope.Directory)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				listener := &shutdownOwnerListener{Listener: raw, accepting: make(chan struct{}), acceptStopped: make(chan struct{}),
					acceptRelease: make(chan struct{}), closeFailure: test.close}
				backend := &listenerShutdownBackend{fixtureBackend: fixtureBackend{deadline: time.Now().Add(time.Hour)},
					closing: make(chan context.Context, 1), release: make(chan struct{}), failure: test.backend}
				until := time.Now().Add(5 * time.Second)
				ctx, cancel := context.WithCancel(t.Context())
				operation := make(chan error, 1)
				done, finished := make(chan error, 1), make(chan struct{})
				releaseBackend := sync.OnceFunc(func() { close(backend.release) })
				releaseAccept := sync.OnceFunc(func() { close(listener.acceptRelease) })
				defer func() {
					cancel()
					releaseBackend()
					releaseAccept()
					<-finished
				}()
				go func() {
					defer close(finished)
					done <- serveOwner(ctx, scope, directory, "/test/tnl", OwnerConfig{Backend: backend, Done: operation,
						ShutdownDeadline: func() time.Time { return until }}, io.Discard,
						func(network, address string) (net.Listener, error) {
							if network != "tcp4" || address != "127.0.0.1:0" {
								t.Error("owner changed its private loopback listener", network, address)
							}
							return listener, nil
						})
				}()
				<-listener.accepting
				if test.operation != nil {
					operation <- test.operation
				} else {
					cancel()
				}
				<-listener.acceptStopped
				cleanup := <-backend.closing
				if got, _ := cleanup.Deadline(); !got.Equal(until) {
					t.Error("listener shutdown replaced the original backend cleanup deadline", got, until)
				}
				if test.spent {
					<-cleanup.Done()
				}
				synctest.Wait()
				select {
				case result := <-done:
					t.Fatal("owner returned before backend cleanup joined", result)
				default:
				}
				if test.acceptJoined {
					releaseAccept()
					synctest.Wait()
				}
				releaseBackend()
				synctest.Wait()
				if !test.acceptJoined {
					select {
					case result := <-done:
						t.Fatal("owner returned before the registered accept joined", result)
					default:
					}
				}
				if got := listener.closes.Load(); got != 1 {
					t.Error("runtime and HTTP server closed the same raw listener more than once", got)
				}
				releaseAccept()
				result := <-done
				if !backend.closed.Load() {
					t.Error("owner did not join backend cleanup")
				}
				for _, cause := range []error{test.close, test.backend, test.operation} {
					if cause != nil && !errors.Is(result, cause) {
						t.Error("owner discarded an independent failure", cause, result)
					}
				}
				if test.spent && !errors.Is(result, context.DeadlineExceeded) {
					t.Error("owner discarded the original cleanup expiry", result)
				}
				if test.close == nil && test.backend == nil && test.operation == nil && !test.spent && result != nil {
					t.Error("clean joined shutdown manufactured a failure", result)
				}
				if got := listener.closes.Load(); got != 1 {
					t.Error("final cleanup closed the raw listener again after joining", got)
				}
			})
		})
	}
}
