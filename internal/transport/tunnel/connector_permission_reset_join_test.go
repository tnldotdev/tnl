package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

type permissionResetOutcome struct {
	*heldPermissionReset
	resets atomic.Int32
	err    error
}

func (s *permissionResetOutcome) Reset(code uint32) error {
	s.resets.Add(1)
	return errors.Join(s.heldPermissionReset.Reset(code), s.err)
}

func TestConnectorPermissionReaderFinishAlwaysResetsAndJoins(t *testing.T) {
	for _, started := range []bool{false, true} {
		for _, failedReset := range []bool{false, true} {
			name := map[bool]string{false: "callback queued", true: "callback running"}[started] +
				map[bool]string{false: "/clean", true: "/failed reset"}[failedReset]
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					budget, finish := context.WithTimeout(t.Context(), 5*time.Second)
					defer finish()
					ctx, cancel := context.WithCancelCause(budget)
					defer cancel(nil)
					local, remote := net.Pipe()
					defer local.Close()
					defer remote.Close()
					held := &heldPermissionReset{Stream: &memoryStream{Conn: local},
						entered: make(chan struct{}), release: make(chan struct{})}
					release := sync.OnceFunc(func() { close(held.release) })
					defer release()
					physical := errors.New("independent permission reset failure")
					stream := &permissionResetOutcome{heldPermissionReset: held}
					if failedReset {
						stream.err = &muxsession.QUICTransportCloseError{Err: errors.Join(context.Canceled, physical)}
					}
					writer := &ConnectorPermissionWriter{stream: stream, ctx: ctx, cancel: cancel, done: make(chan struct{})}
					reset := writer.resetControl
					joined := make(chan struct{})
					var workers sync.WaitGroup
					defer func() { release(); workers.Wait() }()
					if started {
						workers.Go(func() { defer close(joined); reset() })
						await(t, held.entered)
					}
					cancel(context.Canceled)
					stopCalls := 0
					// model the two exact AfterFunc schedules at the real finish
					// boundary. true cancels a queued callback before its body ran;
					// false means the callback owns its running join.
					stopEntered := make(chan struct{})
					stop := func() bool { stopCalls++; close(stopEntered); return !started }
					result := make(chan struct{})
					workers.Go(func() { writer.finishReceive(reset, stop, joined); close(result) })
					await(t, stopEntered)
					select {
					case <-held.entered:
					case <-writer.done:
						t.Error("reader finish canceled its queued callback without running physical reset")
						return
					case <-budget.Done():
						t.Fatal("physical reset did not enter within its original budget")
					}
					select {
					case <-writer.done:
						t.Error("reader finish preceded its held physical reset return")
					default:
					}
					release()
					await(t, result)
					err := writer.Close()
					if stream.resets.Load() != 1 || stopCalls != 1 {
						t.Error("reader and callback did not share one physical closing owner", stream.resets.Load(), stopCalls)
					}
					if !failedReset && err != nil {
						t.Error("clean joined reset became a failure", err)
					}
					if failedReset {
						var failure *ConnectorControlFailure
						if !errors.Is(err, stream.err) || !errors.Is(err, physical) || !errors.As(err, &failure) ||
							failure.Origin != ConnectorControlOwnerStop {
							t.Error("reader finish lost independent physical reset failure or origin", err)
						}
					}
				})
			})
		}
	}
}
