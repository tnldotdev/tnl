package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type permissionCanceledWrite struct {
	muxsession.Stream
	header bool
	cancel atomic.Pointer[func()]
}

func (s *permissionCanceledWrite) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	if err == nil && (len(p) == 4) == s.header {
		if cancel := s.cancel.Swap(nil); cancel != nil {
			(*cancel)()
		}
	}
	return n, err
}

type permissionCanceledSession struct {
	muxsession.Session
	stream *permissionCanceledWrite
}

func (s *permissionCanceledSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	s.stream.Stream = stream
	return s.stream, nil
}

func TestConnectorPermissionVisitorCancellationDoesNotInterruptSharedFrame(t *testing.T) {
	for _, header := range []bool{true, false} {
		t.Run(map[bool]string{true: "after header", false: "after payload"}[header], func(t *testing.T) {
			client, server := newMemoryPair(t)
			tracked := &permissionCanceledWrite{header: header}
			writer, control := permissionControlPair(t, &permissionCanceledSession{Session: client, stream: tracked}, server)
			ctx, cancel := context.WithCancelCause(tunnelContext(t))
			defer cancel(nil)
			cause := errors.New("visitor finished")
			stop := func() { cancel(cause) }
			tracked.cancel.Store(&stop)
			done := tunnelWorker(t, writer.Close, func() error { return writer.Renew(ctx, connectorPermissionFixture()) })
			if _, err := tunnelv1.ReadConnectorPermissionUpdate(control); err != nil {
				t.Fatal("visitor cancellation interrupted the shared frame", err)
			}
			if err := await(t, done); !failure.Only(err, cause) {
				t.Fatal("visitor cancellation lost its exact cause", err)
			}
			if err := writer.Err(); err != nil {
				t.Fatal("one visitor canceled shared permission control", err)
			}
			// the next visitor must use the same control stream, with no retry of
			// the canceled visitor's complete frame or ambiguity in its framing.
			next := tunnelWorker(t, writer.Close, func() error { return writer.Renew(tunnelContext(t), connectorPermissionFixture()) })
			update, err := tunnelv1.ReadConnectorPermissionUpdate(control)
			if err != nil || update.UpdateNumber != 2 {
				t.Fatal("cancellation changed the next visitor's frame", update.UpdateNumber, err)
			}
			if err := tunnelv1.WriteConnectorPermissionResult(control, tunnelv1.ConnectorPermissionResult{VisitorConnectionID: update.VisitorConnectionID, UpdateNumber: update.UpdateNumber, DeliveryGeneration: update.DeliveryGeneration, Kind: tunnelv1.ConnectorPermissionAccepted}); err != nil {
				t.Fatal(err)
			}
			if err := await(t, next); err != nil {
				t.Fatal("visitor cancellation prevented sibling renewal", err)
			}
		})
	}
}

func TestConnectorPermissionVisitorStopPreservesIndependentOwnerFailure(t *testing.T) {
	client, server := newMemoryPair(t)
	tracked := &permissionCanceledWrite{}
	writer, control := permissionControlPair(t, &permissionCanceledSession{Session: client, stream: tracked}, server)
	ctx, cancel := context.WithCancelCause(tunnelContext(t))
	defer cancel(nil)
	visitorStop := errors.New("visitor finished")
	ownerFailure := errors.New("shared permission control failed")
	stop := func() {
		cancel(visitorStop)
		writer.cancel(ownerFailure)
	}
	tracked.cancel.Store(&stop)
	done := tunnelWorker(t, writer.Close, func() error { return writer.Renew(ctx, connectorPermissionFixture()) })
	if _, err := tunnelv1.ReadConnectorPermissionUpdate(control); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); !errors.Is(err, visitorStop) || !errors.Is(err, ownerFailure) {
		t.Fatal("visitor cancellation hid the independent owner failure", err)
	}
}

// an elapsed deadline is observable before the context's cancellation callback
// runs. keep Done open to exercise that ordering without scheduler luck.
type permissionDelayedDeadline struct {
	context.Context
	until time.Time
}

func (c permissionDelayedDeadline) Deadline() (time.Time, bool) { return c.until, true }

func TestConnectorPermissionQueuedDeadlineDoesNotRetireControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := newMemoryPair(t)
		writer, control := permissionControlPair(t, client, server)
		writer.gate <- struct{}{}
		ctx := permissionDelayedDeadline{Context: t.Context(), until: time.Now().Add(time.Second)}
		done := tunnelWorker(t, writer.Close, func() error { return writer.Renew(ctx, connectorPermissionFixture()) })
		synctest.Wait()
		writer.mu.Lock()
		queued := len(writer.pending)
		writer.mu.Unlock()
		if queued != 1 {
			t.Fatal("renewal did not queue behind the occupied write gate")
		}
		time.Sleep(time.Until(ctx.until))
		<-writer.gate
		if err := await(t, done); !failure.Only(err, context.DeadlineExceeded) {
			t.Fatal("queued renewal lost its expired deadline", err)
		}
		if err := writer.Err(); err != nil {
			t.Fatal("a request that wrote no frame retired shared control", err)
		}
		next := tunnelWorker(t, writer.Close, func() error { return writer.Renew(tunnelContext(t), connectorPermissionFixture()) })
		update, err := tunnelv1.ReadConnectorPermissionUpdate(control)
		if err != nil || update.UpdateNumber != 2 {
			t.Fatal("expired queued request changed sibling framing", update.UpdateNumber, err)
		}
		if err := permissionAccepted(control, update); err != nil {
			t.Fatal(err)
		}
		if err := await(t, next); err != nil {
			t.Fatal("sibling renewal could not reuse control", err)
		}
	})
}
