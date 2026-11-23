package stream

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func deadlinePreparedFixture(t *testing.T, until time.Time) (*PreparedConnector, net.Conn) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	left, right := net.Pipe()
	p := &PreparedConnector{ctx: ctx, conn: left, stream: streamPrepared{}, permission: permissionUsable{}, permissionUntil: until, callbackDone: make(chan struct{})}
	p.stop = context.AfterFunc(ctx, func() { defer close(p.callbackDone); _ = p.closePhysical() })
	p.mu.Lock()
	p.startPermissionWorkerLocked()
	p.mu.Unlock()
	t.Cleanup(func() { cancel(); _ = p.Close(); _ = right.Close() })
	return p, right
}

func TestPreparedConnectorPermissionExpiryClosesBlockedReadAndWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, _ := deadlinePreparedFixture(t, time.Now().Add(time.Second))
		if err := p.suspendPermission(); err != nil {
			t.Fatal(err)
		}
		use := &preparedConnectorUse{owner: p, ctx: p.ctx}
		read, write := make(chan error, 1), make(chan error, 1)
		go func() { _, err := use.Read(make([]byte, 1)); read <- err }()
		go func() { _, err := use.Write([]byte("fenced")); write <- err }()
		time.Sleep(time.Second)
		synctest.Wait()
		if err := <-read; err == nil {
			t.Fatal("expired permission returned application bytes")
		}
		if err := <-write; err == nil {
			t.Fatal("expired permission released a waiting write")
		}
		if err := p.renewPermission(p.ctx, permissionDecision(func() error { return nil })); err == nil {
			t.Fatal("late ACK revived an expired prepared stream")
		}
	})
}

func TestPreparedConnectorStalePermissionCannotBorrowNewExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		until := time.Now().Add(time.Second)
		p, _ := deadlinePreparedFixture(t, until)
		if err := p.renewPermission(p.ctx, permissionDecision(func() error { return tunnel.ErrConnectorPermissionStale })); !errors.Is(err, tunnel.ErrConnectorPermissionStale) {
			t.Fatal(err)
		}
		p.mu.Lock()
		_, queued := p.permission.(permissionQueued)
		fenced := queued && p.permissionUntil.Equal(until)
		p.mu.Unlock()
		if !fenced {
			t.Fatal("stale reply released or renewed an application permission")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if err := p.waitPermission(p.ctx); err == nil {
			t.Fatal("stale reply retained writes after the original expiry")
		}
	})
}

func TestPreparedRepeatedPermissionNeedsNoSecondAcknowledgment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		p, remote := deadlinePreparedFixture(t, now.Add(time.Minute))
		calls := 0
		var wantDeadline time.Time
		push := func(generation int64, token string, until time.Time, want int) {
			t.Helper()
			err := p.queuePermission(preparedPermissionRenewal{
				update: tunnelv1.ConnectorPermissionUpdate{VisitorConnectionID: "visitor", DeliveryGeneration: generation,
					Permission: tunnelv1.ConnectorVisitorPermission{Token: token}},
				until: until, writer: preparedRenewalFunc(func(ctx context.Context, _ tunnelv1.ConnectorPermissionUpdate) error {
					calls++
					if deadline, _ := ctx.Deadline(); !wantDeadline.IsZero() && !deadline.Equal(wantDeadline) {
						t.Error("new proof borrowed time past the shortened fence", deadline)
					}
					return nil
				}),
			})
			synctest.Wait()
			if err != nil || calls != want {
				t.Fatalf("queue: err=%v, publisher exchanges=%d, want %d", err, calls, want)
			}
		}
		until := now.Add(time.Minute)
		push(1, "first", until, 1)
		push(1, "first", until, 1)
		push(1, "first", until.Add(time.Second), 2)
		push(1, "second", until, 3)
		push(2, "second", until, 4)
		if err := p.suspendPermission(); err != nil {
			t.Fatal(err)
		}
		push(2, "second", until, 5)
		short := now.Add(2 * time.Second)
		push(2, "second", short, 5)
		wantDeadline = short
		push(2, "third", until, 6)
		push(2, "third", now.Add(time.Second), 6)
		time.Sleep(time.Second)
		synctest.Wait()
		p.mu.Lock()
		closed := p.closedLocked()
		p.mu.Unlock()
		if !closed {
			t.Fatal("permission worker did not wake at the shortened deadline")
		}
		if _, err := remote.Read(make([]byte, 1)); err == nil || !errors.Is(p.Close(), context.DeadlineExceeded) {
			t.Fatal("duplicate proof retained the stream past its shorter local fence")
		}
	})
}
