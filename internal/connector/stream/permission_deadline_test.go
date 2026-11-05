package stream

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

func deadlinePreparedFixture(t *testing.T, until time.Time) (*PreparedConnector, net.Conn) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	left, right := net.Pipe()
	p := &PreparedConnector{ctx: ctx, conn: left, permissionUntil: until, callbackDone: make(chan struct{})}
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
		if err := p.renewPermission(p.ctx, func() error { return nil }, time.Now().Add(time.Minute)); err == nil {
			t.Fatal("late ACK revived an expired prepared stream")
		}
	})
}

func TestPreparedConnectorStalePermissionCannotBorrowNewExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		until := time.Now().Add(time.Second)
		p, _ := deadlinePreparedFixture(t, until)
		if err := p.renewPermission(p.ctx, func() error { return tunnel.ErrConnectorPermissionStale }, time.Now().Add(time.Minute)); !errors.Is(err, tunnel.ErrConnectorPermissionStale) {
			t.Fatal(err)
		}
		p.mu.Lock()
		fenced := p.permissionPending != nil && p.permissionUntil.Equal(until) && p.permissionErr == nil
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
