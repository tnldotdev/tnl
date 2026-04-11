package tailtransport

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
)

func TestStreamRegistryDrainWaitsForOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		registry := newStreamRegistry()
		if err := registry.beginOpen(); err != nil {
			t.Fatalf("beginOpen: %v", err)
		}

		drained := make(chan error, 1)
		go func() { drained <- registry.drain(context.Background()) }()
		synctest.Wait()
		if err := registry.beginOpen(); !errors.Is(err, errDraining) {
			t.Fatalf("beginOpen while draining = %v; want errDraining", err)
		}

		local, peer := net.Pipe()
		defer peer.Close()
		if conn, err := registry.finishOpen(local, nil); conn != nil || !errors.Is(err, errDraining) {
			t.Fatalf("finishOpen = %v, %v; want nil, errDraining", conn, err)
		}
		if err := <-drained; err != nil {
			t.Fatalf("drain: %v", err)
		}
	})
}

func TestStreamRegistryDrainDeadlineClosesStreams(t *testing.T) {
	registry := newStreamRegistry()
	local, peer := net.Pipe()
	tracked, err := registry.track(local)
	if err != nil {
		t.Fatalf("track: %v", err)
	}
	t.Cleanup(func() { tracked.Close() })
	t.Cleanup(func() { peer.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := registry.drain(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("drain = %v; want context.Canceled", err)
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("peer read after drain = %v; want EOF or net.ErrClosed", err)
	}
}

func TestTrackedConnForwardsHalfClose(t *testing.T) {
	base := &halfCloseConn{}
	tracked := &trackedConn{Conn: base, release: func() {}}
	if err := tracked.CloseRead(); err != nil {
		t.Fatalf("CloseRead: %v", err)
	}
	if err := tracked.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if !base.readClosed || !base.writeClosed {
		t.Fatalf("half-close forwarding = read:%v write:%v; want both true", base.readClosed, base.writeClosed)
	}
}

func TestStreamRegistryConcurrentCloseWaits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		registry := newStreamRegistry()
		closeStarted := make(chan struct{})
		unblockClose := make(chan struct{})
		conn := &blockingCloseConn{closeStarted: closeStarted, unblockClose: unblockClose}
		if _, err := registry.track(conn); err != nil {
			t.Fatalf("track: %v", err)
		}

		firstDone := make(chan struct{})
		go func() {
			registry.close()
			close(firstDone)
		}()
		<-closeStarted
		secondDone := make(chan struct{})
		go func() {
			registry.close()
			close(secondDone)
		}()
		synctest.Wait()
		select {
		case <-secondDone:
			t.Fatal("concurrent close returned before stream close completed")
		default:
		}
		close(unblockClose)
		<-firstDone
		<-secondDone
	})
}

type halfCloseConn struct {
	net.Conn
	readClosed  bool
	writeClosed bool
}

type blockingCloseConn struct {
	net.Conn
	closeStarted chan struct{}
	unblockClose chan struct{}
}

func (c *blockingCloseConn) Close() error {
	close(c.closeStarted)
	<-c.unblockClose
	return nil
}

func (c *halfCloseConn) CloseRead() error {
	c.readClosed = true
	return nil
}

func (c *halfCloseConn) CloseWrite() error {
	c.writeClosed = true
	return nil
}
