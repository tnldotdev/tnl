package tunnel

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorRequestRenewalRejectsInvalidDeadlineBeforeGatesOrIO(t *testing.T) {
	for _, test := range []struct {
		name  string
		until time.Time
	}{{"zero", time.Time{}}, {"expired", time.Now().Add(-time.Second)}} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			tracked := &connectorDeadlineConn{Conn: client, deadlines: make(chan time.Time, 4), writes: make(chan struct{}, 8)}
			opened := false
			writer := NewConnectorOpeningWriter(tracked, func([]byte) error { opened = true; return nil })
			writer.renewMu <- struct{}{}
			defer func() { <-writer.renewMu }()
			writer.mu <- struct{}{}
			defer func() { <-writer.mu }()
			done := make(chan error, 1)
			go func() { done <- writer.Renew(connectorRequestPermissionFixture(), test.until) }()
			select {
			case err := <-done:
				if !errors.Is(err, os.ErrDeadlineExceeded) || opened || len(tracked.deadlines) != 0 || len(tracked.writes) != 0 {
					t.Fatal("invalid renewal entered a gate, opened the stream, or changed its deadline", err)
				}
			case <-time.After(time.Second):
				t.Fatal("invalid renewal waited for a serialization gate")
			}
		})
	}
}

func TestConnectorRequestRenewalDeadlineBoundsBothGates(t *testing.T) {
	for _, name := range []string{"renewal", "application"} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			tracked := &connectorDeadlineConn{Conn: client, deadlines: make(chan time.Time, 4), writes: make(chan struct{}, 8)}
			writer := NewConnectorRequestWriter(tracked)
			gate := writer.renewMu
			if name == "application" {
				gate = writer.mu
			}
			gate <- struct{}{}
			release := sync.OnceFunc(func() { <-gate })
			defer release()
			done := make(chan error, 1)
			until := time.Now().Add(20 * time.Millisecond)
			go func() { done <- writer.Renew(connectorRequestPermissionFixture(), until) }()
			select {
			case err := <-done:
				if !errors.Is(err, os.ErrDeadlineExceeded) || len(tracked.deadlines) != 0 || len(tracked.writes) != 0 {
					t.Fatal("waiting renewal changed the deadline or wrote a frame", err)
				}
			case <-time.After(time.Second):
				t.Fatal("renewal waited beyond its original gate budget")
			}
			release()
			// a gate timeout did not start a frame or poison a subsequent write.
			go func() { _, err := writer.Write([]byte("application")); done <- err }()
			_ = server.SetReadDeadline(time.Now().Add(time.Second))
			frame, err := tunnelv1.ReadConnectorRequestFrame(server)
			if err != nil || string(frame.Data) != "application" {
				t.Fatal("gate timeout retained a gate or poisoned application data", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConnectorRequestRenewalBlockedWriteRestoresDeadline(t *testing.T) {
	for _, name := range []string{"permission", "opening", "restore failure"} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			tracked := &connectorDeadlineConn{Conn: client, deadlines: make(chan time.Time, 4), writes: make(chan struct{}, 8)}
			writer := NewConnectorRequestWriter(tracked)
			if name == "opening" {
				writer = NewConnectorOpeningWriter(tracked, func([]byte) error { _, err := tracked.Write([]byte("opening")); return err })
			}
			var restoreErr error
			if name == "restore failure" {
				restoreErr = errors.New("restore failed")
				tracked.restore = func() error { return restoreErr }
			}
			until := time.Now().Add(100 * time.Millisecond)
			done := make(chan error, 1)
			go func() { done <- writer.Renew(connectorRequestPermissionFixture(), until) }()
			select {
			case at := <-tracked.deadlines:
				if !at.Equal(until) {
					t.Fatal("renewal reset its original write deadline")
				}
			case <-time.After(time.Second):
				t.Fatal("renewal did not install its write deadline")
			}
			select {
			case <-tracked.writes:
			case <-time.After(time.Second):
				t.Fatal("renewal stalled before its write")
			}
			select {
			case err := <-done:
				if !errors.Is(err, os.ErrDeadlineExceeded) || (restoreErr != nil && !errors.Is(err, restoreErr)) {
					t.Fatal("blocked renewal lost its deadline or restoration cause", err)
				}
			case <-time.After(time.Second):
				t.Fatal("blocked renewal write escaped its deadline")
			}
			if at := <-tracked.deadlines; !at.IsZero() {
				t.Fatal("failed renewal left its deadline installed")
			}
			if _, err := writer.Write([]byte("following")); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("failed renewal allowed ambiguous framing to resume", err)
			}
		})
	}
}

type connectorTLSCloseFunc func() error

func (close connectorTLSCloseFunc) CloseWrite() error { return close() }

func TestConnectorRequestRenewalRestoresDeadlineBeforeReleasingGates(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tracked := &connectorDeadlineConn{Conn: client, deadlines: make(chan time.Time, 8), writes: make(chan struct{}, 8)}
	restoring, release := make(chan struct{}), make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	defer resume()
	var once sync.Once
	tracked.restore = func() error { once.Do(func() { close(restoring); <-release }); return nil }
	writer := NewConnectorRequestWriter(tracked)
	renewed := make(chan error, 1)
	go func() { renewed <- writer.Renew(connectorRequestPermissionFixture(), time.Now().Add(time.Second)) }()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := tunnelv1.ReadConnectorRequestFrame(server)
	if err != nil || frame.Kind != tunnelv1.ConnectorRequestPermission {
		t.Fatal("renewal lost its permission frame", err)
	}
	<-restoring
	for len(tracked.writes) > 0 {
		<-tracked.writes
	}
	written, closed := make(chan error, 1), make(chan error, 1)
	tlsEntered := make(chan struct{})
	go func() { _, err := writer.Write([]byte("following")); written <- err }()
	go func() {
		closed <- writer.CloseTLSWrite(connectorTLSCloseFunc(func() error { close(tlsEntered); return nil }))
	}()
	select {
	case <-tracked.writes:
		t.Fatal("application write entered before renewal restored its deadline")
	case <-tlsEntered:
		t.Fatal("TLS half-close entered before renewal restored its deadline")
	case <-time.After(20 * time.Millisecond):
	}
	resume()
	if err := <-renewed; err != nil {
		t.Fatal(err)
	}
	frame, err = tunnelv1.ReadConnectorRequestFrame(server)
	if err != nil || string(frame.Data) != "following" {
		t.Fatal("restored renewal changed the following application frame", err)
	}
	for _, done := range []chan error{written, closed} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("restoration retained a serialization gate")
		}
	}
}

func TestConnectorRequestRenewalCloseInterruptsBlockedWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tracked := &connectorDeadlineConn{Conn: client, deadlines: make(chan time.Time, 4), writes: make(chan struct{}, 8)}
	writer := NewConnectorRequestWriter(tracked)
	done := make(chan error, 1)
	go func() { done <- writer.Renew(connectorRequestPermissionFixture(), time.Now().Add(time.Minute)) }()
	<-tracked.writes
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("stream close lost its blocked renewal cause", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream close did not join the blocked renewal")
	}
	if len(writer.mu) != 0 || len(writer.renewMu) != 0 {
		t.Fatal("closed renewal retained a serialization gate")
	}
}
