package publisher

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/streamcopy"
)

func TestVisitorPassthroughForwardsTargetHalfClose(t *testing.T) {
	visitor, publisher := inspectionTCPPair(t)
	target, backend := inspectionTCPPair(t)
	for _, connection := range []net.Conn{visitor, publisher, target, backend} {
		if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	// the publisher replays the PROXY header and inspected ClientHello through
	// these same connection layers before copying the visitor stream.
	metadata := &metadataConn{Conn: &publicURLReaderConn{Conn: publisher, reader: publisher}}
	inspected := &publicURLReaderConn{Conn: metadata, reader: metadata}
	copyDone := make(chan error, 1)
	copyFinished := false
	go func() {
		_, err := streamcopy.Copy(inspected, target)
		copyDone <- err
	}()
	t.Cleanup(func() {
		_ = visitor.Close()
		_ = publisher.Close()
		_ = target.Close()
		_ = backend.Close()
		if copyFinished {
			return
		}
		select {
		case <-copyDone:
		case <-time.After(2 * time.Second):
			t.Error("passthrough copy did not stop after closing both ends")
		}
	})
	if _, err := visitor.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, len("request"))
	if _, err := io.ReadFull(backend, request); err != nil || string(request) != "request" {
		t.Fatalf("private target request = %q, %v", request, err)
	}
	if _, err := backend.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err := backend.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("reply"))
	if _, err := io.ReadFull(visitor, reply); err != nil || string(reply) != "reply" {
		t.Fatalf("visitor reply = %q, %v", reply, err)
	}
	if _, err := visitor.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("target half-close did not reach visitor: %v", err)
	}
	if err := visitor.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-copyDone:
		copyFinished = true
		if err != nil {
			t.Fatalf("passthrough copy shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("passthrough copy did not stop after both half-closes")
	}
}
