package publisher

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/streamcopy"
)

type discardDatabaseInspector struct{}

func (discardDatabaseInspector) clientBytes([]byte) {}
func (discardDatabaseInspector) serverBytes([]byte) {}
func (discardDatabaseInspector) stop()              {}

func TestDatabaseInspectionConnPropagatesVisitorEOF(t *testing.T) {
	const deadline = 5 * time.Second
	client, visitor := inspectionTCPPair(t)
	backend, target := inspectionTCPPair(t)
	observed := &databaseInspectionConn{Conn: backend, observer: discardDatabaseInspector{}}
	copyDone := make(chan struct{})
	var copyErr error
	go func() {
		_, copyErr = streamcopy.Copy(visitor, observed)
		close(copyDone)
	}()
	t.Cleanup(func() {
		_ = visitor.Close()
		_ = backend.Close()
		select {
		case <-copyDone:
		case <-time.After(deadline):
			t.Error("inspected stream did not stop after closing both ends")
		}
	})
	if err := client.SetDeadline(time.Now().Add(deadline)); err != nil {
		t.Fatal(err)
	}
	if err := target.SetDeadline(time.Now().Add(deadline)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(target)
	if err != nil || string(request) != "request" {
		t.Fatalf("target waited for a visitor EOF: request %q, %v", request, err)
	}
	if _, err := target.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := target.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil || string(response) != "response" {
		t.Fatalf("visitor response = %q, %v", response, err)
	}
	select {
	case <-copyDone:
		if copyErr != nil {
			t.Fatalf("copy inspected stream: %v", copyErr)
		}
	case <-time.After(deadline):
		t.Fatal("inspected stream did not finish after both half-closes")
	}
}

func inspectionTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client.(*net.TCPConn), server.(*net.TCPConn)
}
