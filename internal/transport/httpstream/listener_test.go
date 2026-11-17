package httpstream

import (
	"errors"
	"io"
	"net"
	"testing"
)

func TestSingleListenerCloseDoesNotCloseAcceptedConnection(t *testing.T) {
	server, visitor := net.Pipe()
	defer server.Close()
	defer visitor.Close()
	listener := &singleListener{connection: server, done: make(chan struct{})}
	accepted, err := listener.Accept()
	if err != nil || accepted != server {
		t.Fatal("listener did not hand off the exact visitor connection", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed listener admitted another connection", err)
	}
	written := make(chan error, 1)
	go func() { _, err := io.WriteString(accepted, "final"); written <- err }()
	payload := make([]byte, 5)
	if _, err := io.ReadFull(visitor, payload); err != nil || string(payload) != "final" {
		t.Fatal("listener shutdown closed the already accepted connection", string(payload), err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestSingleListenerCloseFencesFirstAccept(t *testing.T) {
	server, visitor := net.Pipe()
	defer server.Close()
	defer visitor.Close()
	listener := &singleListener{connection: server, done: make(chan struct{})}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("listener closed before Serve still admitted its connection", err)
	}
}
