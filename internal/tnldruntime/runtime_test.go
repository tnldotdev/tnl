package tnldruntime

import (
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestConnectionListenerTransfersOwnership(t *testing.T) {
	listener := newConnectionListener(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	enqueued := make(chan bool, 1)
	go func() { enqueued <- listener.Enqueue(server) }()
	accepted, err := listener.Accept()
	if err != nil || accepted != server || !<-enqueued {
		t.Fatalf("accepted connection = %v, %v", accepted, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept after close = %v", err)
	}
	if listener.Enqueue(client) {
		t.Fatal("closed listener accepted a connection")
	}
}

func TestControlHTTPServerBoundsRequestAndResponseIO(t *testing.T) {
	server := controlHTTPServer(http.NotFoundHandler(), nil)
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 30*time.Second ||
		server.WriteTimeout != 3*time.Minute || server.IdleTimeout != 30*time.Second || server.MaxHeaderBytes != 16<<10 {
		t.Fatalf("HTTP server limits = %#v", server)
	}
}
