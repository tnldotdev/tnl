package tnldruntime

import (
	"errors"
	"net"
	"testing"
)

func TestLocalControlDialAddressUsesLoopbackForWildcardListeners(t *testing.T) {
	for input, want := range map[string]string{
		":9443": "127.0.0.1:9443", "0.0.0.0:9444": "127.0.0.1:9444",
		"[::]:9443": "127.0.0.1:9443", "10.0.0.2:9444": "10.0.0.2:9444",
	} {
		got, err := localControlDialAddress(input)
		if err != nil || got != want {
			t.Fatalf("localControlDialAddress(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := localControlDialAddress("invalid"); err == nil {
		t.Fatal("invalid private control listener accepted")
	}
}

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
