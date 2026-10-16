package managedssh

import (
	"context"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSessionRequestFloodCannotBlockConnectionShutdown(t *testing.T) {
	finish := make(chan struct{})
	client, done := protocolServer(t, protocolConfig(t), protocolRunner{run: func(ctx context.Context, _ Request, streams Streams) (int, error) {
		_, _ = io.WriteString(streams.Stdout, "ready")
		select {
		case <-finish:
		case <-ctx.Done():
		}
		if streams.CloseInput != nil {
			streams.CloseInput()
		}
		return 0, nil
	}})
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(requests)
	if ok, err := channel.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{"true"})); err != nil || !ok {
		t.Fatal("exec rejected", err)
	}
	var ready [5]byte
	if _, err := io.ReadFull(channel, ready[:]); err != nil {
		t.Fatal(err)
	}
	floodDone := make(chan struct{})
	go func() {
		defer close(floodDone)
		for i := 0; i < 10000; i++ {
			if _, err := channel.SendRequest("after-exit", false, nil); err != nil {
				return
			}
		}
	}()
	close(finish)
	// leave stdin open while the command exits and requests fill the mux queue.
	time.Sleep(30 * time.Millisecond)
	_ = client.Close()
	awaitProtocol(t, done)
	awaitProtocol(t, floodDone)
}
