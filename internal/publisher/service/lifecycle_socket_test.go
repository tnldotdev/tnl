package service

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

type lifecycleDrainingSlot struct {
	muxsession.Session
	draining chan<- struct{}
	release  <-chan struct{}
}

func (s *lifecycleDrainingSlot) Serve(ctx context.Context) error {
	select {
	case <-ctx.Done():
	case <-s.Done():
	}
	return nil
}

func (s *lifecycleDrainingSlot) Drain(ctx context.Context) error {
	s.draining <- struct{}{}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestPrivateLifecycleSharedSocketOutlivesRelayDrain(t *testing.T) {
	config, _ := lifecycleFixture(t)
	serverTLS, configTLS := privateTransportTLS(t)
	config.TransportTLS = configTLS
	listener, err := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, muxsession.QUICConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var servers sync.WaitGroup
	defer servers.Wait()
	for range 2 {
		servers.Go(func() {
			session, err := listener.Accept(t.Context())
			if err != nil {
				return
			}
			defer session.Close()
			stream, err := session.AcceptStream(t.Context())
			if err == nil {
				defer stream.Close()
				_, _ = io.Copy(stream, stream)
			}
		})
	}
	release := make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	draining := make(chan struct{}, 2)
	connected := make(chan muxsession.Session, 2)
	config.Connect = func(ctx context.Context, _ *Bound, _ uint8, options ConnectOptions) (SlotSession, error) {
		session, err := options.QUIC.Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
		if err != nil {
			return nil, err
		}
		connected <- session
		return &lifecycleDrainingSlot{Session: session, draining: draining, release: release}, nil
	}
	ready := make(chan struct{})
	config.Ready = func() error { close(ready); return nil }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Publish(ctx, config) }()
	defer func() {
		cancel()
		finish()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(12 * time.Second):
			t.Error("publisher did not join after drain")
		}
		_ = listener.Close()
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not become ready")
	}
	var streams [2]muxsession.Stream
	for side := range streams {
		session := <-connected
		streams[side], err = session.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer streams[side].Close()
	}
	exchange := func(stream muxsession.Stream) {
		t.Helper()
		_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(stream, "retained"); err != nil {
			t.Fatal("publisher drain closed shared QUIC", err)
		}
		var response [8]byte
		if _, err := io.ReadFull(stream, response[:]); err != nil || string(response[:]) != "retained" {
			t.Fatal("publisher drain interrupted admitted bytes", err)
		}
	}
	for _, stream := range streams {
		exchange(stream)
	}
	cancel()
	for range streams {
		select {
		case <-draining:
		case <-time.After(3 * time.Second):
			t.Fatal("publisher did not begin relay drain")
		}
	}
	for _, stream := range streams {
		exchange(stream)
	}
}
