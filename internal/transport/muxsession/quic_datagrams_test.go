package muxsession

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestQUICDatagramSenderCancellationKeepsOneSessionWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lifetime, stop := context.WithCancel(t.Context())
		defer stop()
		started, release := make(chan struct{}), make(chan struct{})
		observed := make(chan []byte, 2)
		var calls atomic.Int32
		sender := newQUICDatagramSender(lifetime, func(packet []byte) error {
			if calls.Add(1) == 1 {
				close(started)
				<-release
			}
			observed <- bytes.Clone(packet)
			return nil
		})
		packet := []byte("first")
		call, cancel := context.WithCancelCause(t.Context())
		denied := errors.New("packet owner stopped")
		result := make(chan error, 1)
		go func() { result <- sender.send(call, packet) }()
		<-started
		cancel(denied)
		if err := <-result; !errors.Is(err, denied) {
			t.Fatal("borrower cancellation did not release blocked send", err)
		}
		packet[0] = 'x'
		// the blocked library call belongs to the session, not a growing set
		// of per-packet goroutines after successive borrower cancellations.
		for range 64 {
			call, cancel := context.WithCancelCause(t.Context())
			go func() { result <- sender.send(call, []byte("not submitted")) }()
			synctest.Wait()
			cancel(denied)
			if err := <-result; !errors.Is(err, denied) {
				t.Fatal("canceled queued sender did not join", err)
			}
		}
		if calls.Load() != 1 {
			t.Fatal("blocked session started another library enqueue", calls.Load())
		}
		select {
		case <-sender.done:
			t.Fatal("borrower cancellation retired shared session sender")
		default:
		}
		close(release)
		if got := <-observed; string(got) != "first" {
			t.Fatal("canceled caller mutated in-flight packet", string(got))
		}
		if err := sender.send(t.Context(), []byte("sibling")); err != nil {
			t.Fatal("sibling could not reuse session sender", err)
		}
		if got := <-observed; string(got) != "sibling" {
			t.Fatal("canceled queued packet reached transport", string(got))
		}
		stop()
		<-sender.done
		if err := sender.send(t.Context(), []byte("late")); !errors.Is(err, context.Canceled) {
			t.Fatal("stopped session accepted a late packet", err)
		}
	})
}

func TestQUICDatagramSenderSessionStopJoinsBlockedLibraryEnqueue(t *testing.T) {
	lifetime, stop := context.WithCancel(t.Context())
	defer stop()
	started := make(chan struct{})
	sender := newQUICDatagramSender(lifetime, func([]byte) error {
		close(started)
		<-lifetime.Done() // closing QUIC releases its queue wait.
		return context.Cause(lifetime)
	})
	result := make(chan error, 1)
	go func() { result <- sender.send(t.Context(), []byte("packet")) }()
	<-started
	stop()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal("session shutdown returned send success", err)
	}
	<-sender.done
}

func TestQUICDatagramSenderPreservesEnqueueFailure(t *testing.T) {
	lifetime, stop := context.WithCancel(t.Context())
	defer stop()
	failed := errors.New("fixture enqueue failure")
	sender := newQUICDatagramSender(lifetime, func([]byte) error { return failed })
	if err := sender.send(t.Context(), []byte("packet")); !errors.Is(err, failed) {
		t.Fatal("enqueue cause was lost", err)
	}
	stop()
	<-sender.done
}

func TestQUICDatagramSenderThroughSessionOwnsAndJoinsWorker(t *testing.T) {
	config := &quic.Config{EnableDatagrams: true}
	client, server := newQUICPairWithConfig(t, config, config)
	packets, incoming := client.(DatagramSession), server.(DatagramSession)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	call, canceled := context.WithCancelCause(ctx)
	stopped := errors.New("borrower stopped")
	canceled(stopped)
	if err := packets.SendDatagram(call, []byte("canceled")); !errors.Is(err, stopped) {
		t.Fatal("session ignored canceled borrower", err)
	}
	if err := client.Err(); err != nil {
		t.Fatal("borrower cancellation closed session", err)
	}
	if err := packets.SendDatagram(ctx, []byte("current")); err != nil {
		t.Fatal(err)
	}
	if got, err := incoming.ReceiveDatagram(ctx); err != nil || string(got) != "current" {
		t.Fatal("session lost packet or sent canceled input", string(got), err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.(*quicSession).packets.done:
	default:
		t.Fatal("session close returned before packet worker joined")
	}
	// a session closed without packet traffic seals lazy worker startup too.
	_ = server.Close()
	if server.(*quicSession).packets != nil {
		t.Fatal("unused receiver started an outgoing packet worker")
	}
	if err := incoming.SendDatagram(ctx, []byte("late")); !errors.Is(err, ErrClosed) {
		t.Fatal("late send revived closed session", err)
	}
	if server.(*quicSession).packets != nil {
		t.Fatal("late send started a worker after shutdown")
	}
}
