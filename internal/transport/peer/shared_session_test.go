package peer

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func TestSharedSessionRegistersAndJoinsWithoutClosingTransport(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "quic", true: "tls-tcp"}[tcp], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			serverTLS, clientTLS := peerTLS(t)
			var left, right muxsession.Session
			if tcp {
				left, right = sharedTLSPair(t, ctx, serverTLS, clientTLS)
			} else {
				left, right = sharedQUICPair(t, ctx, serverTLS, clientTLS)
			}
			a, err := NewSharedSession(ctx, left)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := NewDispatchedSharedSession(ctx, right)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			accepted := make(chan struct{})
			go func() {
				defer close(accepted)
				if tcp {
					stream, err := right.AcceptStream(ctx)
					if err == nil {
						b.AcceptIntroduction(ctx, stream)
					}
				}
			}()
			outgoing, incoming := sharedBinding(t, 1, RelayA)
			sender, err := a.Register(outgoing, true)
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := b.Register(incoming, false)
			if err != nil {
				t.Fatal(err)
			}
			frame := signedFrame(t, outgoing)
			if err := sender.Send(ctx, frame); err != nil {
				t.Fatal(err)
			}
			if got, err := receiver.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
				t.Fatal("registered transport lost its frame", err)
			}
			<-accepted
			_ = a.Close()
			_ = b.Close()
			if left.Err() != nil || right.Err() != nil {
				t.Fatal("packet cleanup closed its borrowed transport")
			}
			if _, err := a.Register(outgoing, true); err == nil {
				t.Fatal("closed owner accepted a registration")
			}
		})
	}
}

func TestSharedStreamInitiatorReadDoesNotSpendRemoteIntroduction(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	left, right := sharedTLSPair(t, ctx, serverTLS, clientTLS)
	initiator, err := NewSharedSession(ctx, left)
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.Close()
	outgoing, incoming := sharedBinding(t, 1, RelayA)
	sender, err := initiator.Register(outgoing, true)
	if err != nil {
		t.Fatal(err)
	}
	// the remote registration does not exist yet. a passive read must not
	// create a header-only stream, start its introduction deadline, or retire it.
	quiet, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	_, err = sender.Receive(quiet)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("passive preparation did not honor its own deadline", err)
	}
	remote, err := NewSharedSession(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	receiver, err := remote.Register(incoming, false)
	if err != nil {
		t.Fatal(err)
	}
	frame := signedFrame(t, outgoing)
	if err := sender.Send(ctx, frame); err != nil {
		t.Fatal("passive read spent the only introduction", err)
	}
	if got, err := receiver.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
		t.Fatal("first send did not introduce the installed pair", err)
	}
	reply := signedFrame(t, incoming)
	if err := receiver.Send(ctx, reply); err != nil {
		t.Fatal(err)
	}
	if got, err := sender.Receive(ctx); err != nil || !bytes.Equal(got, reply) {
		t.Fatal("introduced stream lost its return direction", err)
	}
	if left.Err() != nil || right.Err() != nil {
		t.Fatal("preparation closed a borrowed outer transport")
	}
}

func TestSharedStreamPassiveProbeDoesNotSpendConnectorStartup(t *testing.T) {
	for _, replaceable := range []bool{false, true} {
		t.Run(map[bool]string{false: "carrier", true: "slot"}[replaceable], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			serverTLS, clientTLS := peerTLS(t)
			left, right := sharedTLSPair(t, ctx, serverTLS, clientTLS)
			publisher, err := NewSharedSession(ctx, right)
			if err != nil {
				t.Fatal(err)
			}
			defer publisher.Close()
			outgoing, incoming := sharedBinding(t, 1, RelayA)
			passive, err := publisher.Register(incoming, false)
			if err != nil {
				t.Fatal(err)
			}
			var receiver Carrier = passive
			slot := NewCarrierSlot()
			if replaceable {
				if err := slot.Install(passive); err != nil {
					t.Fatal(err)
				}
				receiver = slot
			}
			defer receiver.Close()
			revision := slot.Generation()
			// the publisher can prepare before control lets the connector start
			// its stream. an early probe must drop, not spend a write deadline
			// waiting for that introduction and retire the installed carrier.
			probe := signedFrame(t, incoming)
			write, stop := context.WithTimeout(ctx, 30*time.Millisecond)
			err = receiver.Send(write, probe)
			stop()
			if err != nil || slot.Generation() != revision {
				t.Fatal("an early probe retired the passive path", err)
			}
			connector, err := NewSharedSession(ctx, left)
			if err != nil {
				t.Fatal(err)
			}
			defer connector.Close()
			sender, err := connector.Register(outgoing, true)
			if err != nil {
				t.Fatal(err)
			}
			frame := signedFrame(t, outgoing)
			if err := sender.Send(ctx, frame); err != nil {
				t.Fatal(err)
			}
			if got, err := receiver.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
				t.Fatal("delayed connector could not introduce the retained path", err)
			}
			if err := receiver.Send(ctx, probe); err != nil {
				t.Fatal(err)
			}
			if got, err := sender.Receive(ctx); err != nil || !bytes.Equal(got, probe) {
				t.Fatal("retained path lost its return direction", err)
			}
			if left.Err() != nil || right.Err() != nil {
				t.Fatal("packet startup closed a borrowed relay transport")
			}
		})
	}
}

func TestSharedStreamPassiveProbeHonorsCancellationAndClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	_, right := sharedTLSPair(t, ctx, serverTLS, clientTLS)
	owner, err := NewSharedSession(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	_, incoming := sharedBinding(t, 1, RelayA)
	passive, err := owner.Register(incoming, false)
	if err != nil {
		t.Fatal(err)
	}
	frame := signedFrame(t, incoming)
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := passive.Send(canceled, frame); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled probe was accepted", err)
	}
	if err := passive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := passive.Send(ctx, frame); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed registration accepted a probe", err)
	}
}

func TestSharedStreamPassiveProbeDoesNotWaitForAcceptingReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		pair := &StreamPair{pending: make(chan *SharedStreamCarrier, 1), done: make(chan struct{})}
		passive := pair.Carrier(false)
		readDone := make(chan error, 1)
		go func() {
			_, err := passive.Receive(ctx)
			readDone <- err
		}()
		// the reader now owns the one accept and is waiting for the initiator.
		synctest.Wait()
		write, stop := context.WithTimeout(ctx, 30*time.Millisecond)
		defer stop()
		writeDone := make(chan error, 1)
		go func() { writeDone <- passive.Send(write, nil) }()
		synctest.Wait()
		select {
		case err := <-writeDone:
			if err != nil {
				t.Error("probe spent its deadline waiting for an introduction", err)
			}
		default:
			t.Error("probe blocked behind the accepting reader")
			cancel()
			<-writeDone
		}
		cancel()
		if err := <-readDone; !errors.Is(err, context.Canceled) {
			t.Fatal("reader did not join cancellation", err)
		}
	})
}
