package tunnel

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type terminalAcceptTransport struct {
	muxsession.Session
	entered chan struct{}
	result  chan error
}

func (s terminalAcceptTransport) AcceptStream(context.Context) (muxsession.Stream, error) {
	close(s.entered)
	return nil, <-s.result
}

func TestServiceAcceptOwnersRetainIndependentTerminalFailures(t *testing.T) {
	for _, owner := range []string{"capacity", "dispatcher"} {
		for _, canceled := range []bool{false, true} {
			for _, independent := range []bool{false, true} {
				name := owner + map[bool]string{false: "/closed", true: "/canceled"}[canceled] + map[bool]string{false: "/expected", true: "/independent"}[independent]
				t.Run(name, func(t *testing.T) {
					_, remote := newMemoryPair(t)
					transport := terminalAcceptTransport{Session: remote, entered: make(chan struct{}), result: make(chan error, 1)}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					sentinel := errors.New("independent terminal accept failure")
					acceptErr := error(muxsession.ErrClosed)
					if canceled {
						acceptErr = context.Canceled
					}
					if independent {
						acceptErr = errors.Join(acceptErr, sentinel)
					}
					session := &Session{transport: transport, role: tunnelv1.Ingress}
					var done <-chan error
					var dispatcher *ServiceStreamDispatcher
					if owner == "capacity" {
						done = tunnelWorker(t, cancel, func() error { return session.ServeServiceCapacity(ctx) })
					} else {
						session.role, session.serviceConnection = tunnelv1.Publisher, &tunnelv1.ServicePublisherConnectionRef{}
						var err error
						dispatcher, err = NewServiceStreamDispatcher(ctx, session, nil)
						if err != nil {
							t.Fatal(err)
						}
					}
					await(t, transport.entered)
					if canceled {
						cancel()
					}
					transport.result <- acceptErr
					if owner == "capacity" {
						err := await(t, done)
						if errors.Is(err, sentinel) != independent || !independent && err != nil {
							t.Fatal("capacity lost independent accept failure or reported expected shutdown", err)
						}
					} else {
						// join the actual accept result even if caller cancellation won
						// the forwarding select before the transport returned.
						err := dispatcher.Close()
						if errors.Is(err, sentinel) != independent || !independent && err != nil {
							t.Fatal("dispatcher close lost terminal accept failure", err)
						}
						_, err = dispatcher.AcceptForwardingStream(t.Context())
						if !errors.Is(err, net.ErrClosed) || errors.Is(err, sentinel) != independent {
							t.Fatal("dispatcher consumer lost terminal accept failure", err)
						}
						if again := dispatcher.Close(); errors.Is(again, sentinel) != independent {
							t.Fatal("repeated close lost terminal accept failure", again)
						}
					}
				})
			}
		}
	}
}

func TestServiceDispatcherRetainsRejectedStreamCloseFailure(t *testing.T) {
	client, server := newMemoryPair(t)
	sentinel := errors.New("rejected stream close failed")
	owner := &Session{transport: capacityCloseTransport{Session: server, acceptFailure: sentinel},
		role: tunnelv1.Publisher, serviceConnection: &tunnelv1.ServicePublisherConnectionRef{}}
	d, err := NewServiceStreamDispatcher(t.Context(), owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	stream, err := client.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte{255}); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); !errors.Is(err, sentinel) {
		t.Fatal("dispatcher discarded owned rejected-stream close failure", err)
	}
	if client.Err() != nil || server.Err() != nil {
		t.Fatal("dispatcher closed its borrowed session")
	}
}
