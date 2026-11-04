package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type closeAfterPeerCancellation struct {
	muxsession.Stream
	t        *testing.T
	canceled <-chan struct{}
}

func (s *closeAfterPeerCancellation) Close() error {
	await(s.t, s.canceled)
	return s.Stream.Close()
}

func TestOpeningAcknowledgmentPrecedesMetadataAndVisitorBytes(t *testing.T) {
	for _, transport := range []string{"quic", "tls_yamux"} {
		for _, hop := range []string{"publisher", "relay"} {
			for _, reject := range []bool{false, true} {
				name := transport + "/" + hop + map[bool]string{false: "/accept", true: "/reject"}[reject]
				t.Run(name, func(t *testing.T) {
					client, server := realTunnelPair(t, transport)
					ctx := tunnelContext(t)
					type opened struct {
						stream muxsession.Stream
						err    error
					}
					result := tunnelWorker(t, func() { _ = client.Close() }, func() opened {
						if hop == "publisher" {
							header := visitorStreamHeader()
							header.ConfirmBeforeBytes = true
							stream, err := client.OpenVisitorStream(ctx, header, nil, ReturnEvents{})
							return opened{stream, err}
						}
						header := internalForwardingHeader()
						header.ConfirmBeforeBytes = true
						stream, err := client.OpenInternalForwardingStream(ctx, header, nil, nil, ReturnEvents{})
						return opened{stream, err}
					})
					var stream muxsession.Stream
					var accept func() error
					var deny func(tunnelv1.ErrorCode) error
					if hop == "publisher" {
						incoming, err := server.AcceptVisitorStream(ctx)
						if err != nil {
							t.Fatal(err)
						}
						stream, accept, deny = incoming.Stream, incoming.Accept, incoming.Reject
					} else {
						incoming, err := server.AcceptInternalForwardingStream(ctx)
						if err != nil {
							t.Fatal(err)
						}
						stream, accept, deny = incoming.Stream(), incoming.Accept, incoming.Reject
					}
					defer stream.Close()
					if err := stream.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
						t.Fatal(err)
					}
					var payload [1]byte
					n, err := stream.Read(payload[:])
					var timeout net.Error
					if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Fatal("metadata or visitor bytes preceded acceptance", n, err)
					}
					select {
					case <-result:
						t.Fatal("opening returned before acceptance")
					default:
					}
					if reject {
						if transport == "quic" {
							// force the opener to consume the rejection and cancel its
							// stream before the responder closes the sending side.
							reply := stream.(*replyStream)
							peer := reply.Stream.(interface{ Context() context.Context })
							reply.Stream = &closeAfterPeerCancellation{Stream: reply.Stream, t: t, canceled: peer.Context().Done()}
						}
						// receipt owns the rejection result. the opener's cleanup
						// may cancel the responder's close after a successful write.
						denyErr := deny(tunnelv1.CapacityExceeded)
						got := await(t, result)
						var protocolError *ProtocolError
						if got.stream != nil || !errors.As(got.err, &protocolError) || protocolError.Code != tunnelv1.CapacityExceeded {
							t.Fatal("rejection returned a usable stream or lost its cause", got.err, denyErr)
						}
						if client.Err() != nil || server.Err() != nil {
							t.Fatal("stream rejection closed its session", client.Err(), server.Err())
						}
						return
					}
					if err := accept(); err != nil {
						t.Fatal(err)
					}
					got := await(t, result)
					if got.err != nil {
						t.Fatal(got.err)
					}
					defer got.stream.Close()
					if _, err := got.stream.Write([]byte("x")); err != nil {
						t.Fatal(err)
					}
					if _, err := io.ReadFull(stream, payload[:]); err != nil || payload[0] != 'x' {
						t.Fatal("accepted stream did not carry the original bytes", err)
					}
				})
			}
		}
	}
}
