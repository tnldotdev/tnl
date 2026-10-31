package tunnel

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

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
							stream, err := client.OpenVisitorStream(ctx, visitorStreamHeader(), ReturnEvents{})
							return opened{stream, err}
						}
						stream, err := client.OpenInternalForwardingStream(ctx, internalForwardingHeader(), ReturnEvents{})
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
						if err := deny(tunnelv1.CapacityExceeded); err != nil {
							t.Fatal(err)
						}
						got := await(t, result)
						var protocolError *ProtocolError
						if got.stream != nil || !errors.As(got.err, &protocolError) || protocolError.Code != tunnelv1.CapacityExceeded {
							t.Fatal("rejection returned a usable stream or lost its cause", got.err)
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
