package tunnel

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// the independently reviewed setup owner is composed later. this fixture supplies
// its optional method structurally, without importing or duplicating that owner.
type setupCapabilityFixture struct {
	muxsession.Session
	confirmed atomic.Int32
}

func (*setupCapabilityFixture) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (*setupCapabilityFixture) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 5678}
}
func (*setupCapabilityFixture) TLSConnectionState() tls.ConnectionState {
	return tls.ConnectionState{NegotiatedProtocol: muxsession.ALPN}
}
func (s *setupCapabilityFixture) ConfirmAuthentication(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	s.confirmed.Add(1)
	return nil
}

type datagramSetupCapabilityFixture struct{ *setupCapabilityFixture }

func (*datagramSetupCapabilityFixture) SupportsDatagrams() bool { return true }
func (*datagramSetupCapabilityFixture) SendDatagram(ctx context.Context, _ []byte) error {
	return context.Cause(ctx)
}
func (*datagramSetupCapabilityFixture) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return []byte("fixture packet"), context.Cause(ctx)
}

var (
	_ muxsession.Session                                        = (*setupCapabilityFixture)(nil)
	_ muxsession.AcceptedPeer                                   = (*setupCapabilityFixture)(nil)
	_ interface{ ConfirmAuthentication(context.Context) error } = (*setupCapabilityFixture)(nil)
	_ muxsession.Session                                        = (*datagramSetupCapabilityFixture)(nil)
	_ muxsession.AcceptedPeer                                   = (*datagramSetupCapabilityFixture)(nil)
	_ muxsession.DatagramSession                                = (*datagramSetupCapabilityFixture)(nil)
	_ interface{ ConfirmAuthentication(context.Context) error } = (*datagramSetupCapabilityFixture)(nil)
)

func TestServicePublisherTransportRetainsWholeOptionalCapabilitiesWithoutPromotion(t *testing.T) {
	for _, datagrams := range []bool{false, true} {
		t.Run(map[bool]string{false: "stream", true: "datagram"}[datagrams], func(t *testing.T) {
			_, server := newMemoryPair(t)
			fixture := &setupCapabilityFixture{Session: server}
			var original muxsession.Session = fixture
			if datagrams {
				original = &datagramSetupCapabilityFixture{fixture}
			}
			owner := &Session{transport: original, role: tunnelv1.Publisher, serviceConnection: &tunnelv1.ServicePublisherConnectionRef{}}
			borrowed, err := owner.BorrowServicePublisherTransport()
			if err != nil || borrowed != original {
				t.Fatal("borrowing wrapped or replaced the accepted transport", err)
			}
			accepted, ok := borrowed.(muxsession.AcceptedPeer)
			if !ok || accepted.LocalAddr().String() != fixture.LocalAddr().String() || accepted.RemoteAddr().String() != fixture.RemoteAddr().String() || accepted.TLSConnectionState().NegotiatedProtocol != muxsession.ALPN {
				t.Fatal("borrowing lost accepted peer identity")
			}
			setup, ok := borrowed.(interface{ ConfirmAuthentication(context.Context) error })
			if !ok || fixture.confirmed.Load() != 0 {
				t.Fatal("borrowing lost or prematurely invoked setup authentication")
			}
			packets, supports := borrowed.(muxsession.DatagramSession)
			if supports != datagrams {
				t.Fatal("borrowing changed conditional datagram capability")
			}
			if supports {
				if !packets.SupportsDatagrams() || packets.SendDatagram(t.Context(), []byte("packet")) != nil {
					t.Fatal("borrowing lost complete datagram send capability")
				}
				if packet, err := packets.ReceiveDatagram(t.Context()); err != nil || string(packet) != "fixture packet" {
					t.Fatal("borrowing lost complete datagram receive capability", err)
				}
			}
			// only the credential owner invokes promotion. neither accepted TLS,
			// a publisher role marker, nor borrowing is an authentication result.
			if err := setup.ConfirmAuthentication(t.Context()); err != nil || fixture.confirmed.Load() != 1 {
				t.Fatal("accepted setup owner did not retain its lifecycle hook", err)
			}
		})
	}
}
