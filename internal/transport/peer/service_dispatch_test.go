package peer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPeerServiceDispatcherOnAuthenticatedTLSYamux(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan muxsession.Session, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		s, _ := muxsession.AcceptTLSYamux(ctx, conn, serverTLS, muxsession.TLSYamuxConfig{})
		accepted <- s
	}()
	client, err := (muxsession.TLSYamuxConnector{TLSConfig: clientTLS}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "peer.test"})
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("TLS/yamux acceptance failed")
	}
	defer client.Close()
	defer server.Close()
	id := func(prefix string) string {
		t.Helper()
		v, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: id(opaqueid.ServicePrefix), ServiceRunID: id(opaqueid.ServiceRunPrefix),
		RunNumber: 1, PublisherConnectionID: id(opaqueid.PublisherConnectionPrefix), ConnectionSlot: 0,
		ConnectionAssignmentRevision: 1, RelayServiceID: "relay-one"}
	ready := make(chan *tunnel.Session, 1)
	go func() {
		s, _, _ := tunnel.Accept(ctx, server, func(_ context.Context, hello tunnelv1.Message) error {
			if hello.ServiceConnection == nil || *hello.ServiceConnection != ref {
				return errors.New("wrong claimed assignment")
			}
			return nil
		})
		ready <- s
	}()
	publisher, err := tunnel.Dial(ctx, client, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Publisher, Credential: "test-credential", ServiceConnection: &ref})
	if err != nil {
		t.Fatal(err)
	}
	relay := <-ready
	if relay == nil {
		t.Fatal("tunnel authentication failed")
	}
	defer publisher.Close()
	defer relay.Close()
	peers, err := NewDispatchedSharedStreams(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	defer peers.Close()
	d, err := tunnel.NewServiceStreamDispatcher(ctx, publisher, peers)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	a, b := sharedBinding(t, 1, RelayB)
	a.Role, b.Role = 1, 0 // frames sent from the server carry role 1.
	binding, err := peers.Register(b)
	if err != nil {
		t.Fatal(err)
	}
	c, sibling := sharedBinding(t, 2, RelayB)
	c.Role, sibling.Role = 1, 0
	siblingPair, err := peers.Register(sibling)
	if err != nil {
		t.Fatal(err)
	}
	// incomplete peer headers occupy all introduction slots, but not the
	// classifier: a forwarding stream must still be admitted promptly.
	var stalled []muxsession.Stream
	for range 8 {
		stream, err := server.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write([]byte{tunnelv1.Version}); err != nil {
			t.Fatal(err)
		}
		stalled = append(stalled, stream)
	}
	defer func() {
		for _, stream := range stalled {
			_ = stream.Close()
		}
	}()
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID, RunNumber: ref.RunNumber,
		PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision,
		Connector: &tunnelv1.ConnectorAdmission{SessionID: id(opaqueid.ConnectorSessionPrefix),
			Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: id(opaqueid.IdentityPrefix), DeviceID: id(opaqueid.VisitorDevicePrefix)}, GrantRevision: 1},
		SourceIP: "192.0.2.1", VisitorConnectionID: id(opaqueid.VisitorConnectionPrefix), ExpiresAt: time.Now().Add(time.Minute),
	}, ConnectionSlot: ref.ConnectionSlot, RelayServiceID: ref.RelayServiceID, RelayID: "relay-one-process",
		RelayRunID: id(opaqueid.RelayRunPrefix), RelayLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
	wrong, err := server.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	changed := header
	changed.RunNumber++
	if err := tunnelv1.WriteServiceForwardingHeader(wrong, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.AcceptDispatchedServiceForwardingStream(ctx, d); err == nil {
		t.Fatal("dispatcher bypassed claimed forwarding assignment")
	}
	_ = wrong.Close()
	forward, err := server.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer forward.Close()
	wrote := make(chan error, 1)
	go func() { _, err := tunnelv1.WriteServiceOpening(forward, header, []byte("visitor")); wrote <- err }()
	fast, stop := context.WithTimeout(ctx, 700*time.Millisecond)
	defer stop()
	incoming, err := publisher.AcceptDispatchedServiceForwardingStream(fast, d)
	if err != nil {
		t.Fatalf("forwarding behind incomplete peer introductions: %v", err)
	}
	if incoming.Header.ServiceID != header.ServiceID || !bytes.Equal(incoming.TakeInitial(), []byte("visitor")) {
		t.Fatal("forwarding header or opening bytes changed")
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	_ = incoming.Stream().Close()
	// let the stalled introductions time out before sending a valid pair.
	for _, stream := range stalled {
		_ = stream.Close()
	}
	forged, err := server.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	peerHeader, _ := a.Delivery.Header()
	if _, err := forged.Write(peerHeader[:]); err != nil {
		t.Fatal(err)
	}
	badFrame := signedFrame(t, a)
	badFrame[len(badFrame)-1]++
	badWire, err := a.Delivery.Seal(tunnelv1.PeerDeliveryStream, a.Key, badFrame)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnelv1.WritePeerDeliveryFrame(forged, badWire, tunnelv1.PeerDeliveryStream, a.Key); err != nil {
		t.Fatal(err)
	}
	_ = forged.Close()
	quiet, stopQuiet := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stopQuiet()
	if _, err := binding.Accept(quiet); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("invalid first peer frame admitted", err)
	}
	for _, pair := range []struct {
		sender   PairBinding
		receiver *StreamPair
	}{{a, binding}, {c, siblingPair}} {
		peerStream, err := server.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer peerStream.Close()
		first := signedFrame(t, pair.sender)
		peerHeader, _ := pair.sender.Delivery.Header()
		if _, err := peerStream.Write(peerHeader[:]); err != nil {
			t.Fatal(err)
		}
		wire, err := pair.sender.Delivery.Seal(tunnelv1.PeerDeliveryStream, pair.sender.Key, first)
		if err != nil {
			t.Fatal(err)
		}
		if err := tunnelv1.WritePeerDeliveryFrame(peerStream, wire, tunnelv1.PeerDeliveryStream, pair.sender.Key); err != nil {
			t.Fatal(err)
		}
		received, err := pair.receiver.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := received.Receive(ctx); err != nil || !bytes.Equal(got, first) {
			t.Fatalf("peer first frame: %v", err)
		}
		_ = received.Close()
	}
	// unknown and truncated openings close locally without killing siblings.
	for _, raw := range [][]byte{{3}, {0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 1}} {
		s, err := server.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Write(raw); err != nil {
			t.Fatal(err)
		}
		_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.Copy(io.Discard, s); err != nil {
			t.Fatal("invalid stream was not closed", err)
		}
		_ = s.Close()
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if client.Err() != nil || server.Err() != nil {
		t.Fatal("dispatcher shutdown closed outer session")
	}
}
