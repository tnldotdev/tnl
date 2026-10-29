package publisher

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type publicCapacityFixture struct {
	t        *testing.T
	ctx      context.Context
	route    *PublicURLServer
	refs     [2]tunnelv1.PublisherConnectionRef
	relays   [2]*tunnel.Session
	finished [2]<-chan error
	sequence atomic.Int64
}

type publicCapacityStream struct {
	muxsession.Stream
	metadata []byte
	header   tunnelv1.VisitorStreamHeader
}

func (f *publicCapacityFixture) metadataFor(stream net.Conn) []byte {
	return stream.(*publicCapacityStream).metadata
}

func newPublicCapacityFixture(t *testing.T, capacity int, handler http.Handler, configure ...func(*PublicURLServerConfig)) *publicCapacityFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	first := tunnelv1.PublisherConnectionRef{PublicURLID: certificateTestPublicURLID, PublishRunID: "run-1", PublishRunNumber: 1, PublisherConnectionID: "connection-a", RelayServiceID: "relay-a", ConnectionAssignmentRevision: 1}
	second := first
	second.ConnectionSlot, second.PublisherConnectionID, second.RelayServiceID = 1, "connection-b", "relay-b"
	config := PublicURLServerConfig{Hostname: "route.example", PublicURLID: first.PublicURLID, PublishRunID: first.PublishRunID, PublishRunNumber: 1,
		StreamCapacity: capacity, Certificate: publicURLTestCertificate(t, "route.example"), Handler: handler}
	for _, apply := range configure {
		apply(&config)
	}
	first.PublicURLID, first.PublishRunID, first.PublishRunNumber = config.PublicURLID, config.PublishRunID, config.PublishRunNumber
	second.PublicURLID, second.PublishRunID, second.PublishRunNumber = config.PublicURLID, config.PublishRunID, config.PublishRunNumber
	route, err := newTestPublicURLServer(t, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	f := &publicCapacityFixture{t: t, ctx: ctx, route: route, refs: [2]tunnelv1.PublisherConnectionRef{first, second}}
	f.connect(0)
	f.connect(1)
	return f
}

func (f *publicCapacityFixture) connect(index int) {
	f.t.Helper()
	ref := f.refs[index]
	publisher, relay := promotionSessionPair(f.t, ref)
	f.relays[index] = relay
	done := make(chan error, 1)
	f.finished[index] = done
	go func() { done <- f.route.ServePublisherConnection(f.ctx, publisher, ref); close(done) }()
	f.t.Cleanup(func() { _ = publisher.Close(); awaitPublisherTest(f.t, done) })
}

func (f *publicCapacityFixture) open(index int, denied bool, claimed ...int) (muxsession.Stream, error) {
	ref := f.refs[index]
	if len(claimed) != 0 {
		ref = f.refs[claimed[0]]
	}
	header := tunnelv1.VisitorStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream,
		VisitorConnectionID: fmt.Sprintf("visitor-%d", f.sequence.Add(1)), PublicURLID: ref.PublicURLID, PublishRunID: ref.PublishRunID,
		PublishRunNumber: ref.PublishRunNumber, PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision, AccessPending: denied}
	stream, err := f.relays[index].OpenVisitorStream(f.ctx, header)
	if err == nil {
		metadata, sourceErr := encodeTestPublicMetadata(f.route, header, proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("127.0.0.1:443")})
		if sourceErr != nil {
			_ = stream.Close()
			return nil, sourceErr
		}
		stream = &publicCapacityStream{Stream: stream, metadata: metadata, header: header}
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		f.t.Cleanup(func() { _ = stream.Close() })
	}
	return stream, err
}

func (f *publicCapacityFixture) secure(stream net.Conn, protocols ...string) (*tls.Conn, error) {
	if _, err := stream.Write(f.metadataFor(stream)); err != nil {
		return nil, err
	}
	client := tls.Client(stream, &tls.Config{RootCAs: rootsForCertificate(f.t, *f.route.certificate.Load()), ServerName: "route.example", NextProtos: protocols})
	return client, client.HandshakeContext(f.ctx)
}

func (f *publicCapacityFixture) request(stream net.Conn, path string, token ...string) (*http.Response, error) {
	client, err := f.secure(stream)
	if err != nil {
		return nil, err
	}
	return capacityRequest(client, path, true, token...)
}

func capacityRequest(client net.Conn, path string, closeConnection bool, token ...string) (*http.Response, error) {
	connection := "keep-alive"
	if closeConnection {
		connection = "close"
	}
	credential := ""
	if len(token) != 0 {
		credential = visitorTokenHeader + ": " + token[0] + "\r\n"
	}
	if _, err := fmt.Fprintf(client, "GET %s HTTP/1.1\r\nHost: route.example\r\nConnection: %s\r\n%s\r\n", path, connection, credential); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(client), nil)
}

func (f *publicCapacityFixture) wait(pending, authorized int) {
	f.t.Helper()
	for {
		f.route.mu.Lock()
		p, a := f.route.pendingStreams, f.route.authorizedStreams
		f.route.mu.Unlock()
		if p == pending && a == authorized {
			return
		}
		select {
		case <-f.ctx.Done():
			f.t.Fatalf("stream state pending=%d authorized=%d, want %d/%d", p, a, pending, authorized)
		case <-time.After(time.Millisecond):
		}
	}
}
