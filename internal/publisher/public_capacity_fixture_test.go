package publisher

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type publicCapacityFixture struct {
	t           *testing.T
	ctx         context.Context
	route       *PublicURLServer
	policy      *visitorlease.Lease
	update      visitorlease.Update
	token       visitortoken.Token
	allocation  controlv1.StreamCapacityAllocation
	certificate tls.Certificate
	refs        [2]tunnelv1.PublisherConnectionRef
	relays      [2]*tunnel.Session
	finished    [2]<-chan error
	metadata    []byte
}

func newPublicCapacityFixture(t *testing.T, capacity int, handler http.Handler) *publicCapacityFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	policy, update, token := httpPermissionFixture(t, false)
	first := tunnelv1.PublisherConnectionRef{PublicURLID: update.View.Scope.ID, PublishRunID: "pr_0123456789abcdefghijkl", PublishRunNumber: 1, PublisherConnectionID: "domain-a", RelayServiceID: "relay-a", ConnectionAssignmentRevision: 1}
	second := first
	second.ConnectionSlot, second.PublisherConnectionID, second.RelayServiceID = 1, "domain-b", "relay-b"
	allocation := testPublicAllocations(controlv1.PublisherVisitorPolicyRequest{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: first.PublicURLID}, RunId: first.PublishRunID, RunNumber: 1}, time.Now())[0]
	allocation.Capacity = capacity
	update.Allocations = map[string]controlv1.StreamCapacityAllocation{allocation.Id: allocation}
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	certificate := publicURLTestCertificate(t, update.View.Hostname)
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: update.View.Hostname, PublicURLID: first.PublicURLID, PublishRunID: first.PublishRunID, PublishRunNumber: 1, StreamCapacity: capacity, VisitorPolicy: policy, Certificate: certificate, Target: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	if err := route.Start(); err != nil {
		t.Fatal(err)
	}
	metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("127.0.0.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	f := &publicCapacityFixture{t: t, ctx: ctx, route: route, policy: policy, update: update, token: token, allocation: allocation, certificate: certificate, refs: [2]tunnelv1.PublisherConnectionRef{first, second}, metadata: metadata}
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

func (f *publicCapacityFixture) open(index int, slot uint32, sequence uint64, claimed ...int) (muxsession.Stream, error) {
	return f.openAllocation(f.allocation, index, slot, sequence, claimed...)
}

func (f *publicCapacityFixture) openAllocation(allocation controlv1.StreamCapacityAllocation, index int, slot uint32, sequence uint64, claimed ...int) (muxsession.Stream, error) {
	ref := f.refs[index]
	if len(claimed) != 0 {
		ref = f.refs[claimed[0]]
	}
	reservation := testPublicStreamReservation(ref, slot)
	reservation.AllocationID = allocation.Id
	reservation.IngressID, reservation.IngressRunID = allocation.IngressId, allocation.IngressRunId
	reservation.IngressLeaseRevision = uint64(allocation.IngressLeaseRevision)
	reservation.Sequence = sequence
	reservation.VisitorConnectionID = fmt.Sprintf("vc_%022d", sequence*100+uint64(slot))
	if err := visitortoken.SignReservation(allocation.ReservationKey, &reservation, netip.MustParseAddr("192.0.2.1")); err != nil {
		return nil, err
	}
	stream, err := f.relays[index].StartVisitorStream(f.ctx, tunnelv1.VisitorStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream, VisitorConnectionID: reservation.VisitorConnectionID, Reservation: reservation, PublicURLID: ref.PublicURLID, PublishRunID: ref.PublishRunID, PublishRunNumber: ref.PublishRunNumber, PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision}, nil, nil)
	if err == nil {
		_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
		f.t.Cleanup(func() { _ = stream.Close() })
	}
	return stream, err
}

func (f *publicCapacityFixture) secure(stream muxsession.Stream) (*tls.Conn, error) {
	if _, err := stream.Write(f.metadata); err != nil {
		return nil, err
	}
	client := tls.Client(stream, &tls.Config{RootCAs: rootsForCertificate(f.t, f.certificate), ServerName: f.update.View.Hostname})
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	return client, client.HandshakeContext(f.ctx)
}

func (f *publicCapacityFixture) request(stream muxsession.Stream, path string) (*http.Response, error) {
	client, err := f.secure(stream)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(client, "GET %s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\nConnection: close\r\n\r\n", path, f.update.View.Hostname, visitorTokenHeader, f.token.Reveal()); err != nil {
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
