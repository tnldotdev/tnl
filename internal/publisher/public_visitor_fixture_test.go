package publisher

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var testPublicVisitorSourceKey = [32]byte{1}
var testPublicVisitorSourceSequence atomic.Uint64

func testVisitorSourceKeyBytes() *[]byte {
	key := testPublicVisitorSourceKey
	return new(key[:])
}

func testPublicStreamHeader(route *PublicURLServer, header tunnelv1.VisitorStreamHeader) tunnelv1.VisitorStreamHeader {
	if header.PublicURLID == "" {
		header.PublicURLID = route.run.PublicURLID
	}
	if header.PublishRunID == "" {
		header.PublishRunID = route.run.PublishRunID
	}
	if header.PublishRunNumber == 0 {
		header.PublishRunNumber = route.run.Number
	}
	if header.VisitorConnectionID == "" {
		header.VisitorConnectionID = "test-visitor"
	}
	return header
}

func encodeTestPublicMetadata(route *PublicURLServer, header tunnelv1.VisitorStreamHeader, metadata proxyproto.Header) ([]byte, error) {
	header = testPublicStreamHeader(route, header)
	view, _, _ := route.policy.Current()
	now := view.AuthorityTime(time.Now())
	until := view.AuthorityTime(view.ValidUntil)
	return encodeTestPublicSource(route.visitorSourceKey, header, view.VisitorPolicyRevision, now, until, metadata)
}

func encodeTestPublicSource(master [32]byte, header tunnelv1.VisitorStreamHeader, revision int64, now, until time.Time, metadata proxyproto.Header) ([]byte, error) {
	authority, key, err := visitortoken.IssueVisitorSourceAuthority(master, tunnelv1.VisitorSourceAuthority{
		PublicURLID: header.PublicURLID, PublishRunID: header.PublishRunID, PublishRunNumber: header.PublishRunNumber,
		IngressID: "fixture-ingress", IngressRunID: "fixture-process", IngressLeaseRevision: 1,
		VisitorPolicyRevision: revision, ValidUntil: until.Unix(),
	}, now)
	if err != nil {
		return nil, err
	}
	proof, err := visitortoken.SignVisitorSource(key, authority, testPublicVisitorSourceSequence.Add(1), tunnelv1.VisitorSourceBinding{
		PublicURLID: header.PublicURLID, PublishRunID: header.PublishRunID, PublishRunNumber: header.PublishRunNumber,
		VisitorID: header.VisitorConnectionID, Source: metadata.Source, Destination: metadata.Destination,
	}, now)
	if err != nil {
		return nil, err
	}
	wire, err := proof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	metadata.VisitorSourceProof = string(wire)
	return proxyproto.Encode(metadata)
}

// http and policy fixtures omit the relay wire, but use the same run-owned
// reservation, commit, timer, and retirement as production visitor connections.
func reserveTestPublicSetup(route *PublicURLServer, connection net.Conn) (*publicVisitorAdmission, error) {
	route.mu.Lock()
	live := route.sessions[0]
	if live == nil {
		live = &livePublisherSession{ctx: route.life, ref: tunnelv1.PublisherConnectionRef{RelayServiceID: "fixture-relay"}}
		route.sessions[0] = live
	}
	route.mu.Unlock()
	a, code := route.reservePublicSetup(live, connection)
	if code != "" {
		return nil, &tunnel.ProtocolError{Code: code}
	}
	return a, nil
}

func serveTestPublicVisitor(t *testing.T, route *PublicURLServer, connection net.Conn, header tunnelv1.VisitorStreamHeader) {
	t.Helper()
	a, err := reserveTestPublicSetup(route, connection)
	if err != nil {
		_ = connection.Close()
		t.Error(err)
		return
	}
	route.handleVisitor(route.life, a, testPublicStreamHeader(route, header), nil, nil)
}

func ownTestVisitorSession(t *testing.T, route *PublicURLServer, session *visitorSession) func() {
	t.Helper()
	connection, peer := net.Pipe()
	a, err := reserveTestPublicSetup(route, connection)
	if err != nil {
		_ = connection.Close()
		_ = peer.Close()
		t.Fatal(err)
	}
	session.capacity = a
	if session.life == nil {
		session.life, session.cancel = context.WithCancel(route.life)
	}
	return func() {
		session.close()
		a.retire()
		_ = peer.Close()
	}
}

func serveTestPublicRequest(t *testing.T, route *PublicURLServer, response http.ResponseWriter, request *http.Request) {
	t.Helper()
	session, _ := request.Context().Value(visitorSessionKey{}).(*visitorSession)
	if session == nil {
		source, err := netip.ParseAddrPort(request.RemoteAddr)
		if err != nil {
			t.Fatal(err)
		}
		session = &visitorSession{visitor: Visitor{Run: route.run, Source: source}, guard: route.guard, promote: route.promote}
	}
	if session.capacity == nil {
		defer ownTestVisitorSession(t, route, session)()
	}
	request = request.WithContext(context.WithValue(request.Context(), visitorSessionKey{}, session))
	route.http.Handler.ServeHTTP(response, request)
}
