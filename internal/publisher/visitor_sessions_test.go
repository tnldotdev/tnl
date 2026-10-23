package publisher

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func promotionSessionPair(t *testing.T, ref tunnelv1.PublisherConnectionRef) (*tunnel.Session, *tunnel.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	certificate := publicURLTestCertificate(t, "relay.example")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	type accepted struct {
		session *tunnel.Session
		err     error
	}
	result := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			result <- accepted{err: err}
			return
		}
		transport, err := muxsession.AcceptTLSYamux(ctx, c, &tls.Config{Certificates: []tls.Certificate{certificate}}, muxsession.TLSYamuxConfig{})
		if err != nil {
			_ = c.Close()
			result <- accepted{err: err}
			return
		}
		s, _, err := tunnel.Accept(ctx, transport, func(context.Context, tunnelv1.Message) error { return nil })
		result <- accepted{session: s, err: err}
	}()
	transport, err := (muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{RootCAs: rootsForCertificate(t, certificate)}}).Connect(ctx, muxsession.Endpoint{Address: l.Addr().String(), ServerName: "relay.example"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	publisher, err := tunnel.Dial(ctx, transport, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher, Credential: "test-credential", PublisherConnection: &ref})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publisher.Close() })
	relay := awaitPublisherTest(t, result)
	if relay.err != nil {
		t.Fatal(relay.err)
	}
	t.Cleanup(func() { _ = relay.session.Close() })
	return publisher, relay.session
}

func TestAutomaticPromotionUsesExactCurrentStreamWithoutAck(t *testing.T) {
	ref := tunnelv1.PublisherConnectionRef{PublicURLID: "url-1", PublishRunID: "run-1", PublishRunNumber: 1, PublisherConnectionID: "connection-1", ConnectionAssignmentRevision: 1, RelayServiceID: "relay-1"}
	publisher, relay := promotionSessionPair(t, ref)
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", PublicURLID: ref.PublicURLID, PublishRunID: ref.PublishRunID, PublishRunNumber: ref.PublishRunNumber, Handler: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	live, err := route.registerPublisherSession(t.Context(), publisher, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer route.unregisterPublisherSession(live)
	decision, entered := make(chan struct{}), make(chan struct{})
	ctx := t.Context()
	accepted := make(chan *tunnel.IncomingVisitorStream, 1)
	worker := make(chan error, 1)
	go func() {
		incoming, err := publisher.AcceptVisitorStream(ctx)
		if err == nil {
			err = incoming.Accept()
			accepted <- incoming
		}
		worker <- err
	}()
	h := tunnelv1.VisitorStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream, VisitorConnectionID: "visitor-1", PublicURLID: ref.PublicURLID, PublishRunID: ref.PublishRunID, PublishRunNumber: ref.PublishRunNumber, PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision, AccessPending: true}
	stream, err := relay.StartVisitorStream(ctx, h, nil, &tunnel.ReturnEvents{Promoted: func(h tunnelv1.AdmissionHeader) error {
		if h.PublisherConnectionID != ref.PublisherConnectionID || h.PublishRunID != ref.PublishRunID || h.ConnectionAssignmentRevision != ref.ConnectionAssignmentRevision {
			t.Error("promotion changed stream identity")
		}
		close(entered)
		select {
		case <-decision:
			return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
		case <-ctx.Done():
			return ctx.Err()
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	incoming := awaitPublisherTest(t, accepted)
	t.Cleanup(func() { _ = incoming.Stream.Close() })
	if err := awaitPublisherTest(t, worker); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() { _, err := stream.Read(make([]byte, 1)); read <- err }()
	result := make(chan error, 1)
	go func() { result <- route.promoteVisitorStream(ctx, Visitor{Header: h}, incoming.Stream) }()
	awaitPublisherTest(t, entered)
	if err := awaitPublisherTest(t, result); err != nil {
		t.Fatal(err)
	}
	close(decision)
	var rejection *tunnel.ProtocolError
	if err := awaitPublisherTest(t, read); !errors.As(err, &rejection) || rejection.Code != tunnelv1.CapacityExceeded {
		t.Fatal("return-side rejection was not isolated from visitor TLS", err)
	}
	h.PublisherConnectionID = "replacement-connection"
	if err := route.promoteVisitorStream(ctx, Visitor{Header: h}, incoming.Stream); err == nil {
		t.Fatal("old visitor resolved a different publisher connection")
	}
	if route.resolvePublisherSession(ref.PublisherConnectionID) != publisher {
		t.Fatal("current session disappeared")
	}
	route.unregisterPublisherSession(live)
	if route.resolvePublisherSession(ref.PublisherConnectionID) != nil {
		t.Fatal("ended session remained promotable")
	}
	h.PublisherConnectionID = ref.PublisherConnectionID
	if err := route.promoteVisitorStream(ctx, Visitor{Header: h}, incoming.Stream); err == nil {
		t.Fatal("ended session retained a usable notification capability")
	}
}

func TestPublisherSessionReplacementCancelsOldLifetime(t *testing.T) {
	ref := tunnelv1.PublisherConnectionRef{PublicURLID: "url-1", PublishRunID: "run-1", PublishRunNumber: 1, PublisherConnectionID: "connection-1", ConnectionAssignmentRevision: 1, RelayServiceID: "relay-1"}
	publisher, _ := promotionSessionPair(t, ref)
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Handler: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	old, err := route.registerPublisherSession(t.Context(), publisher, ref)
	if err != nil {
		t.Fatal(err)
	}
	ref.PublisherConnectionID = "connection-2"
	ref.ConnectionAssignmentRevision++
	replacement, _ := promotionSessionPair(t, ref)
	current, err := route.registerPublisherSession(t.Context(), replacement, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer route.unregisterPublisherSession(current)
	if !errors.Is(old.ctx.Err(), context.Canceled) || route.resolvePublisherSession("connection-1") != nil {
		t.Fatal("replacement retained old session admission")
	}
	route.unregisterPublisherSession(old)
	if route.resolvePublisherSession("connection-2") != replacement {
		t.Fatal("old session cleanup removed its replacement")
	}
	_ = route.Close()
	if current.ctx.Err() == nil {
		t.Fatal("engine close did not cancel publisher session lifetime")
	}
}

func TestPromotedDeniedHTTPResponseOutlivesPendingDeadline(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			accessClient := &shareAccessTestClient{shareID: "shr_0123456789abcdefghijkl", cookie: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32))), active: true, minted: true}
			access := &shareAccess{client: accessClient, runID: "run-1", version: 1}
			if err := access.refresh(t.Context()); err != nil {
				t.Fatal(err)
			}
			var promoted atomic.Int32
			route, err := newTestPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Certificate: publicURLTestCertificate(t, "route.example"), ShareAccess: access,
				PromoteVisitor: func(context.Context, Visitor) error { promoted.Add(1); return nil },
				Handler:        http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { time.Sleep(6 * time.Second); w.WriteHeader(204) })})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = route.Close() })
			if err := route.Start(); err != nil {
				t.Fatal(err)
			}
			client := mixedVisitorClient(t, route, h2, true)
			client.Timeout = 12 * time.Second
			r, _ := http.NewRequest("GET", "https://route.example/", nil)
			r.AddCookie(&http.Cookie{Name: shareCookieName, Value: accessClient.shareID + "." + accessClient.cookie})
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != 204 || promoted.Load() != 1 {
				t.Fatalf("status=%d promotion=%d", response.StatusCode, promoted.Load())
			}
			response, err = client.Get("https://route.example/")
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != 403 || promoted.Load() != 1 {
				t.Fatalf("cached promotion bypassed this request's permission: status=%d promotion=%d", response.StatusCode, promoted.Load())
			}
		})
	}
}
