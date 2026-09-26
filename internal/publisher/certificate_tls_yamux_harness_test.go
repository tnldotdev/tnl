package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// This harness starts real local HTTP, TLS and yamux servers. Synctest
// certificate tests use certificateTestTransport instead.
func startCertificateTLSYamuxHarness(t *testing.T, control *certificateTestControl) Config {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(upstream.Close)
	control.setup.PublicUrl.Target = upstream.URL
	control.routes = []controlv1.PublicURL{control.setup.PublicUrl}
	certificate := publicURLTestCertificate(t, "relay.example")
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	var listeners []net.Listener
	t.Cleanup(func() {
		cancel()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		joined := make(chan struct{})
		go func() { workers.Wait(); close(joined) }()
		awaitPublisherTest(t, joined)
	})
	for slot := range 2 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		control.setup.PublisherConnections = append(control.setup.PublisherConnections, controlv1.ConnectionAssignment{
			ConnectionSlot: slot, ConnectionAssignmentRevision: 1, PublisherConnectionId: fmt.Sprintf("connection_%d", slot),
			PublisherConnectionCredential: "test-credential", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Hour),
			RelayServiceId: fmt.Sprintf("relay_service_%d", slot), RelayAddress: listener.Addr().String(), TlsServerName: "relay.example", State: controlv1.PublisherConnectionStateAssigned,
		})
		workers.Go(func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Go(func() {
					defer connection.Close()
					stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
					defer stop()
					transport, err := muxsession.AcceptTLSYamux(ctx, connection, &tls.Config{Certificates: []tls.Certificate{certificate}}, muxsession.TLSYamuxConfig{})
					if err != nil {
						return
					}
					defer transport.Close()
					session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, hello tunnelv1.Message) error {
						if hello.Role != tunnelv1.Publisher || hello.Credential != "test-credential" || hello.PublisherConnection == nil || hello.PublisherConnection.ConnectionSlot != uint8(slot) {
							return errors.New("unexpected publisher hello")
						}
						return nil
					})
					if err != nil {
						return
					}
					defer session.Close()
					if err := session.HandlePublisherDrain(ctx, func(context.Context) error { return nil }); err == nil {
						select {
						case <-ctx.Done():
						case <-transport.Done():
						}
					}
				})
			}
		})
	}
	return Config{
		Control: control, State: control.store, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1", PublicURLScope: controlv1.Member,
		Hostname: control.setup.PublicUrl.CanonicalHostname, Target: upstream.URL, FallbackDelay: time.Millisecond, DrainTime: time.Second,
		QUICConnector: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
			return nil, errors.New("test uses TLS/yamux")
		}),
		TCPConnector: muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{RootCAs: rootsForCertificate(t, certificate)}},
	}
}
