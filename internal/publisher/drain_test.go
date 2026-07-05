package publisher

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestSessionVisitorDrain(t *testing.T) {
	previous := heartbeatInterval
	heartbeatInterval = 20 * time.Millisecond
	defer func() { heartbeatInterval = previous }()
	for _, test := range []struct {
		transport string
		stop      string
	}{
		{"quic", "parent_cancel"},
		{"tls_yamux", "parent_cancel"},
		{"tls_yamux", "drain_deadline"},
		{"tls_yamux", "stale_session"},
		{"tls_yamux", "unauthenticated"},
		{"tls_yamux", "certificate_expired"},
		{"tls_yamux", "certificate_expired_while_draining"},
	} {
		t.Run(test.transport+"/"+test.stop, func(t *testing.T) {
			transport, stop := test.transport, test.stop
			ctx, finish := context.WithTimeout(t.Context(), 10*time.Second)
			defer finish()
			entered, release, upstreamDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			body := strings.Repeat("complete visitor response\n", 32768)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(upstreamDone)
				close(entered)
				select {
				case <-release:
					_, _ = io.WriteString(w, body)
				case <-r.Context().Done():
				}
			}))
			defer upstream.Close()
			control := newCertificateTestControl(t, "route.example", routeCertificateTestPlan())
			control.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
			if strings.HasPrefix(stop, "certificate_expired") {
				control.change = func(issuance *controlv1.CertificateIssuance, leaf *x509.Certificate) {
					leaf.NotAfter = time.Now().Add(2 * time.Second).UTC().Truncate(time.Second)
					issuance.NotAfter = pointer(leaf.NotAfter)
				}
				issued := false
				control.create = func(csr []byte, _ string) (controlv1.CertificateIssuance, error) {
					if issued {
						return controlv1.CertificateIssuance{}, controlclient.ErrUnavailable
					}
					issued = true
					return control.issue(csr)
				}
			}
			connector, relays, publishers := drainTestConnections(t, ctx, control, transport)
			failHeartbeat := make(chan struct{})
			control.heartbeat = func(context.Context, string, uint64, credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error) {
				select {
				case <-failHeartbeat:
					if stop == "unauthenticated" {
						return controlv1.RouteSessionHeartbeat{}, controlclient.ErrUnauthenticated
					}
					return controlv1.RouteSessionHeartbeat{}, controlclient.ErrStatusConflict
				default:
					return controlv1.RouteSessionHeartbeat{RouteSession: control.setup.RouteSession}, nil
				}
			}
			ready, draining := make(chan struct{}), make(chan struct{})
			config := Config{Control: control, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1", RouteScope: controlv1.Member,
				Hostname: "route.example", Target: upstream.URL, State: control.store, QUICConnector: connector, TCPConnector: connector,
				FallbackDelay: time.Hour, DrainTime: 5 * time.Second, ProvisioningStalledDelay: time.Hour,
				Observe: func(event Event) error {
					if event.Type == EventDraining {
						close(draining)
					}
					return nil
				},
			}
			if stop == "drain_deadline" {
				config.DrainTime = 50 * time.Millisecond
			}
			sessionCtx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() {
				done <- runSession(sessionCtx, config, control.setup, func() error { close(ready); return nil })
			}()
			finished := false
			defer func() {
				cancel()
				unblock()
				if !finished {
					select {
					case <-done:
					case <-ctx.Done():
						t.Error("publisher goroutines did not finish")
					}
				}
			}()
			select {
			case <-ready:
			case err := <-done:
				finished = true
				t.Fatalf("session did not become ready: %v", err)
			case <-ctx.Done():
				t.Fatal("session readiness timed out")
			}
			activeRelay := <-relays
			standbyRelay := <-relays
			publisherTransports := []muxsession.Session{<-publishers, <-publishers}
			if activeRelay.err != nil || standbyRelay.err != nil {
				t.Fatalf("relay handshake: %v, %v", activeRelay.err, standbyRelay.err)
			}
			stream, err := activeRelay.connection.OpenVisitor(ctx, "visitor_drain")
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.1:4321"), Destination: netip.MustParseAddrPort("127.0.0.1:443")})
			if err != nil {
				t.Fatal(err)
			}
			responseDone := make(chan error, 1)
			startVisitor := func() {
				if _, err := stream.Write(metadata); err != nil {
					t.Fatal(err)
				}
				visitor := tls.Client(stream, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, control.signer)})
				request := "GET / HTTP/1.1\r\nHost: route.example\r\nConnection: close\r\n\r\n"
				if stop == "parent_cancel" {
					request = "GET / HTTP/1.1\r\nHost: route.example\r\n\r\n"
				}
				if _, err := io.WriteString(visitor, request); err != nil {
					t.Fatal(err)
				}
				go func() {
					reader := bufio.NewReader(visitor)
					response, err := http.ReadResponse(reader, nil)
					if err == nil {
						var got []byte
						got, err = io.ReadAll(response.Body)
						_ = response.Body.Close()
						if err == nil && (response.StatusCode != http.StatusOK || string(got) != body) {
							err = fmt.Errorf("incomplete response: status=%d bytes=%d", response.StatusCode, len(got))
						}
						if err == nil && stop == "parent_cancel" {
							if _, readErr := reader.ReadByte(); !errors.Is(readErr, io.EOF) {
								err = fmt.Errorf("idle visitor remained open after drain: %w", readErr)
							}
							_ = visitor.Close()
						}
					}
					responseDone <- err
				}()
				select {
				case <-entered:
				case err := <-responseDone:
					t.Fatalf("visitor completed before reaching local service: %v", err)
				case <-ctx.Done():
					t.Fatal("visitor did not reach local service")
				}
			}
			if stop != "parent_cancel" {
				startVisitor()
			}
			if stop == "stale_session" || stop == "unauthenticated" {
				close(failHeartbeat)
			} else if stop != "certificate_expired" {
				cancel()
				select {
				case <-draining:
				case <-ctx.Done():
					t.Fatal("normal cancellation did not enter drain")
				}
				if stop == "parent_cancel" || strings.HasSuffix(stop, "while_draining") {
					admitted, err := activeRelay.connection.OpenVisitor(ctx, "visitor_after_cancel")
					if err == nil {
						_ = admitted.Close()
						t.Fatal("draining session admitted a new visitor")
					}
					var rejected *tunnel.ProtocolError
					if !errors.Is(err, relay.ErrDraining) && (!errors.As(err, &rejected) || rejected.Code != tunnelv1.Unavailable) {
						t.Fatalf("drain closed transport instead of rejecting admission: %v", err)
					}
				}
			}
			if stop == "parent_cancel" {
				startVisitor()
				unblock()
			}
			select {
			case err := <-responseDone:
				if (err == nil) != (stop == "parent_cancel") {
					t.Errorf("visitor response after %s: %v", stop, err)
				}
			case <-ctx.Done():
				t.Fatal("visitor response goroutine leaked")
			}
			_ = stream.Close()
			select {
			case err := <-done:
				finished = true
				if stop == "parent_cancel" && err != nil || stop == "drain_deadline" && !errors.Is(err, context.DeadlineExceeded) ||
					stop == "stale_session" && !errors.Is(err, controlclient.ErrStatusConflict) || stop == "unauthenticated" && !errors.Is(err, controlclient.ErrUnauthenticated) ||
					strings.HasPrefix(stop, "certificate_expired") && !errors.Is(err, errCertificateExpired) {
					t.Errorf("session result after %s: %v", stop, err)
				}
			case <-ctx.Done():
				t.Fatal("session goroutines leaked")
			}
			for _, transport := range publisherTransports {
				select {
				case <-transport.Done():
				default:
					t.Error("publisher transport leaked after session returned")
				}
			}
			select {
			case <-upstreamDone:
			case <-ctx.Done():
				t.Fatal("upstream handler leaked")
			}
		})
	}
}

type drainTestRelay struct {
	connection *relay.PublisherConnection
	err        error
}

func drainTestConnections(t *testing.T, ctx context.Context, control *certificateTestControl, kind string) (muxsession.Connector, <-chan drainTestRelay, <-chan muxsession.Session) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	certificate := routeTestCertificate(t, "relay.example")
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}}
	clientTLS := &tls.Config{RootCAs: rootsForCertificate(t, certificate)}
	relays, publishers := make(chan drainTestRelay, 2), make(chan muxsession.Session, 2)
	var connector muxsession.Connector
	var listeners []io.Closer
	var workers sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		workers.Wait()
	})
	for slot := range 2 {
		var address string
		var accept func() (muxsession.Session, error)
		if kind == "quic" {
			listener, err := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, muxsession.QUICConfig{})
			if err != nil {
				t.Fatal(err)
			}
			listeners = append(listeners, listener)
			address = listener.Addr().String()
			accept = func() (muxsession.Session, error) { return listener.Accept(ctx) }
			connector = muxsession.QUICConnector{TLSConfig: clientTLS}
		} else {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listeners = append(listeners, listener)
			address = listener.Addr().String()
			accept = func() (muxsession.Session, error) {
				connection, err := listener.Accept()
				if err != nil {
					return nil, err
				}
				return muxsession.AcceptTLSYamux(ctx, connection, serverTLS, muxsession.TLSYamuxConfig{})
			}
			connector = muxsession.TLSYamuxConnector{TLSConfig: clientTLS}
		}
		control.setup.PublisherConnections = append(control.setup.PublisherConnections, controlv1.ConnectionAssignment{
			ConnectionSlot: slot, ConnectionAssignmentRevision: 1, PublisherConnectionId: fmt.Sprintf("drain_connection_%d", slot),
			PublisherConnectionCredential: "test-credential", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Hour),
			RelayServiceId: fmt.Sprintf("relay_service_%d", slot), RelayAddress: address, TlsServerName: "relay.example", State: controlv1.PublisherConnectionStateAssigned,
		})
		workers.Go(func() {
			transport, err := accept()
			if err != nil {
				relays <- drainTestRelay{err: err}
				return
			}
			defer transport.Close()
			stop := context.AfterFunc(ctx, func() { _ = transport.Close() })
			defer stop()
			session, hello, err := tunnel.Accept(ctx, transport, func(context.Context, tunnelv1.Message) error { return nil })
			if err != nil {
				relays <- drainTestRelay{err: err}
				return
			}
			ref := *hello.PublisherConnection
			connection, err := relay.NewPublisherConnection(ref, relayv1.ClaimedPublisherConnection{
				ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision), ConnectionSlot: int(ref.ConnectionSlot),
				PublisherConnectionId: ref.PublisherConnectionID, RelayId: "relay_1", RelayLeaseRevision: 1,
				RelayRunId: "relay_run_1", RelayServiceId: ref.RelayServiceID, RouteId: ref.RouteID,
				RouteSessionId: ref.RouteSessionID, RouteVersion: int64(ref.RouteVersion),
			}, session)
			if err != nil {
				relays <- drainTestRelay{err: err}
				return
			}
			defer connection.Close()
			relays <- drainTestRelay{connection: connection}
			if err := session.HandlePublisherDrain(ctx, connection.Drain); err == nil {
				select {
				case <-ctx.Done():
				case <-session.Done():
				}
			}
		})
	}
	return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		transport, err := connector.Connect(ctx, endpoint)
		if err == nil {
			publishers <- transport
		}
		return transport, err
	}), relays, publishers
}
