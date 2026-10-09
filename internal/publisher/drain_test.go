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
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestSessionParentCancellationDrainsAdmittedVisitor(t *testing.T) {
	for _, transport := range []string{"quic", "tls_yamux"} {
		t.Run(transport, func(t *testing.T) {
			h := newVisitorDrainHarness(t, transport, nil)
			stream := h.admit()
			h.cancel()
			awaitPublisherTest(t, h.draining)
			h.assertAdmissionRejected()
			response := h.startVisitor(stream, true)
			h.unblock()
			if err := awaitPublisherTest(t, response); err != nil {
				t.Fatalf("admitted visitor did not finish: %v", err)
			}
			h.assertFinished(nil)
		})
	}
}

func TestSessionDrainDeadlineClosesActiveVisitor(t *testing.T) {
	h := newVisitorDrainHarness(t, "tls_yamux", func(_ *certificateTestControl, config *Config) { config.DrainTime = 50 * time.Millisecond })
	response := h.startVisitor(h.admit(), false)
	h.cancel()
	awaitPublisherTest(t, h.draining)
	if err := awaitPublisherTest(t, response); err == nil {
		t.Fatal("visitor completed despite drain deadline")
	}
	h.assertFinished(context.DeadlineExceeded)
}

func TestSessionStaleHeartbeatClosesActiveVisitor(t *testing.T) {
	assertHeartbeatFailureClosesVisitor(t, controlclient.ErrStatusConflict)
}

func TestSessionUnauthenticatedHeartbeatClosesActiveVisitor(t *testing.T) {
	assertHeartbeatFailureClosesVisitor(t, controlclient.ErrUnauthenticated)
}

func assertHeartbeatFailureClosesVisitor(t *testing.T, failure error) {
	t.Helper()
	fail := make(chan struct{})
	h := newVisitorDrainHarness(t, "tls_yamux", func(control *certificateTestControl, _ *Config) {
		control.heartbeat = func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
			select {
			case <-fail:
				return controlv1.PublishRunHeartbeat{}, failure
			default:
				return controlv1.PublishRunHeartbeat{PublishRun: control.setup.PublishRun}, nil
			}
		}
	})
	response := h.startVisitor(h.admit(), false)
	close(fail)
	if err := awaitPublisherTest(t, response); err == nil {
		t.Fatal("visitor completed after heartbeat rejection")
	}
	h.assertFinished(failure)
}

func TestSessionCertificateExpirationClosesActiveVisitor(t *testing.T) {
	h := newVisitorDrainHarness(t, "tls_yamux", expireDrainCertificate)
	response := h.startVisitor(h.admit(), false)
	if err := awaitPublisherTest(t, response); err == nil {
		t.Fatal("visitor completed after certificate expiration")
	}
	h.assertFinished(errCertificateExpired)
}

func TestSessionCertificateExpirationInterruptsDrain(t *testing.T) {
	h := newVisitorDrainHarness(t, "tls_yamux", expireDrainCertificate)
	response := h.startVisitor(h.admit(), false)
	h.cancel()
	awaitPublisherTest(t, h.draining)
	h.assertAdmissionRejected()
	if err := awaitPublisherTest(t, response); err == nil {
		t.Fatal("draining visitor completed after certificate expiration")
	}
	h.assertFinished(errCertificateExpired)
}

func expireDrainCertificate(control *certificateTestControl, _ *Config) {
	control.change = func(issuance *controlv1.CertificateIssuance, leaf *x509.Certificate) {
		leaf.NotAfter = time.Now().Add(4 * time.Second).UTC().Truncate(time.Second)
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

type visitorDrainHarness struct {
	t                               *testing.T
	ctx                             context.Context
	cancel                          context.CancelFunc
	control                         *certificateTestControl
	relay                           *relay.PublisherConnection
	publishers                      []muxsession.Session
	draining, entered, upstreamDone chan struct{}
	done                            chan error
	unblock                         func()
	body                            string
}

func newVisitorDrainHarness(t *testing.T, transport string, configure func(*certificateTestControl, *Config)) *visitorDrainHarness {
	t.Helper()
	ctx, finish := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(finish)
	h := &visitorDrainHarness{t: t, ctx: ctx, draining: make(chan struct{}), entered: make(chan struct{}), upstreamDone: make(chan struct{}), done: make(chan error, 1), body: strings.Repeat("complete visitor response\n", 32768)}
	release := make(chan struct{})
	var once sync.Once
	h.unblock = func() { once.Do(func() { close(release) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(h.upstreamDone)
		close(h.entered)
		select {
		case <-release:
			_, _ = io.WriteString(w, h.body)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { h.unblock(); upstream.Close() })
	control := newCertificateTestControl(t, "route.example", publicURLCertificateTestPlan())
	h.control = control
	control.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
	connector, relays, publishers := drainTestConnections(t, ctx, control, transport)
	config := Config{Control: control, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1", PublicURLScope: controlv1.Member, Purpose: controlv1.App,
		Hostname: "route.example", Target: upstream.URL, State: control.store, QUICConnector: connector, TCPConnector: connector,
		FallbackDelay: time.Hour, DrainTime: 5 * time.Second, ProvisioningStalledDelay: time.Hour, heartbeatInterval: 20 * time.Millisecond,
		Observe: func(event Event) error {
			if event.Type == EventDraining {
				close(h.draining)
			}
			return nil
		},
	}
	if configure != nil {
		configure(control, &config)
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	h.cancel = cancel
	ready, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		h.done <- runSession(sessionCtx, config, control.setup, func() error { close(ready); return nil })
	}()
	t.Cleanup(func() {
		cancel()
		h.unblock()
		finish() // interrupt real relay I/O as well as the session on failure.
		awaitPublisherTest(t, joined)
	})
	select {
	case <-ready:
	case err := <-h.done:
		t.Fatalf("session did not become ready: %v", err)
	case <-ctx.Done():
		t.Fatal("session readiness timed out")
	}
	active, standby := awaitPublisherTest(t, relays), awaitPublisherTest(t, relays)
	if active.err != nil || standby.err != nil {
		t.Fatalf("relay handshake: %v, %v", active.err, standby.err)
	}
	h.relay = active.connection
	h.publishers = []muxsession.Session{awaitPublisherTest(t, publishers), awaitPublisherTest(t, publishers)}
	return h
}

func (h *visitorDrainHarness) admit() net.Conn {
	h.t.Helper()
	stream, err := h.relay.OpenVisitor(h.ctx, "visitor_drain")
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = stream.Close() })
	if err := stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		h.t.Fatal(err)
	}
	return stream
}

func (h *visitorDrainHarness) assertAdmissionRejected() {
	h.t.Helper()
	admitted, err := h.relay.OpenVisitor(h.ctx, "visitor_after_cancel")
	if err == nil {
		_ = admitted.Close()
		h.t.Fatal("draining session admitted a new visitor")
	}
	var rejected *tunnel.ProtocolError
	if !errors.Is(err, relay.ErrDraining) && (!errors.As(err, &rejected) || rejected.Code != tunnelv1.Unavailable) {
		h.t.Fatalf("drain closed transport instead of rejecting admission: %v", err)
	}
}

func (h *visitorDrainHarness) startVisitor(stream net.Conn, keepAlive bool) <-chan error {
	h.t.Helper()
	metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.1:4321"), Destination: netip.MustParseAddrPort("127.0.0.1:443")})
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := stream.Write(metadata); err != nil {
		h.t.Fatal(err)
	}
	visitor := tls.Client(stream, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(h.t, h.control.signer)})
	h.t.Cleanup(func() { _ = visitor.Close() })
	request := "GET / HTTP/1.1\r\nHost: route.example\r\nConnection: close\r\n\r\n"
	if keepAlive {
		request = "GET / HTTP/1.1\r\nHost: route.example\r\n\r\n"
	}
	if _, err := io.WriteString(visitor, request); err != nil {
		h.t.Fatal(err)
	}
	done, joined := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(joined)
		defer visitor.Close()
		reader := bufio.NewReader(visitor)
		response, err := http.ReadResponse(reader, nil)
		if err == nil {
			var got []byte
			got, err = io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err == nil && (response.StatusCode != http.StatusOK || string(got) != h.body) {
				err = fmt.Errorf("incomplete response: status=%d bytes=%d", response.StatusCode, len(got))
			}
			if err == nil && keepAlive {
				if _, readErr := reader.ReadByte(); !errors.Is(readErr, io.EOF) {
					err = fmt.Errorf("idle visitor remained open after drain: %w", readErr)
				}
			}
		}
		done <- err
	}()
	h.t.Cleanup(func() { _ = visitor.Close(); awaitPublisherTest(h.t, joined) })
	select {
	case <-h.entered:
	case err := <-done:
		h.t.Fatalf("visitor completed before reaching local service: %v", err)
	case <-h.ctx.Done():
		h.t.Fatal("visitor did not reach local service")
	}
	return done
}

func (h *visitorDrainHarness) assertFinished(want error) {
	h.t.Helper()
	if err := awaitPublisherTest(h.t, h.done); !errors.Is(err, want) {
		h.t.Errorf("session result = %v, want %v", err, want)
	}
	for _, transport := range h.publishers {
		select {
		case <-transport.Done():
		default:
			h.t.Error("publisher transport leaked after session returned")
		}
	}
	awaitPublisherTest(h.t, h.upstreamDone)
}
