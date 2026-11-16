package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	"github.com/tnldotdev/tnl/internal/testutil/transporttest"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type forwardingDiagnosticHalfClose struct {
	nativeErr, err, sendCause error
}

type forwardingDiagnosticSession struct {
	muxsession.Session
	opened  chan<- context.Context
	half    chan<- forwardingDiagnosticHalfClose
	cleanup error
	copyErr error
}

func (s *forwardingDiagnosticSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	sender, ok := stream.(interface{ Context() context.Context })
	if !ok {
		return nil, errors.Join(errors.New("diagnostic requires a real QUIC send context"), stream.Close())
	}
	s.opened <- sender.Context()
	return &forwardingDiagnosticStream{Stream: stream, send: sender.Context(), half: s.half, cleanup: s.cleanup, copyErr: s.copyErr}, nil
}

type forwardingDiagnosticStream struct {
	muxsession.Stream
	send    context.Context
	half    chan<- forwardingDiagnosticHalfClose
	cleanup error
	copyErr error
}

func (s *forwardingDiagnosticStream) CloseWrite() error {
	nativeErr := s.Stream.CloseWrite()
	err := errors.Join(nativeErr, s.copyErr)
	s.half <- forwardingDiagnosticHalfClose{nativeErr: nativeErr, err: err, sendCause: context.Cause(s.send)}
	return err
}

func (s *forwardingDiagnosticStream) Close() error {
	return errors.Join(s.Stream.Close(), s.cleanup)
}

type forwardingDiagnosticTransfer struct {
	upload, download int64
	err              error
}

type forwardingDiagnosticObserver struct {
	transfers chan forwardingDiagnosticTransfer
}

func (*forwardingDiagnosticObserver) ObserveOperationContext(context.Context, observability.ServerOperation, error, time.Duration) {
}

func (o *forwardingDiagnosticObserver) ObserveRelayTransfer(upload, download int64, err error) {
	o.transfers <- forwardingDiagnosticTransfer{upload: upload, download: download, err: err}
}

type forwardingDiagnosticPublisher struct {
	muxsession.Session
	accepted chan<- muxsession.Stream
}

func (s forwardingDiagnosticPublisher) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err == nil {
		s.accepted <- stream
	}
	return stream, err
}

// capture the copy result and final report separately: deferred physical closes
// can add causes after the transfer observer runs. no cause text is classified.
func TestRelayForwardingDiagnosticRetainsQUICHalfCloseOrigin(t *testing.T) {
	for _, test := range []struct {
		name        string
		code        quic.StreamErrorCode
		independent bool
		copyFailure bool
	}{{"normal-stop", 0, false, false}, {"abnormal-stop", 17, false, false},
		{"normal-stop-and-independent-close", 0, true, false}, {"normal-stop-and-independent-copy-half-close", 0, false, true}} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			material := httptest.NewTLSServer(nil)
			defer material.Close()
			roots := x509.NewCertPool()
			roots.AddCert(material.Certificate())
			clientTLS := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
			header := privateLifecycleHeader()
			var err error
			header.VisitorConnectionID, err = opaqueid.New(opaqueid.VisitorConnectionPrefix)
			if err != nil {
				t.Fatal(err)
			}
			header.PublicService.DestinationPort = 443
			ref := tunnel.ServiceForwardingRef(header)
			registry := NewServiceRegistry()
			defer func() {
				if err := registry.Close(); err != nil {
					t.Error("close diagnostic registry", err)
				}
			}()
			cleanup := errors.New("independent publisher stream close failure")
			var injected error
			if test.independent {
				injected = cleanup
			}
			copyFailure := errors.New("independent forwarding half-close failure")
			var injectedCopy error
			if test.copyFailure {
				injectedCopy = copyFailure
			}
			opened := make(chan context.Context, 1)
			half := make(chan forwardingDiagnosticHalfClose, 1)
			registered := make(chan struct{}, 1)
			publisherOwner := make(chan error, 1)
			publisherAddress := traceMuxServer(t, ctx, tunnel.TransportQUIC, material.TLS, func(owner context.Context, mux muxsession.Session) (result error) {
				defer func() { publisherOwner <- result }()
				wire := &forwardingDiagnosticSession{Session: mux, opened: opened, half: half, cleanup: injected, copyErr: injectedCopy}
				session, _, err := tunnel.Accept(owner, wire, func(_ context.Context, hello tunnelv1.Message) error {
					if hello.Role != tunnelv1.Publisher || hello.ServiceConnection == nil || *hello.ServiceConnection != ref {
						return errors.New("diagnostic publisher changed its exact service assignment")
					}
					return nil
				})
				if err != nil {
					return err
				}
				lease := privateDiagnosticLease(header)
				if err := registry.insert(&serviceConnection{ref: ref, lease: lease, paths: newStreamLifetime(session)}); err != nil {
					return err
				}
				registered <- struct{}{}
				select {
				case <-session.Done():
				case <-owner.Done():
				}
				return session.Close()
			})
			mux, err := (muxsession.QUICConnector{TLSConfig: clientTLS, Dialer: transporttest.QUICTransport(t)}).Connect(ctx,
				muxsession.Endpoint{Address: publisherAddress, ServerName: "127.0.0.1"})
			if err != nil {
				t.Fatal(err)
			}
			acceptedStreams := make(chan muxsession.Stream, 1)
			publisher, err := tunnel.Dial(ctx, forwardingDiagnosticPublisher{Session: mux, accepted: acceptedStreams}, tunnelv1DiagnosticHello(ref))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := publisher.Close(); err != nil {
					t.Error("close diagnostic publisher", err)
				}
				if err := relayAwait(t, publisherOwner); err != nil {
					t.Error("join diagnostic publisher owner", err)
				}
			}()
			relayAwait(t, registered)
			secret := strings.Repeat("s", 32)
			secrets, err := serverhttp.NewBearerSecrets(secret, "")
			if err != nil {
				t.Fatal(err)
			}
			reports, transfers := make(chan error, 1), make(chan forwardingDiagnosticTransfer, 1)
			lease := privateDiagnosticLease(header)
			acceptor, err := NewForwardingAcceptor(ForwardingAcceptorConfig{
				ServiceRegistry: registry, CurrentLease: func() relayv1.RelayLease { return lease }, ClusterSecrets: secrets,
				StreamCapacity: 1, Report: func(err error) { reports <- err }, Observer: &forwardingDiagnosticObserver{transfers: transfers},
			})
			if err != nil {
				t.Fatal(err)
			}
			acceptResult := make(chan error, 1)
			address := traceMuxServer(t, ctx, tunnel.TransportTLSTCP, material.TLS, func(owner context.Context, mux muxsession.Session) error {
				err := acceptor.Accept(owner, mux)
				acceptResult <- err
				return err
			})
			forwarder, err := ingress.NewForwarder(ingress.ForwarderConfig{Context: ctx, TLSConfig: clientTLS, ClusterSecret: secret})
			if err != nil {
				t.Fatal(err)
			}
			joinAcceptor := sync.OnceValue(func() error {
				return errors.Join(forwarder.Close(), relayAwait(t, acceptResult))
			})
			defer func() {
				if err := joinAcceptor(); err != nil {
					t.Error("close diagnostic forwarder and join relay acceptor", err)
				}
			}()
			relay := ingressv1.ServiceRelay{PublisherConnectionId: ref.PublisherConnectionID, ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision),
				RelayServiceId: header.RelayServiceID, RelayId: header.RelayID, RelayRunId: header.RelayRunID, RelayLeaseRevision: int64(header.RelayLeaseRevision),
				LeaseExpiresAt: header.LeaseExpiresAt, InternalRelayAddress: address, TlsServerName: "127.0.0.1", ConnectionSlot: int(header.ConnectionSlot)}
			visitorDone := make(chan error, 1)
			peer := make(chan *tunnel.IncomingServiceForwardingStream, 1)
			go func() {
				incoming, err := publisher.AcceptServiceForwardingStream(ctx)
				if err == nil {
					peer <- incoming
					err = incoming.Accept()
				}
				visitorDone <- err
			}()
			stream, err := forwarder.OpenService(ctx, relay, header, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := stream.Close(); err != nil {
					t.Error("close diagnostic visitor stream", err)
				}
			}()
			incoming := relayAwait(t, peer)
			if err := relayAwait(t, visitorDone); err != nil {
				t.Fatal(err)
			}
			if incoming.Header.VisitorConnectionID != header.VisitorConnectionID {
				t.Fatal("diagnostic visitor identity changed")
			}
			if _, err := stream.Write([]byte("request")); err != nil {
				t.Fatal("write diagnostic request", err)
			}
			var request [7]byte
			if _, err := io.ReadFull(incoming.Stream(), request[:]); err != nil || string(request[:]) != "request" {
				t.Fatal("diagnostic request did not reach publisher unchanged", err)
			}
			// deliver a complete framed response, then stop only the peer's read
			// half. hold the ingress half-close until QUIC observes that stop.
			if _, err := incoming.Stream().Write([]byte("complete")); err != nil {
				t.Fatal(err)
			}
			if err := incoming.CloseWrite(ctx); err != nil {
				t.Fatal(err)
			}
			physical := relayAwait(t, acceptedStreams)
			stopRead := physical.(interface{ CancelRead(quic.StreamErrorCode) })
			stopRead.CancelRead(test.code)
			if body, err := io.ReadAll(stream); err != nil || string(body) != "complete" {
				t.Fatal("response did not complete before sender stop", err)
			}
			send := relayAwait(t, opened)
			relayAwait(t, send.Done())
			if err := stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal("finish ingress upload", err)
			}
			origin := relayAwait(t, half)
			transfer := relayAwait(t, transfers)
			wantReport := test.code != 0 || test.independent || test.copyFailure
			var reported error
			if wantReport {
				// observe real failures while the accept owner is still live,
				// before its joined shutdown could fence further reports.
				reported = relayAwait(t, reports)
			}
			var stopped *quic.StreamError
			if !errors.As(origin.sendCause, &stopped) || !stopped.Remote || stopped.ErrorCode != test.code {
				t.Fatal("half-close did not follow the exact observed peer stop")
			}
			if test.code == 0 {
				if origin.nativeErr != nil {
					t.Fatal("normal peer stop invented a native half-close failure", origin.nativeErr)
				}
			} else {
				var reset *quic.StreamError
				if !errors.As(origin.nativeErr, &reset) || !reset.Remote || reset.ErrorCode != test.code ||
					reset.StreamID != stopped.StreamID || !errors.Is(reported, origin.nativeErr) {
					t.Fatal("abnormal peer half-close lost its typed cause")
				}
			}
			if !errors.Is(transfer.err, origin.err) || test.copyFailure != errors.Is(transfer.err, copyFailure) ||
				test.independent != errors.Is(reported, cleanup) || test.copyFailure != errors.Is(reported, copyFailure) ||
				wantReport != (reported != nil) || ctx.Err() != nil {
				t.Fatal("copy or final relay report lost its native or independent failure")
			}
			if transfer.upload != 7 || transfer.download != 8 {
				t.Fatal("half-close changed complete request or response bytes", transfer.upload, transfer.download)
			}
			select {
			case <-publisher.Done():
				t.Fatal("diagnostic came from a lost publisher carrier rather than one stream")
			default:
			}
			if err := joinAcceptor(); err != nil {
				t.Fatal("forwarding owner did not join", err)
			}
			select {
			case <-reports:
				t.Fatal("completed forwarding emitted an unexpected or duplicate diagnostic")
			default:
			}
			t.Logf("report boundary=relay.Report service_id=%s run_id=%s visitor_connection_id=%s native_half_close_type=%T remote=%t code=%d reported=%t independent_close=%t independent_copy_half_close=%t upload=%d download=%d",
				header.ServiceID, header.ServiceRunID, header.VisitorConnectionID, origin.nativeErr, stopped.Remote, stopped.ErrorCode, reported != nil, test.independent, test.copyFailure, transfer.upload, transfer.download)
		})
	}
}

func privateDiagnosticLease(header tunnelv1.ServiceForwardingHeader) relayv1.RelayLease {
	return relayv1.RelayLease{RelayServiceId: header.RelayServiceID, RelayId: header.RelayID, RelayRunId: header.RelayRunID,
		RelayLeaseRevision: int64(header.RelayLeaseRevision), LeaseExpiresAt: header.LeaseExpiresAt}
}

func tunnelv1DiagnosticHello(ref tunnelv1.ServicePublisherConnectionRef) tunnelv1.Message {
	return tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher, Credential: "diagnostic-publisher", ServiceConnection: &ref}
}
