package ingress

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type restorationPoolRequest struct {
	header  tunnelv1.ServiceForwardingHeader
	payload string
}

func restorationSameForwardingHeader(got, want tunnelv1.ServiceForwardingHeader) bool {
	// json retains exact timestamp instants, not go's monotonic clock or location
	// representation. normalize only those representations, then compare all fields.
	got.ExpiresAt, want.ExpiresAt = got.ExpiresAt.UTC(), want.ExpiresAt.UTC()
	got.LeaseExpiresAt, want.LeaseExpiresAt = got.LeaseExpiresAt.UTC(), want.LeaseExpiresAt.UTC()
	return reflect.DeepEqual(got, want)
}

func restorationPoolTuple(t *testing.T, address, serverName string) (ingressv1.ServiceRelay, tunnelv1.ServiceForwardingHeader) {
	t.Helper()
	_, control, _, lease := publicServiceTestConfig(t)
	relay := control.relays[0]
	relay.InternalRelayAddress, relay.TlsServerName = address, serverName
	return relay, restorationPoolHeader(t, control, lease, relay)
}

func restorationPoolHeader(t *testing.T, control *publicServiceControlFixture, lease ingressv1.IngressLease, relay ingressv1.ServiceRelay) tunnelv1.ServiceForwardingHeader {
	t.Helper()
	return tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: control.service, ServiceRunID: control.run, RunNumber: 1,
		PublisherConnectionID: relay.PublisherConnectionId, ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision),
		VisitorConnectionID: publicServiceTestID(t, "vc_"), SourceIP: "192.0.2.4", ExpiresAt: lease.LeaseExpiresAt,
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: lease.IngressId, IngressRunID: lease.IngressRunId,
			IngressLeaseRevision: uint64(lease.IngressLeaseRevision), DestinationPort: 443},
	}, ConnectionSlot: uint8(relay.ConnectionSlot), RelayServiceID: relay.RelayServiceId, RelayID: relay.RelayId,
		RelayRunID: relay.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLeaseRevision), LeaseExpiresAt: relay.LeaseExpiresAt}
}

func restorationAcceptIngress(ctx context.Context, transport muxsession.Session) (*tunnel.Session, error) {
	session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, hello tunnelv1.Message) error {
		if hello.Role != tunnelv1.Ingress || hello.Credential != forwardingClusterSecret || hello.ServiceConnection != nil {
			return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		return nil
	})
	return session, err
}

func restorationCapturePool(ctx context.Context, transport muxsession.Session, requests chan<- restorationPoolRequest) error {
	session, err := restorationAcceptIngress(ctx, transport)
	if err != nil {
		return err
	}
	defer session.Close()
	for {
		incoming, err := session.AcceptServiceForwardingStream(ctx)
		if err != nil {
			if ctx.Err() != nil || muxsession.NormalSessionCloseOnly(err) || failure.Only(err, io.EOF) || failure.Only(err, syscall.ECONNRESET) {
				return nil
			}
			return err
		}
		if err := func() error {
			defer incoming.Stream().Close()
			if err := incoming.Accept(); err != nil {
				return err
			}
			_ = incoming.Stream().SetDeadline(time.Now().Add(fixtureTimeout))
			var payload [4]byte
			if _, err := io.ReadFull(incoming.Stream(), payload[:]); err != nil {
				return err
			}
			if _, err := incoming.Stream().Write([]byte("pong")); err != nil {
				return err
			}
			select {
			case requests <- restorationPoolRequest{incoming.Header, string(payload[:])}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}(); err != nil {
			return err
		}
	}
}

func restorationPoolExchange(ctx context.Context, forwarder *Forwarder, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, payload string) error {
	connection, err := forwarder.OpenService(ctx, relay, header, nil)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(fixtureTimeout))
	if _, err := connection.Write([]byte(payload)); err != nil {
		return err
	}
	var response [4]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil {
		return err
	}
	if string(response[:]) != "pong" {
		return fmt.Errorf("response = %q", response)
	}
	return nil
}

type restorationGateConnector struct {
	relayConnector
	started chan struct{}
	release <-chan struct{}
	calls   atomic.Int32
	failure error
}

func (c *restorationGateConnector) Credential() string { return forwardingClusterSecret }
func (c *restorationGateConnector) Connect(ctx context.Context, target relayTarget) (muxsession.Session, error) {
	if c.calls.Add(1) == 1 {
		close(c.started)
	}
	select {
	case <-c.release:
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	if c.relayConnector == nil {
		return nil, c.failure
	}
	return c.relayConnector.Connect(ctx, target)
}

// Done is observed after the waiter has found the shared connecting entry.
type restorationWaitingContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *restorationWaitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestServicePoolRestorationEightColdOpensShareRealSession(t *testing.T) {
	const count = 8
	material := newForwardingTestMaterial(t)
	requests := make(chan restorationPoolRequest, count)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		return restorationCapturePool(ctx, transport, requests)
	})
	forwarder := newTestForwarder(t, material)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	connector := &restorationGateConnector{relayConnector: forwarder.connector, started: make(chan struct{}), release: release}
	forwarder.connector = connector
	relay, header := restorationPoolTuple(t, server.address(), material.serverName)
	ctx, cancel := context.WithTimeout(t.Context(), fixtureTimeout)
	results, done := make(chan error, count), make(chan struct{})
	var workers sync.WaitGroup
	t.Cleanup(func() { unblock(); cancel(); _ = forwarder.Close(); ingressAwait(t, done) })
	var headers [count]tunnelv1.ServiceForwardingHeader
	var waiting [count]*restorationWaitingContext
	for index := range count {
		headers[index] = header
		headers[index].VisitorConnectionID = publicServiceTestID(t, "vc_")
		waiting[index] = &restorationWaitingContext{Context: ctx, entered: make(chan struct{})}
	}
	for index := range count {
		workers.Go(func() { results <- restorationPoolExchange(waiting[index], forwarder, relay, headers[index], "ping") })
	}
	go func() { workers.Wait(); close(done) }()
	ingressAwait(t, connector.started)
	for _, waiter := range waiting {
		ingressAwait(t, waiter.entered)
	}
	unblock()
	for range count {
		if err := ingressAwait(t, results); err != nil {
			t.Error(err)
		}
	}
	seen := make(map[string]bool, count)
	for range count {
		request := ingressAwait(t, requests)
		want := header
		want.VisitorConnectionID = request.header.VisitorConnectionID
		if request.payload != "ping" || seen[request.header.VisitorConnectionID] || !restorationSameForwardingHeader(request.header, want) {
			t.Fatalf("forwarded request = %+v", request)
		}
		seen[request.header.VisitorConnectionID] = true
	}
	if connector.calls.Load() != 1 || server.accepted.Load() != 1 {
		t.Fatalf("connects=%d accepted TLS/yamux sessions=%d", connector.calls.Load(), server.accepted.Load())
	}
}

func TestServicePoolRestorationCanceledFirstWaiterLeavesSuccessfulSecond(t *testing.T) {
	material := newForwardingTestMaterial(t)
	requests := make(chan restorationPoolRequest, 1)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		return restorationCapturePool(ctx, transport, requests)
	})
	forwarder := newTestForwarder(t, material)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	connector := &restorationGateConnector{relayConnector: forwarder.connector, started: make(chan struct{}), release: release}
	forwarder.connector = connector
	relay, header := restorationPoolTuple(t, server.address(), material.serverName)
	firstCtx, cancelFirst := context.WithCancelCause(ingressContext(t))
	cause := errors.New("first visitor left")
	first := ingressWorker(t, func() { cancelFirst(cause); unblock() }, func() error {
		return restorationPoolExchange(firstCtx, forwarder, relay, header, "ping")
	})
	ingressAwait(t, connector.started)
	secondHeader := header
	secondHeader.VisitorConnectionID = publicServiceTestID(t, "vc_")
	secondCtx := &restorationWaitingContext{Context: ingressContext(t), entered: make(chan struct{})}
	second := ingressWorker(t, unblock, func() error {
		return restorationPoolExchange(secondCtx, forwarder, relay, secondHeader, "ping")
	})
	ingressAwait(t, secondCtx.entered)
	cancelFirst(cause)
	if err := ingressAwait(t, first); !errors.Is(err, cause) {
		t.Fatalf("canceled first waiter = %v", err)
	}
	select {
	case err := <-second:
		t.Fatalf("first waiter owned shared setup: %v", err)
	default:
	}
	unblock()
	if err := ingressAwait(t, second); err != nil {
		t.Fatal("second visitor did not continue shared setup", err)
	}
	if request := ingressAwait(t, requests); !restorationSameForwardingHeader(request.header, secondHeader) || request.payload != "ping" {
		t.Fatal("canceled visitor replaced the successful visitor", request)
	}
	if connector.calls.Load() != 1 || server.accepted.Load() != 1 {
		t.Fatalf("connects=%d sessions=%d", connector.calls.Load(), server.accepted.Load())
	}
}

func restorationTarget(relay ingressv1.ServiceRelay) relayTarget {
	return relayTarget{address: relay.InternalRelayAddress, serverName: relay.TlsServerName, relayServiceID: relay.RelayServiceId,
		relayID: relay.RelayId, relayRunID: relay.RelayRunId, relayLeaseRevision: uint64(relay.RelayLeaseRevision)}
}

func TestServicePoolRestorationStaleProjectionPreservesLiveReplacement(t *testing.T) {
	material := newForwardingTestMaterial(t)
	requests := make(chan restorationPoolRequest, 4)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		return restorationCapturePool(ctx, transport, requests)
	})
	forwarder := newTestForwarder(t, material)
	oldRelay, oldHeader := restorationPoolTuple(t, server.address(), material.serverName)
	for range 2 {
		header := oldHeader
		header.VisitorConnectionID = publicServiceTestID(t, "vc_")
		if err := restorationPoolExchange(ingressContext(t), forwarder, oldRelay, header, "ping"); err != nil {
			t.Fatal(err)
		}
		if request := ingressAwait(t, requests); !restorationSameForwardingHeader(request.header, header) || request.payload != "ping" {
			t.Fatal("old projection changed exact forwarding facts", request)
		}
	}
	if server.accepted.Load() != 1 {
		t.Fatal("unchanged relay did not pool its first two visitors")
	}
	relay, header := oldRelay, oldHeader
	relay.RelayRunId = publicServiceTestID(t, "rr_")
	header.RelayRunID = relay.RelayRunId
	relay.RelayLeaseRevision++
	header.RelayLeaseRevision++
	header.VisitorConnectionID = publicServiceTestID(t, "vc_")
	live, err := forwarder.OpenService(ingressContext(t), relay, header, nil)
	if err != nil {
		t.Fatal(err)
	}
	ownIngressConn(t, live)
	session, _, err := forwarder.session(ingressContext(t), restorationTarget(relay))
	if err != nil {
		t.Fatal(err)
	}
	if connection, err := forwarder.OpenService(ingressContext(t), oldRelay, oldHeader, nil); connection != nil || err == nil {
		t.Fatal("stale projection started another stream", err)
	} else {
		var rejected *tunnel.ProtocolError
		if !errors.As(err, &rejected) || rejected.Code != tunnelv1.StaleConnectionAssignment {
			t.Fatal("stale projection lost its typed rejection", err)
		}
	}
	if _, err := live.Write([]byte("next")); err != nil {
		t.Fatal("stale projection closed the live replacement", err)
	}
	var response [4]byte
	if _, err := io.ReadFull(live, response[:]); err != nil || string(response[:]) != "pong" {
		t.Fatal("replacement lost bytes", string(response[:]), err)
	}
	_ = live.Close()
	if request := ingressAwait(t, requests); !restorationSameForwardingHeader(request.header, header) || request.payload != "next" {
		t.Fatal("replacement forwarding facts changed", request)
	}
	header.VisitorConnectionID = publicServiceTestID(t, "vc_")
	if err := restorationPoolExchange(ingressContext(t), forwarder, relay, header, "ping"); err != nil {
		t.Fatal(err)
	}
	ingressAwait(t, requests)
	if session.Err() != nil || !forwarder.currentSession(restorationTarget(relay).key(), session) || server.accepted.Load() != 2 {
		t.Fatal("stale projection evicted or reconnected the replacement")
	}
}

func TestServicePoolRestorationStaleProjectionPreservesConnectingReplacement(t *testing.T) {
	for _, revision := range []int64{4, 5} {
		t.Run(fmt.Sprintf("old_revision=%d", revision), func(t *testing.T) {
			material := newForwardingTestMaterial(t)
			requests := make(chan restorationPoolRequest, 1)
			server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
				return restorationCapturePool(ctx, transport, requests)
			})
			forwarder := newTestForwarder(t, material)
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			t.Cleanup(unblock)
			connector := &restorationGateConnector{relayConnector: forwarder.connector, started: make(chan struct{}), release: release}
			forwarder.connector = connector
			relay, header := restorationPoolTuple(t, server.address(), material.serverName)
			relay.RelayLeaseRevision, header.RelayLeaseRevision = 5, 5
			current := ingressWorker(t, unblock, func() error {
				return restorationPoolExchange(ingressContext(t), forwarder, relay, header, "ping")
			})
			ingressAwait(t, connector.started)
			staleRelay, staleHeader := relay, header
			staleRelay.RelayRunId = publicServiceTestID(t, "rr_")
			staleHeader.RelayRunID = staleRelay.RelayRunId
			staleRelay.RelayLeaseRevision, staleHeader.RelayLeaseRevision = revision, uint64(revision)
			connection, err := forwarder.OpenService(ingressContext(t), staleRelay, staleHeader, nil)
			var rejected *tunnel.ProtocolError
			if connection != nil || !errors.As(err, &rejected) || rejected.Code != tunnelv1.StaleConnectionAssignment {
				t.Fatal("old projection competed with connecting replacement", err)
			}
			select {
			case err := <-current:
				t.Fatal("stale projection canceled connecting replacement", err)
			default:
			}
			unblock()
			if err := ingressAwait(t, current); err != nil {
				t.Fatal("replacement did not finish", err)
			}
			ingressAwait(t, requests)
			if connector.calls.Load() != 1 || server.accepted.Load() != 1 {
				t.Fatalf("connects=%d sessions=%d", connector.calls.Load(), server.accepted.Load())
			}
		})
	}
}

func TestServicePoolRestorationCanceledAndClosedOpens(t *testing.T) {
	t.Run("already canceled starts no setup", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			connector := &restorationGateConnector{started: make(chan struct{}), release: release}
			forwarder := newForwarder(connector)
			defer forwarder.Close()
			ctx, cancel := context.WithCancelCause(t.Context())
			cause := errors.New("visitor already canceled")
			cancel(cause)
			_, _, err := forwarder.session(ctx, relayTarget{relayID: "relay"})
			synctest.Wait()
			if !errors.Is(err, cause) || connector.calls.Load() != 0 {
				t.Fatalf("already canceled open: error=%v connects=%d", err, connector.calls.Load())
			}
		})
	})
	for _, closePool := range []bool{false, true} {
		t.Run(fmt.Sprintf("close_pool=%t", closePool), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				cause := errors.New("connector failed")
				connector := &restorationGateConnector{started: make(chan struct{}), release: release, failure: cause}
				forwarder := newForwarder(connector)
				defer forwarder.Close()
				target := relayTarget{relayID: "relay"}
				owner := ingressWorker(t, func() { _ = forwarder.Close() }, func() error {
					_, _, err := forwarder.session(t.Context(), target)
					return err
				})
				ingressAwait(t, connector.started)
				waitCtx, cancel := context.WithCancelCause(t.Context())
				waiter := ingressWorker(t, func() { cancel(context.Canceled) }, func() error {
					_, _, err := forwarder.session(waitCtx, target)
					return err
				})
				synctest.Wait()
				if closePool {
					if err := forwarder.Close(); err != nil {
						t.Fatal(err)
					}
					for _, result := range []<-chan error{owner, waiter} {
						if err := ingressAwait(t, result); !errors.Is(err, context.Canceled) {
							t.Fatal("pool close lost setup cancellation", err)
						}
					}
					if _, _, err := forwarder.session(t.Context(), target); !errors.Is(err, net.ErrClosed) {
						t.Fatal("open after close", err)
					}
				} else {
					waiterCause := errors.New("waiting visitor left")
					cancel(waiterCause)
					if err := ingressAwait(t, waiter); !errors.Is(err, waiterCause) {
						t.Fatal("waiter lost cancellation cause", err)
					}
					select {
					case err := <-owner:
						t.Fatal("waiter canceled shared setup", err)
					default:
					}
					close(release)
					if err := ingressAwait(t, owner); !errors.Is(err, cause) {
						t.Fatal("setup lost connector cause", err)
					}
				}
				if connector.calls.Load() != 1 {
					t.Fatal("waiter or close started another setup", connector.calls.Load())
				}
			})
		})
	}
}

type restorationStreamFailureConnector struct {
	relayConnector
	failure error
}

func (c restorationStreamFailureConnector) Connect(ctx context.Context, target relayTarget) (muxsession.Session, error) {
	transport, err := c.relayConnector.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	return &restorationStreamFailureTransport{Session: transport, failure: c.failure}, nil
}

type restorationStreamFailureTransport struct {
	muxsession.Session
	failure error
	opens   atomic.Int32
}

func (s *restorationStreamFailureTransport) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	if s.opens.Add(1) == 2 {
		return nil, s.failure
	}
	return s.Session.OpenStream(ctx)
}

func TestServicePoolRestorationVisitorFailureKeepsBorrowedSession(t *testing.T) {
	material := newForwardingTestMaterial(t)
	requests := make(chan restorationPoolRequest, 1)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		return restorationCapturePool(ctx, transport, requests)
	})
	forwarder := newTestForwarder(t, material)
	cause := errors.New("only this visitor stream failed")
	forwarder.connector = restorationStreamFailureConnector{forwarder.connector, cause}
	relay, header := restorationPoolTuple(t, server.address(), material.serverName)
	target := restorationTarget(relay)
	session, _, err := forwarder.session(ingressContext(t), target)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := forwarder.OpenService(ingressContext(t), relay, header, nil)
	var opening *tunnel.OpeningError
	if connection != nil || !errors.Is(err, cause) || !errors.As(err, &opening) || opening.Committed || opening.VisitorBytes != 0 {
		t.Fatal("visitor failure lost its original error or zero-byte boundary", err)
	}
	if session.Err() != nil || !forwarder.currentSession(target.key(), session) {
		t.Fatal("failed visitor invalidated a healthy borrowed session")
	}
	header.VisitorConnectionID = publicServiceTestID(t, "vc_")
	if err := restorationPoolExchange(ingressContext(t), forwarder, relay, header, "ping"); err != nil {
		t.Fatal(err)
	}
	ingressAwait(t, requests)
	if server.accepted.Load() != 1 {
		t.Fatal("next visitor reconnected after a per-stream failure", server.accepted.Load())
	}
}

type restorationRetryConnector struct {
	relayConnector
	opened  chan int
	release [2]chan struct{}
	calls   atomic.Int32
	failure error
}

func (c *restorationRetryConnector) Connect(ctx context.Context, target relayTarget) (muxsession.Session, error) {
	transport, err := c.relayConnector.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	return &restorationRetryTransport{Session: transport, owner: c, index: int(c.calls.Add(1)) - 1}, nil
}

type restorationRetryTransport struct {
	muxsession.Session
	owner *restorationRetryConnector
	index int
	opens atomic.Int32
}

func (s *restorationRetryTransport) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	if s.opens.Add(1) == 1 {
		return s.Session.OpenStream(ctx)
	}
	if s.index >= len(s.owner.release) {
		return nil, errors.New("unexpected third relay connection")
	}
	s.owner.opened <- s.index
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.owner.release[s.index]:
		return nil, s.owner.failure
	}
}

func TestServicePoolRestorationRetryReusesConcurrentReplacement(t *testing.T) {
	material := newForwardingTestMaterial(t)
	requests := make(chan restorationPoolRequest, 1)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		return restorationCapturePool(ctx, transport, requests)
	})
	forwarder := newTestForwarder(t, material)
	connector := &restorationRetryConnector{relayConnector: forwarder.connector, opened: make(chan int, 2),
		release: [2]chan struct{}{make(chan struct{}), make(chan struct{})}, failure: errors.New("visitor stream open failed")}
	forwarder.connector = connector
	relay, header := restorationPoolTuple(t, server.address(), material.serverName)
	target := restorationTarget(relay)
	ctx := ingressContext(t)
	first, reused, err := forwarder.session(ctx, target)
	if err != nil || reused {
		t.Fatal("initial session", reused, err)
	}
	done := ingressWorker(t, func() { _ = forwarder.Close() }, func() error {
		_, err := forwarder.OpenService(ctx, relay, header, nil)
		return err
	})
	if index := ingressAwait(t, connector.opened); index != 0 {
		t.Fatal("wrong first attempt", index)
	}
	if err := forwarder.invalidate(ctx, target.key(), first); err != nil {
		t.Fatal(err)
	}
	second, reused, err := forwarder.session(ctx, target)
	if err != nil || reused || second == first {
		t.Fatal("concurrent replacement", reused, err)
	}
	close(connector.release[0])
	if index := ingressAwait(t, connector.opened); index != 1 {
		t.Fatal("retry did not borrow concurrent replacement", index)
	}
	close(connector.release[1])
	if err := ingressAwait(t, done); !errors.Is(err, connector.failure) {
		t.Fatal("retry exhaustion lost stream failure", err)
	}
	if connector.calls.Load() != 2 || server.accepted.Load() != 2 || second.Err() != nil || !forwarder.currentSession(target.key(), second) {
		t.Fatal("retry evicted the healthy replacement or reconnected", connector.calls.Load(), server.accepted.Load())
	}
	select {
	case request := <-requests:
		t.Fatal("unaccepted stream received visitor bytes", request)
	default:
	}
}

func TestServicePoolRestorationRejectsWrongRelayTLSHostname(t *testing.T) {
	material := newForwardingTestMaterial(t)
	wrong := issueForwardingTestCertificate(t, material.authority, material.authorityKey, "wrong.example")
	var opens atomic.Int32
	server := startForwardingTestServerWithCertificate(t, material, wrong, func(context.Context, muxsession.Session) error {
		opens.Add(1)
		return errors.New("wrong relay certificate reached authenticated session")
	})
	forwarder := newTestForwarder(t, material)
	relay, header := restorationPoolTuple(t, server.address(), material.serverName)
	connection, err := forwarder.OpenService(ingressContext(t), relay, header, nil)
	var hostname x509.HostnameError
	if connection != nil || !errors.As(err, &hostname) || hostname.Host != material.serverName {
		t.Fatal("wrong exact relay hostname was not rejected", err)
	}
	select {
	case err := <-server.errors:
		if err == nil || !strings.Contains(err.Error(), "tls: bad certificate") {
			t.Fatal("server did not observe certificate rejection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not observe client certificate rejection within 1s")
	}
	if server.accepted.Load() != 0 || opens.Load() != 0 {
		t.Fatal("wrong certificate opened an authenticated session", server.accepted.Load(), opens.Load())
	}
}

func TestServicePoolRestorationUnexpectedCloseHasExactIdentityAndCause(t *testing.T) {
	material := newForwardingTestMaterial(t)
	peers := make(chan muxsession.Session, 1)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		peers <- transport
		return restorationCapturePool(ctx, transport, make(chan restorationPoolRequest, 1))
	})
	forwarder := newTestForwarder(t, material)
	type closure struct {
		service, relay, origin string
		cause                  error
	}
	closed := make(chan closure, 2)
	forwarder.onSessionClosed = func(service, relay, origin string, cause error) { closed <- closure{service, relay, origin, cause} }
	relay, _ := restorationPoolTuple(t, server.address(), material.serverName)
	if _, _, err := forwarder.session(ingressContext(t), restorationTarget(relay)); err != nil {
		t.Fatal(err)
	}
	if err := ingressAwait(t, peers).Close(); err != nil {
		t.Fatal(err)
	}
	got := ingressAwait(t, closed)
	if got.service != relay.RelayServiceId || got.relay != relay.RelayId || got.origin != "observed_close" ||
		!errors.Is(got.cause, io.EOF) && !errors.Is(got.cause, syscall.ECONNRESET) {
		t.Fatalf("unexpected-close callback = %+v", got)
	}
	if err := forwarder.Close(); err != nil && !muxsession.NormalSessionCloseOnly(err) && !failure.Only(err, io.EOF) && !failure.Only(err, syscall.ECONNRESET) {
		t.Fatal(err)
	}
	if len(closed) != 0 || server.accepted.Load() != 1 {
		t.Fatal("planned close duplicated the unexpected-close callback")
	}
}
