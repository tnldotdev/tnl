package service

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil/transporttest"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// retain real QUIC, verified TLS, DATAGRAM negotiation, and the exact claim.
// observe the actual accept result before adding a separately owned fault.
type dispatcherQUICCleanupTransport struct {
	privateSlotQUICTransport
	entered           chan struct{}
	accepted          chan error
	once              sync.Once
	acceptFailure     error
	closeFailure      error
	beforeAcceptError func()
	closes            atomic.Int32
}

var _ privateSlotQUICTransport = (*dispatcherQUICCleanupTransport)(nil)

func (s *dispatcherQUICCleanupTransport) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	s.once.Do(func() { close(s.entered) })
	stream, err := s.privateSlotQUICTransport.AcceptStream(ctx)
	if err != nil {
		if s.beforeAcceptError != nil {
			s.beforeAcceptError()
		}
		s.accepted <- err
		return stream, errors.Join(err, s.acceptFailure)
	}
	return stream, nil
}

func (s *dispatcherQUICCleanupTransport) Close() error {
	s.closes.Add(1)
	return errors.Join(s.privateSlotQUICTransport.Close(), s.closeFailure)
}

type dispatcherQUICCleanupDialer struct {
	muxsession.QUICDialer
	connection chan *quic.Conn
}

func (d dispatcherQUICCleanupDialer) DialQUIC(ctx context.Context, address net.Addr, trust *tls.Config, config *quic.Config) (*quic.Conn, error) {
	conn, err := d.QUICDialer.DialQUIC(ctx, address, trust, config)
	if err == nil {
		d.connection <- conn
	}
	return conn, err
}

// dropping packets keeps the real UDP socket bound, avoiding ICMP failures or a
// synthetic timeout. both QUIC endpoints still own their normal idle timers.
type dispatcherQUICCleanupPackets struct {
	net.PacketConn
	drop atomic.Bool
}

func (p *dispatcherQUICCleanupPackets) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, address, err := p.PacketConn.ReadFrom(b)
		if err != nil || !p.drop.Load() {
			return n, address, err
		}
	}
}

func (p *dispatcherQUICCleanupPackets) WriteTo(b []byte, address net.Addr) (int, error) {
	if p.drop.Load() {
		return len(b), nil
	}
	return p.PacketConn.WriteTo(b, address)
}

type dispatcherQUICCleanupFixture struct {
	claimed       *Claimed
	outer         *dispatcherQUICCleanupTransport
	local, remote *quic.Conn
	packets       *dispatcherQUICCleanupPackets
}

func newDispatcherQUICCleanupFixture(t *testing.T, bound *Bound, idle time.Duration, acceptFailure, closeFailure error, beforeAcceptError func()) dispatcherQUICCleanupFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	serverTLS, roots := privateTransportTLS(t)
	serverTLS.NextProtos = []string{muxsession.ALPN}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packets := &dispatcherQUICCleanupPackets{PacketConn: packet}
	serverTransport := &quic.Transport{Conn: packets}
	t.Cleanup(func() { _ = serverTransport.Close(); _ = packet.Close() })
	config := &quic.Config{EnableDatagrams: true, MaxIdleTimeout: idle}
	listener, err := serverTransport.Listen(serverTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	bound.mu.Lock()
	bound.connections[0].TlsServerName = "relay.test"
	assignment := bound.connections[0]
	ref := bound.prepared.connectionRef(assignment)
	bound.mu.Unlock()
	type accepted struct {
		connection *quic.Conn
		session    *tunnel.Session
		err        error
	}
	remote, joined := make(chan accepted, 1), make(chan struct{})
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		_ = serverTransport.Close()
		claimedAwait(t, joined)
	})
	go func() {
		defer close(joined)
		connection, err := listener.Accept(ctx)
		if err != nil {
			remote <- accepted{err: err}
			return
		}
		outer, err := muxsession.AdoptQUIC(connection)
		if err != nil {
			remote <- accepted{err: err}
			return
		}
		session, _, err := tunnel.Accept(ctx, outer, func(_ context.Context, hello tunnelv1.Message) error {
			if hello.Role != tunnelv1.Publisher || hello.ServiceConnection == nil ||
				*hello.ServiceConnection != ref || hello.Credential != assignment.PublisherConnectionCredential {
				return ErrPrivateStream
			}
			return nil
		})
		remote <- accepted{connection, session, err}
	}()
	dialer := dispatcherQUICCleanupDialer{QUICDialer: transporttest.QUICTransport(t), connection: make(chan *quic.Conn, 1)}
	connector := muxsession.QUICConnector{TLSConfig: roots, Config: muxsession.QUICConfig{Config: config}, Dialer: dialer}
	var observed *dispatcherQUICCleanupTransport
	options := ConnectOptions{
		QUIC: muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
			if endpoint.Address != assignment.RelayAddress || endpoint.ServerName != "relay.test" {
				return nil, ErrPrivateStream
			}
			endpoint.Address = listener.Addr().String()
			outer, err := connector.Connect(ctx, endpoint)
			if err != nil {
				return nil, err
			}
			capabilities, ok := outer.(privateSlotQUICTransport)
			if !ok {
				return nil, errors.Join(ErrPrivateStream, outer.Close())
			}
			observed = &dispatcherQUICCleanupTransport{privateSlotQUICTransport: capabilities,
				entered: make(chan struct{}), accepted: make(chan error, 1), acceptFailure: acceptFailure, closeFailure: closeFailure,
				beforeAcceptError: beforeAcceptError}
			return observed, nil
		}),
		TCP: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
			return nil, net.ErrClosed
		}),
	}
	claimed, err := bound.ConnectSlot(t.Context(), 0, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = claimed.Close() })
	relay := claimedAwait(t, remote)
	if relay.err != nil {
		t.Fatal(relay.err)
	}
	t.Cleanup(func() { _ = relay.session.Close() })
	local := claimedAwait(t, dialer.connection)
	claimedAwait(t, joined)
	claimedAwait(t, observed.entered)
	if claimed.Transport() != tunnel.TransportQUIC || claimed.ref != ref || claimed.dispatcher == nil || claimed.packets == nil ||
		!observed.SupportsDatagrams() || len(observed.TLSConnectionState().VerifiedChains) == 0 {
		t.Fatal("fixture bypassed verified QUIC, the exact claim, or production dispatch composition")
	}
	return dispatcherQUICCleanupFixture{claimed, observed, local, relay.connection, packets}
}

func waitDispatcherQUICCleanupSlot(t *testing.T, slots *tunnel.Slots, want *Claimed) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		ready, changed := slots.Snapshot()
		if want == nil && ready[0] == nil || want != nil && ready[0] == want {
			return
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("claimed QUIC slot did not reach the expected readiness")
		}
	}
}

func assertDispatcherQUICCleanupCause(t *testing.T, err error, code quic.ApplicationErrorCode, remote, timeout bool) {
	t.Helper()
	if timeout {
		var idle *quic.IdleTimeoutError
		if !errors.As(err, &idle) || errors.Is(err, muxsession.ErrClosed) {
			t.Error("lost actual typed idle timeout or relabeled it as a normal close", err)
		}
		return
	}
	var application *quic.ApplicationError
	if !errors.As(err, &application) || application.ErrorCode != code || application.Remote != remote ||
		errors.Is(err, muxsession.ErrClosed) != (code == 0) {
		t.Error("lost actual typed QUIC application close or its local/remote identity", err)
	}
}

func TestServiceDispatcherQUICClosureRetainsOnlyIndependentCleanupFailures(t *testing.T) {
	cleanup := errors.New("independent dispatcher cleanup failed")
	reset := &quic.StreamError{Remote: true, ErrorCode: 17}
	timeout := &quic.IdleTimeoutError{}
	closedPhysical := &muxsession.QUICTransportCloseError{Err: net.ErrClosed}
	canceledPhysical := &muxsession.QUICTransportCloseError{Err: context.Canceled}
	deadlinePhysical := &muxsession.QUICTransportCloseError{Err: context.DeadlineExceeded}
	joinedPhysical := &muxsession.QUICTransportCloseError{Err: errors.Join(context.Canceled, cleanup)}
	for _, test := range []struct {
		name                        string
		remote, timeout             bool
		code                        quic.ApplicationErrorCode
		acceptFailure, closeFailure error
		ownerCancelCause            error
		contextOnlyClose            bool
	}{
		{name: "local_normal"},
		{name: "remote_normal", remote: true},
		{name: "remote_abnormal", remote: true, code: 17},
		{name: "idle_timeout", timeout: true},
		{name: "local_normal_joined_cleanup", acceptFailure: cleanup},
		{name: "local_normal_joined_cancellation_and_cleanup", acceptFailure: errors.Join(context.Canceled, cleanup)},
		{name: "local_normal_joined_deadline", acceptFailure: context.DeadlineExceeded},
		{name: "local_normal_joined_short_write", acceptFailure: io.ErrShortWrite},
		{name: "local_normal_joined_abnormal_reset", acceptFailure: reset},
		{name: "local_normal_joined_timeout", acceptFailure: timeout},
		{name: "local_normal_physical_cleanup_failure", closeFailure: cleanup},
		{name: "local_normal_physical_quic_close_closed", closeFailure: closedPhysical},
		{name: "local_normal_physical_quic_close_canceled", closeFailure: canceledPhysical,
			ownerCancelCause: context.Canceled},
		{name: "local_normal_physical_quic_close_deadline", closeFailure: deadlinePhysical,
			ownerCancelCause: context.DeadlineExceeded},
		{name: "local_normal_physical_quic_close_joined_cancellation", closeFailure: errors.Join(context.Canceled, closedPhysical),
			ownerCancelCause: context.Canceled},
		{name: "local_normal_physical_quic_close_joined_deadline", closeFailure: errors.Join(context.DeadlineExceeded, closedPhysical),
			ownerCancelCause: context.DeadlineExceeded},
		{name: "local_normal_physical_quic_close_canceled_and_independent_cleanup", closeFailure: joinedPhysical,
			ownerCancelCause: context.Canceled},
		{name: "local_normal_expected_context_only_close_cancellation", closeFailure: context.Canceled,
			ownerCancelCause: context.Canceled, contextOnlyClose: true},
		{name: "local_normal_expected_context_only_close_deadline", closeFailure: context.DeadlineExceeded,
			ownerCancelCause: context.DeadlineExceeded, contextOnlyClose: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			owner, cancelOwner := context.WithCancelCause(t.Context())
			defer cancelOwner(nil)
			idle := 30 * time.Second
			if test.timeout {
				idle = time.Second
			}
			fixture := newDispatcherQUICCleanupFixture(t, bound, idle, test.acceptFailure, test.closeFailure, func() {
				// publish the expected cause only after real QUIC returned its
				// terminal error, before claimed serving can enter cleanup.
				if test.ownerCancelCause != nil {
					cancelOwner(test.ownerCancelCause)
				}
			})
			ended := make(chan error, 1)
			slots, err := tunnel.NewSlots(owner, tunnel.SlotsConfig{SingleUse: true,
				Connect:      func(context.Context, uint8, bool) (tunnel.SlotSession, error) { return fixture.claimed, nil },
				SessionEnded: func(_ uint8, _ tunnel.SlotSession, err error) { ended <- err }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = slots.Close() })
			if err := slots.Set(0, bound.assignmentKey(0)); err != nil {
				t.Fatal(err)
			}
			waitDispatcherQUICCleanupSlot(t, slots, fixture.claimed)
			switch {
			case test.timeout:
				fixture.packets.drop.Store(true)
			case test.remote:
				if err := fixture.remote.CloseWithError(test.code, "fixture"); err != nil {
					t.Fatal(err)
				}
			default:
				if err := fixture.local.CloseWithError(0, "fixture"); err != nil {
					t.Fatal(err)
				}
			}
			acceptErr := claimedAwait(t, fixture.outer.accepted)
			assertDispatcherQUICCleanupCause(t, acceptErr, test.code, test.remote, test.timeout)
			if test.ownerCancelCause != nil && context.Cause(owner) != test.ownerCancelCause {
				t.Fatal("fixture did not publish the exact expected owner context cause")
			}
			serveErr := claimedAwait(t, ended)
			waitDispatcherQUICCleanupSlot(t, slots, nil)
			dispatchErr, claimErr, slotsErr := fixture.claimed.dispatcher.Close(), fixture.claimed.Close(), slots.Close()
			// transport evidence must remain typed even when owned cleanup is normal.
			assertDispatcherQUICCleanupCause(t, fixture.claimed.session.Err(), test.code, test.remote, test.timeout)
			for name, result := range map[string]error{"serve": serveErr, "dispatcher": dispatchErr, "claimed": claimErr, "retired slots": slotsErr} {
				operationResult := name == "serve" || name == "dispatcher"
				retainClose := name != "dispatcher" && (name != "serve" || !test.contextOnlyClose)
				retainOperation := operationResult && (test.timeout || test.code != 0 || test.acceptFailure != nil)
				retain := retainOperation || retainClose && test.closeFailure != nil
				if !retain {
					if result != nil {
						t.Errorf("%s cached a normal QUIC close as cleanup failure: %v", name, result)
					}
					continue
				}
				if retainOperation {
					assertDispatcherQUICCleanupCause(t, result, test.code, test.remote, test.timeout)
				}
				for _, cause := range []error{cleanup, context.Canceled, context.DeadlineExceeded, io.ErrShortWrite, reset} {
					want := operationResult && errors.Is(test.acceptFailure, cause) || retainClose && errors.Is(test.closeFailure, cause)
					if errors.Is(result, cause) != want {
						t.Errorf("%s lost or invented independent cause %v: %v", name, cause, result)
					}
				}
				// zero-sized QUIC timeout values are typed facts, not unique sentinels.
				var expectedTimeout, retainedTimeout *quic.IdleTimeoutError
				wantTimeout := operationResult && (test.timeout || errors.As(test.acceptFailure, &expectedTimeout)) ||
					retainClose && errors.As(test.closeFailure, &expectedTimeout)
				if errors.As(result, &retainedTimeout) != wantTimeout {
					t.Errorf("%s lost or invented a typed idle timeout: %v", name, result)
				}
				if retainClose && test.closeFailure != nil && !errors.Is(result, test.closeFailure) {
					t.Errorf("%s lost the original physical cleanup tree: %v", name, result)
				}
				var expectedPhysical, retainedPhysical *muxsession.QUICTransportCloseError
				wantPhysical := operationResult && errors.As(test.acceptFailure, &expectedPhysical) ||
					retainClose && errors.As(test.closeFailure, &expectedPhysical)
				if errors.As(result, &retainedPhysical) != wantPhysical ||
					wantPhysical && (retainedPhysical != expectedPhysical || !errors.Is(result, expectedPhysical.Err)) {
					t.Errorf("%s lost or replaced the exact physical cleanup marker or cause: %v", name, result)
				}
			}
			if fixture.outer.closes.Load() != 1 {
				t.Error("retired claimed session did not close its physical transport exactly once", fixture.outer.closes.Load())
			}
			if again := fixture.claimed.Close(); again != claimErr {
				t.Error("claimed close did not retain its cached result", again)
			}
			bound.mu.Lock()
			retired := bound.packetSlots[0] == nil
			bound.mu.Unlock()
			if !retired {
				t.Error("retired claim still owns the packet slot")
			}
		})
	}
}

func TestServiceDispatcherQUICRetiredNormalCloseDoesNotPoisonReplacement(t *testing.T) {
	testServiceDispatcherQUICRetiredClose(t, false)
}

func TestServiceDispatcherQUICRetiredLossDoesNotPoisonReplacement(t *testing.T) {
	testServiceDispatcherQUICRetiredClose(t, true)
}

func testServiceDispatcherQUICRetiredClose(t *testing.T, timeout bool) {
	t.Helper()
	_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
	idle := 30 * time.Second
	if timeout {
		idle = time.Second
	}
	old := newDispatcherQUICCleanupFixture(t, bound, idle, nil, nil, nil)
	next, ended := make(chan *Claimed, 1), make(chan error, 2)
	preferences := make(chan bool, 2)
	observed := make(chan error, 1)
	observe := old.claimed.endObservation
	old.claimed.endObservation = func(err error, expected bool) {
		if !expected {
			observed <- err
		}
		observe(err, expected)
	}
	next <- old.claimed
	slots, err := tunnel.NewSlots(t.Context(), tunnel.SlotsConfig{SingleUse: true,
		Connect: func(ctx context.Context, _ uint8, preferTCP bool) (tunnel.SlotSession, error) {
			select {
			case claimed := <-next:
				preferences <- preferTCP
				return claimed, nil
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
		},
		SessionEnded: func(_ uint8, _ tunnel.SlotSession, err error) { ended <- err }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slots.Close() })
	if err := slots.Set(0, bound.assignmentKey(0)); err != nil {
		t.Fatal(err)
	}
	waitDispatcherQUICCleanupSlot(t, slots, old.claimed)
	if claimedAwait(t, preferences) {
		t.Fatal("original QUIC assignment unexpectedly preferred TCP")
	}
	if timeout {
		old.packets.drop.Store(true)
	} else if err := old.local.CloseWithError(0, "retire original"); err != nil {
		t.Fatal(err)
	}
	if err := claimedAwait(t, ended); timeout {
		assertDispatcherQUICCleanupCause(t, err, 0, false, true)
	} else if err != nil {
		t.Error("normal original closure became a serving failure", err)
	}
	waitDispatcherQUICCleanupSlot(t, slots, nil)
	if err := claimedAwait(t, observed); timeout {
		assertDispatcherQUICCleanupCause(t, err, 0, false, true)
	} else if err == nil {
		t.Error("cleanup erased the unexpected live-owner transport-loss observation")
	}
	bound.mu.Lock()
	assignments := bound.connections
	bound.mu.Unlock()
	assignments[0].PublisherConnectionId, err = opaqueid.New(opaqueid.PublisherConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	assignments[0].ConnectionAssignmentRevision++
	assignments[0].PublisherConnectionCredential = "replacement-assignment-credential"
	if err := bound.ApplyHeartbeat(controlv1.ServiceRunState{ServiceId: bound.prepared.Preparation.ServiceId,
		ServiceRunId: bound.prepared.Preparation.ServiceRunId, RunNumber: bound.prepared.Preparation.RunNumber,
		State: "ready", PublisherExpiresAt: time.Now().Add(time.Minute), PublisherConnections: assignments[:]}); err != nil {
		t.Fatal(err)
	}
	replacement := newDispatcherQUICCleanupFixture(t, bound, 30*time.Second, nil, nil, nil)
	if replacement.claimed.ref.PublisherConnectionID == old.claimed.ref.PublisherConnectionID ||
		replacement.claimed.ref.ConnectionAssignmentRevision <= old.claimed.ref.ConnectionAssignmentRevision ||
		old.claimed.ref.ServiceRunID != replacement.claimed.ref.ServiceRunID {
		t.Fatal("replacement reused the spent assignment or changed the service run")
	}
	next <- replacement.claimed
	if err := slots.Set(0, bound.assignmentKey(0)); err != nil {
		t.Fatal(err)
	}
	waitDispatcherQUICCleanupSlot(t, slots, replacement.claimed)
	if !claimedAwait(t, preferences) {
		t.Error("normal cleanup erased the replacement's TCP-first fallback preference")
	}
	if replacement.claimed.session.Err() != nil {
		t.Fatal("replacement did not establish a live authenticated session")
	}
	if err := old.claimed.Close(); err != nil {
		t.Error("retired dispatcher poisoned cleanup after replacement readiness", err)
	}
	bound.mu.Lock()
	current := bound.packetSlots[0] == replacement.claimed
	bound.mu.Unlock()
	if !current {
		t.Fatal("retired claim cleanup removed the replacement packet owner")
	}
	if err := replacement.local.CloseWithError(0, "retire replacement"); err != nil {
		t.Fatal(err)
	}
	if err := claimedAwait(t, ended); err != nil {
		t.Error("normal replacement closure became a serving failure", err)
	}
	if err := slots.Close(); err != nil {
		t.Error("slots retained the normally closed original or replacement dispatcher", err)
	}
	if old.outer.closes.Load() != 1 || replacement.outer.closes.Load() != 1 {
		t.Error("retiring old and replacement claims did not join each transport exactly once")
	}
}
