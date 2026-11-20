package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type httpAdmissionTestConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
	closes   atomic.Int32
	entered  chan struct{}
	release  <-chan struct{}
	closeErr error
}

func (c *httpAdmissionTestConn) Close() error {
	c.closes.Add(1)
	err := c.Conn.Close()
	close(c.entered)
	if c.release != nil {
		<-c.release
	}
	return errors.Join(err, c.closeErr)
}

func (c *httpAdmissionTestConn) SetDeadline(until time.Time) error {
	c.mu.Lock()
	c.deadline = until
	c.mu.Unlock()
	return c.Conn.SetDeadline(until)
}

func newHTTPAdmissionTestRun(t *testing.T, capacity int) *Bound {
	t.Helper()
	prepared, bound, _, _ := privateFixture(t, "127.0.0.1:1")
	prepared.managedProtocol = config.ProtocolHTTP
	bound.streamCapacity = capacity
	return bound
}

func TestDefaultPublisherStreamCapacityExceedsIngressDefault(t *testing.T) {
	bound := newHTTPAdmissionTestRun(t, 0)
	ref := bound.prepared.connectionRef(bound.connections[0])
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
		if bound.reservedStreams != 0 {
			t.Error("final stream cleanup retained capacity", bound.reservedStreams)
		}
	}()
	for range 4096 {
		release, ok := bound.reserveStream(ref)
		if !ok {
			t.Fatal("publisher default stopped below its advertised capacity")
		}
		releases = append(releases, release)
	}
	if _, ok := bound.reserveStream(ref); ok {
		t.Fatal("publisher default failed to enforce active stream capacity")
	}
	releases[0]()
	releases[0]()
	release, ok := bound.reserveStream(ref)
	if !ok {
		t.Fatal("joined cleanup did not release its stream slot")
	}
	releases = append(releases, release)
}

func openHTTPAdmissionTest(t *testing.T, bound *Bound, slot uint8, wire *httpAdmissionTestConn) (*httpAdmission, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	if wire == nil {
		wire = &httpAdmissionTestConn{}
	}
	wire.Conn, wire.entered = server, make(chan struct{})
	bound.mu.Lock()
	ref := bound.prepared.connectionRef(bound.connections[slot])
	bound.mu.Unlock()
	header := privateHeader(t, ref)
	header.PublicService.DestinationPort = 443
	visitor, code := bound.reserveHTTP(t.Context(), ref, wire, header)
	if visitor == nil {
		_ = client.Close()
		_ = server.Close()
		t.Fatal("reserve owned HTTP setup", code)
	}
	return visitor.http, client
}

func TestHTTPAdmissionFixtureReadsCurrentHeartbeatAssignment(t *testing.T) {
	bound := newHTTPAdmissionTestRun(t, 1)
	bound.mu.Lock()
	original := bound.prepared.connectionRef(bound.connections[0])
	state := controlv1.ServiceRunState{
		ServiceId: bound.prepared.Preparation.ServiceId, ServiceRunId: bound.prepared.Preparation.ServiceRunId,
		RunNumber: bound.prepared.Preparation.RunNumber, State: controlv1.ServiceRunStateState("ready"),
		PublisherExpiresAt:   time.Now().Add(time.Minute),
		PublisherConnections: append([]controlv1.ConnectionAssignment(nil), bound.connections[:]...),
	}
	bound.mu.Unlock()
	var err error
	state.PublisherConnections[0].PublisherConnectionId, err = opaqueid.New(opaqueid.PublisherConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	state.PublisherConnections[0].ConnectionAssignmentRevision++
	// the same fixture helper must capture the installed heartbeat replacement,
	// not a reference copied before the run owner started its workers.
	updated := make(chan error, 1)
	go func() { updated <- bound.ApplyHeartbeat(state) }()
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	a, client := openHTTPAdmissionTest(t, bound, 0, nil)
	defer client.Close()
	defer a.retire()
	if a.ref == original || a.ref.PublisherConnectionID != state.PublisherConnections[0].PublisherConnectionId ||
		a.ref.ConnectionAssignmentRevision != uint64(state.PublisherConnections[0].ConnectionAssignmentRevision) ||
		!bound.current(a.ref) {
		t.Fatal("HTTP admission fixture used a stale publisher connection reference")
	}
	assertHTTPAdmissionCharges(t, a, 1, 0, 0)
	if err := a.retire(); err != nil {
		t.Fatal(err)
	}
	assertHTTPAdmissionCharges(t, a, 0, 0, 0)
}

func assertHTTPAdmissionCharges(t *testing.T, a *httpAdmission, pending, sources, final int) {
	t.Helper()
	b := a.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	var sourceTotal int
	for _, count := range b.httpPendingSources {
		sourceTotal += count
	}
	if b.httpPending != pending || b.httpPendingRelays[a.ref.RelayServiceID] != pending ||
		sourceTotal != sources || b.reservedStreams != final || len(b.active) != pending+final {
		t.Fatal("HTTP charge differs from joined ownership", b.httpPending, b.httpPendingRelays,
			b.httpPendingSources, b.reservedStreams, len(b.active), pending, sources, final)
	}
}

func TestHTTPAdmissionPhasesRetainChargeThroughPhysicalAndDecisionCleanup(t *testing.T) {
	for _, phase := range []string{"unverified", "verified", "final", "ready"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bound := newHTTPAdmissionTestRun(t, 1)
				closeErr, decisionErr := errors.New("physical close failed"), errors.New("capacity cleanup failed")
				closeRelease, decisionRelease := make(chan struct{}), make(chan struct{})
				releaseClose := sync.OnceFunc(func() { close(closeRelease) })
				releaseDecision := sync.OnceFunc(func() { close(decisionRelease) })
				defer releaseClose()
				defer releaseDecision()
				wire := &httpAdmissionTestConn{release: closeRelease, closeErr: closeErr}
				a, client := openHTTPAdmissionTest(t, bound, 0, wire)
				defer client.Close()
				if phase != "unverified" {
					if err := a.verifySource(netip.MustParseAddr("192.0.2.1")); err != nil {
						t.Fatal(err)
					}
				}
				var decisionResult chan error
				if phase == "final" || phase == "ready" {
					entered := make(chan struct{})
					decisionResult = make(chan error, 1)
					go func() {
						decisionResult <- a.reserveCapacity(t.Context(), func(call context.Context) error {
							close(entered)
							if phase == "final" {
								<-decisionRelease
								return errors.Join(context.Cause(call), decisionErr)
							}
							return nil
						})
					}()
					<-entered
					synctest.Wait()
					if phase == "ready" {
						if err := <-decisionResult; err != nil {
							t.Fatal(err)
						}
					}
				}
				pending, sources, final := 1, 0, 0
				if phase == "verified" {
					sources = 1
				}
				if phase == "final" || phase == "ready" {
					pending, final = 0, 1
				}
				assertHTTPAdmissionCharges(t, a, pending, sources, final)
				readResult := make(chan error, 1)
				go func() { _, err := client.Read(make([]byte, 1)); readResult <- err }()
				retired := make(chan error, 1)
				go func() { retired <- a.retire() }()
				<-wire.entered
				synctest.Wait()
				select {
				case err := <-readResult:
					if err == nil {
						t.Fatal("physical close did not interrupt the reader")
					}
				default:
					t.Fatal("physical close waited for owned cleanup before interrupting IO")
				}
				assertHTTPAdmissionCharges(t, a, pending, sources, final)
				bound.mu.Lock()
				_, retiring := a.state.(retiringHTTPAdmission)
				bound.mu.Unlock()
				if !retiring {
					t.Fatal("close did not retain an explicit retiring phase")
				}
				select {
				case <-a.completed:
					t.Fatal("blocked physical cleanup released ownership")
				default:
				}
				releaseClose()
				synctest.Wait()
				if phase == "final" {
					assertHTTPAdmissionCharges(t, a, 0, 0, 1)
					select {
					case <-a.completed:
						t.Fatal("capacity cleanup had not joined before final capacity was released")
					default:
					}
					releaseDecision()
					if err := <-decisionResult; !errors.Is(err, decisionErr) {
						t.Fatal("capacity cancellation hid independent cleanup", err)
					}
				}
				err := <-retired
				if !errors.Is(err, closeErr) || phase == "final" && !errors.Is(err, decisionErr) {
					t.Fatal("retirement discarded independent owned cleanup", err)
				}
				if again := a.retire(); !errors.Is(again, closeErr) || wire.closes.Load() != 1 {
					t.Fatal("retirement/close did not retain one physical result", again, wire.closes.Load())
				}
				assertHTTPAdmissionCharges(t, a, 0, 0, 0)
				bound.mu.Lock()
				_, released := a.state.(releasedHTTPAdmission)
				a.retireLocked()
				_, stillReleased := a.state.(releasedHTTPAdmission)
				bound.mu.Unlock()
				if !released || !stillReleased || httpAdmissionRoutineError(err) {
					t.Fatal("released phase revived or cancellation classified cleanup as routine", err)
				}
			})
		})
	}
}

func TestHTTPAdmissionConcurrentWaitersOwnOneCapacityExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bound := newHTTPAdmissionTestRun(t, 1)
		a, client := openHTTPAdmissionTest(t, bound, 0, nil)
		defer client.Close()
		defer a.retire()
		if err := a.verifySource(netip.MustParseAddr("192.0.2.1")); err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan context.Context, 1), make(chan struct{})
		releaseDecision := sync.OnceFunc(func() { close(release) })
		defer releaseDecision()
		var calls atomic.Int32
		reserve := func(call context.Context) error {
			calls.Add(1)
			entered <- call
			<-release
			return nil
		}
		first, cancelFirst := context.WithCancel(t.Context())
		defer cancelFirst()
		firstResult := make(chan error, 1)
		go func() { firstResult <- a.reserveCapacity(first, reserve) }()
		shared := <-entered
		const siblings = 8
		results := make(chan error, siblings)
		for range siblings {
			go func() { results <- a.reserveCapacity(t.Context(), reserve) }()
		}
		cancelFirst()
		if err := <-firstResult; !errors.Is(err, context.Canceled) {
			t.Fatal("canceled waiter did not leave independently", err)
		}
		synctest.Wait()
		if shared.Err() != nil || calls.Load() != 1 || len(results) != 0 {
			t.Fatal("one HTTP/2 waiter canceled or duplicated the connection's decision", shared.Err(), calls.Load(), len(results))
		}
		if until, ok := shared.Deadline(); !ok || !until.Equal(a.setupUntil) {
			t.Fatal("shared decision borrowed a request deadline", until, a.setupUntil)
		}
		assertHTTPAdmissionCharges(t, a, 0, 0, 1)
		releaseDecision()
		for range siblings {
			if err := <-results; err != nil {
				t.Fatal("sibling lost the shared ingress acknowledgement", err)
			}
		}
		if err := a.reserveCapacity(t.Context(), reserve); err != nil || calls.Load() != 1 {
			t.Fatal("keepalive repeated final capacity or ingress work", err, calls.Load())
		}
		bound.mu.Lock()
		_, ready := a.state.(readyHTTPAdmission)
		bound.mu.Unlock()
		if !ready {
			t.Fatal("joined capacity result did not finish setup")
		}
		time.Sleep(11 * time.Second)
		synctest.Wait()
		select {
		case <-a.visitor.Conn.(*httpAdmissionTestConn).entered:
			t.Fatal("disarmed setup timer closed a ready keepalive visitor")
		default:
		}
	})
}

func TestHTTPAdmissionDenialIsOneRetainedConnectionDecision(t *testing.T) {
	for _, local := range []bool{true, false} {
		t.Run(map[bool]string{true: "final-capacity", false: "ingress-denial"}[local], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bound := newHTTPAdmissionTestRun(t, 1)
				a, client := openHTTPAdmissionTest(t, bound, 0, nil)
				defer client.Close()
				defer a.retire()
				if err := a.verifySource(netip.MustParseAddr("192.0.2.1")); err != nil {
					t.Fatal(err)
				}
				release := func() {}
				if local {
					var ok bool
					release, ok = bound.reserveStream(a.ref)
					if !ok {
						t.Fatal("reserve existing physical visitor")
					}
				}
				var calls int
				reserve := func(context.Context) error {
					calls++
					return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
				}
				for attempt := range 2 {
					err := a.reserveCapacity(t.Context(), reserve)
					var rejection *tunnel.ProtocolError
					if !errors.As(err, &rejection) || rejection.Code != tunnelv1.CapacityExceeded {
						t.Fatal("capacity denial was not retained", attempt, err)
					}
					// freeing unrelated capacity cannot authorize a second
					// connection decision after a denied first request.
					release()
				}
				wantCalls, pending, sources, final := 1, 0, 0, 1
				if local {
					wantCalls, pending, sources, final = 0, 1, 1, 0
				}
				if calls != wantCalls {
					t.Fatal("denied connection repeated the ingress exchange", calls, wantCalls)
				}
				assertHTTPAdmissionCharges(t, a, pending, sources, final)
			})
		})
	}
}

func TestHTTPAdmissionSetupFenceDoesNotRestartAndLateIngressCannotPromote(t *testing.T) {
	for _, phase := range []string{"unverified", "verified", "final"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bound := newHTTPAdmissionTestRun(t, 1)
				a, client := openHTTPAdmissionTest(t, bound, 0, nil)
				defer client.Close()
				until := a.setupUntil
				time.Sleep(3 * time.Second)
				if phase != "unverified" {
					if err := a.verifySource(netip.MustParseAddr("192.0.2.1")); err != nil {
						t.Fatal(err)
					}
				}
				time.Sleep(3 * time.Second)
				if err := a.visitor.SetDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
				wire := a.visitor.Conn.(*httpAdmissionTestConn)
				wire.mu.Lock()
				socketUntil := wire.deadline
				wire.mu.Unlock()
				if !socketUntil.Equal(until) {
					t.Fatal("a TLS/header deadline reset escaped the original setup bound", socketUntil, until)
				}
				var decisionResult chan error
				release := make(chan struct{})
				releaseDecision := sync.OnceFunc(func() { close(release) })
				defer releaseDecision()
				if phase == "final" {
					entered := make(chan struct{})
					decisionResult = make(chan error, 1)
					go func() {
						decisionResult <- a.reserveCapacity(t.Context(), func(call context.Context) error {
							close(entered)
							<-call.Done()
							<-release
							return nil // an acknowledgement after the fixed fence
						})
					}()
					<-entered
				}
				time.Sleep(3 * time.Second)
				synctest.Wait()
				select {
				case <-wire.entered:
					t.Fatal("setup closed before its original ten seconds")
				default:
				}
				time.Sleep(time.Second)
				synctest.Wait()
				select {
				case <-wire.entered:
				default:
					t.Fatal("setup phase restarted the fixed deadline")
				}
				pending, sources, final := 1, 0, 0
				if phase == "verified" {
					sources = 1
				}
				if phase == "final" {
					pending, final = 0, 1
				}
				assertHTTPAdmissionCharges(t, a, pending, sources, final)
				retired := make(chan error, 1)
				go func() { retired <- a.retire() }()
				synctest.Wait()
				if phase == "final" {
					select {
					case <-a.completed:
						t.Fatal("deadline returned final capacity before late ingress work joined")
					default:
					}
					releaseDecision()
					if err := <-decisionResult; err == nil {
						t.Fatal("late ingress acknowledgement revived expired setup")
					}
				}
				<-retired
				assertHTTPAdmissionCharges(t, a, 0, 0, 0)
			})
		})
	}
}

func TestHTTPAdmissionRunAndRelayAllowancesUseCapturedAssignment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bound := newHTTPAdmissionTestRun(t, 1)
		var owned []*httpAdmission
		defer func() {
			for _, a := range owned {
				_ = a.retire()
			}
		}()
		for slot := range uint8(2) {
			for range maxHTTPPendingRelay {
				a, client := openHTTPAdmissionTest(t, bound, slot, nil)
				defer client.Close()
				owned = append(owned, a)
			}
		}
		bound.mu.Lock()
		pending, final, visitors := bound.httpPending, bound.reservedStreams, len(bound.active)
		bound.mu.Unlock()
		if pending != maxHTTPPendingRun || final != 0 || visitors != maxHTTPPendingRun {
			t.Fatal("pending HTTP setups spent final capacity or lost the run allowance", pending, final, visitors)
		}
		ref := owned[0].ref
		header := privateHeader(t, ref)
		header.PublicService.DestinationPort = 443
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		if visitor, code := bound.reserveHTTP(t.Context(), ref, server, header); visitor != nil || code != tunnelv1.CapacityExceeded {
			t.Fatal("thirty-third pending setup bypassed the run allowance", visitor, code)
		}
		header.ConnectionAssignmentRevision++
		if visitor, code := bound.reserveHTTP(t.Context(), ref, server, header); visitor != nil || code != tunnelv1.StaleConnectionAssignment {
			t.Fatal("full capacity hid stale exact assignment", visitor, code)
		}
		// a current claim cannot borrow a full sibling relay's setup slots.
		_ = owned[maxHTTPPendingRelay].retire()
		header = privateHeader(t, ref)
		header.PublicService.DestinationPort = 443
		if visitor, code := bound.reserveHTTP(t.Context(), ref, server, header); visitor != nil || code != tunnelv1.CapacityExceeded {
			t.Fatal("free run capacity bypassed the captured relay allowance", visitor, code)
		}
	})
}

func TestHTTPAdmissionDrainJoinsMetadataOwnerBeforeBodyWorkerEntry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bound := newHTTPAdmissionTestRun(t, 1)
		closeErr := errors.New("metadata physical cleanup failed")
		a, client := openHTTPAdmissionTest(t, bound, 0, &httpAdmissionTestConn{closeErr: closeErr})
		defer client.Close()
		defer a.retire()
		until := time.Now().Add(5 * time.Second)
		if err := bound.startDrain(until); !errors.Is(err, closeErr) {
			t.Fatal("drain discarded pending physical cleanup", err)
		}
		joined := make(chan error, 1)
		go func() { joined <- bound.joinDrain() }()
		synctest.Wait()
		select {
		case <-joined:
			t.Fatal("drain joined only body workers and forgot accepted metadata ownership")
		default:
		}
		assertHTTPAdmissionCharges(t, a, 1, 0, 0)
		if err := a.verifySource(netip.MustParseAddr("192.0.2.1")); err == nil {
			t.Fatal("draining setup acquired a source charge")
		}
		if err := a.reserveCapacity(t.Context(), func(context.Context) error {
			t.Error("draining setup entered ingress capacity")
			return nil
		}); err == nil {
			t.Fatal("draining setup acquired final capacity")
		}
		if err := a.retire(); !errors.Is(err, closeErr) {
			t.Fatal("retirement lost the drain close result", err)
		}
		if err := <-joined; !errors.Is(err, closeErr) {
			t.Fatal("joined drain lost an independent metadata cleanup failure", err)
		}
		assertHTTPAdmissionCharges(t, a, 0, 0, 0)
		bound.mu.Lock()
		stillUntil := bound.drainUntil
		bound.mu.Unlock()
		if !stillUntil.Equal(until) {
			t.Fatal("metadata joining restarted the run drain deadline")
		}
	})
}

func TestHTTPAdmissionFiringTimerCancellationAndRetirementJoinOnePhysicalClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bound := newHTTPAdmissionTestRun(t, 1)
		owner, cancelOwner := context.WithCancel(t.Context())
		defer cancelOwner()
		client, server := net.Pipe()
		defer client.Close()
		released := make(chan struct{})
		release := sync.OnceFunc(func() { close(released) })
		defer release()
		cleanup := errors.New("timed out stream physical cleanup failed")
		wire := &httpAdmissionTestConn{Conn: server, entered: make(chan struct{}),
			release: released, closeErr: errors.Join(context.Canceled, cleanup)}
		ref := bound.prepared.connectionRef(bound.connections[0])
		header := privateHeader(t, ref)
		header.PublicService.DestinationPort = 443
		visitor, code := bound.reserveHTTP(owner, ref, wire, header)
		if visitor == nil {
			t.Fatal(code)
		}
		a := visitor.http
		// observe all three real close paths after cancellation, before they
		// contend on closeOnce. synctest cannot establish quiescence with a
		// waiter on that mutex while this test holds physical cleanup.
		closing := make(chan struct{}, 3)
		bound.mu.Lock()
		cancel := a.cancel
		a.cancel = func() {
			cancel()
			closing <- struct{}{}
		}
		bound.mu.Unlock()
		if err := a.verifySource(netip.MustParseAddr("192.0.2.1")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Second)
		<-wire.entered
		<-closing // the original setup timer reached physical close
		cancelOwner()
		retired := make(chan error, 1)
		go func() { retired <- a.retire() }()
		// cancellation and retirement have both entered close, in either order.
		for range 2 {
			<-closing
		}
		assertHTTPAdmissionCharges(t, a, 1, 1, 0)
		for _, done := range []<-chan struct{}{a.timerDone, a.ownerDone, a.completed} {
			select {
			case <-done:
				t.Fatal("a firing timer/cancellation callback detached from unjoined physical cleanup")
			default:
			}
		}
		release()
		err := <-retired
		if !errors.Is(err, cleanup) || !errors.Is(err, context.Canceled) ||
			httpAdmissionRoutineError(err) || wire.closes.Load() != 1 {
			t.Fatal("racing timer/cancellation lost independent cleanup or closed twice", err, wire.closes.Load())
		}
		for _, done := range []<-chan struct{}{a.timerDone, a.ownerDone, a.completed} {
			select {
			case <-done:
			default:
				t.Fatal("retirement returned before an owned callback joined")
			}
		}
		assertHTTPAdmissionCharges(t, a, 0, 0, 0)
	})
}

func TestHTTPAdmissionCommittedIngressDecisionRetainsOriginalDrainFence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bound := newHTTPAdmissionTestRun(t, 1)
		a, client := openHTTPAdmissionTest(t, bound, 0, nil)
		defer client.Close()
		defer a.retire()
		if err := a.verifySource(netip.MustParseAddr("192.0.2.1")); err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		releaseDecision := sync.OnceFunc(func() { close(release) })
		defer releaseDecision()
		result := make(chan error, 1)
		go func() {
			result <- a.reserveCapacity(t.Context(), func(context.Context) error {
				close(entered)
				<-release
				return nil
			})
		}()
		<-entered
		until := time.Now().Add(5 * time.Second)
		if err := bound.startDrain(until); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case <-a.visitor.Conn.(*httpAdmissionTestConn).entered:
			t.Fatal("drain interrupted an already committed ingress decision")
		default:
		}
		joined := make(chan error, 1)
		go func() { joined <- bound.joinDrain() }()
		time.Sleep(3 * time.Second)
		releaseDecision()
		if err := <-result; err != nil {
			t.Fatal("committed bounded ingress decision could not finish during drain", err)
		}
		synctest.Wait()
		assertHTTPAdmissionCharges(t, a, 0, 0, 1)
		select {
		case <-joined:
			t.Fatal("drain returned before the ready physical visitor retired")
		default:
		}
		_ = a.retire()
		if err := <-joined; err != nil {
			t.Fatal("joined drain lost its original deadline", err)
		}
		if !bound.drainUntil.Equal(until) {
			t.Fatal("capacity success restarted the run's drain deadline")
		}
		assertHTTPAdmissionCharges(t, a, 0, 0, 0)
	})
}

func TestHTTPAdmissionRoutineTerminationCannotHideIndependentCleanup(t *testing.T) {
	cleanup := errors.New("independent physical cleanup failed")
	for _, termination := range []error{
		context.Canceled, net.ErrClosed,
		&tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded},
		&yamux.StreamError{Remote: true, ErrorCode: 17},
		&quic.StreamError{Remote: true, ErrorCode: 17},
	} {
		if !httpAdmissionRoutineError(termination) {
			t.Fatal("ordinary stream rejection became terminal run failure", termination)
		}
		if httpAdmissionRoutineError(errors.Join(termination, cleanup)) {
			t.Fatal("ordinary rejection/cancellation hid independent cleanup", termination)
		}
	}
}
