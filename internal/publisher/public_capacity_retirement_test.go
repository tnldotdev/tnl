package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// the first close wakes readers but keeps physical cleanup held. a second raw
// close returns early, as an idempotent underlying transport is allowed to do.
type retiringPublicStream struct {
	muxsession.Stream
	first   atomic.Bool
	entered chan struct{}
	gate    chan struct{}
	release func()
}

func (s *retiringPublicStream) Close() error {
	if !s.first.CompareAndSwap(false, true) {
		return s.Stream.Close()
	}
	err := s.Stream.Close()
	close(s.entered)
	<-s.gate
	return err
}

type retiringPublicVisitor struct {
	stream    *retiringPublicStream
	admission *publicVisitorAdmission
	client    *tls.Conn
	cancel    context.CancelFunc
}

func openRetiringPublicVisitor(t *testing.T, f *publicCapacityFixture) retiringPublicVisitor {
	t.Helper()
	ref := f.refs[0]
	ref.ConnectionAssignmentRevision++
	ref.PublisherConnectionID = fmt.Sprintf("retiring-%d", ref.ConnectionAssignmentRevision)
	publisher, relay := promotionSessionPair(t, ref)
	ctx, cancel := context.WithCancel(f.ctx)
	live, err := f.route.registerPublisherSession(ctx, publisher, ref)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f.refs[0], f.relays[0] = ref, relay
	s := &retiringPublicStream{entered: make(chan struct{}), gate: make(chan struct{})}
	s.release = sync.OnceFunc(func() { close(s.gate) })
	accepted := make(chan error, 1)
	t.Cleanup(func() {
		s.release()
		cancel()
		_ = publisher.Close()
		_ = awaitPublisherTest(t, accepted)
		f.route.unregisterPublisherSession(live)
		live.visitors.Wait()
	})
	go func() {
		incoming, err := publisher.AcceptVisitorStream(live.ctx)
		if err == nil {
			s.Stream = incoming.Stream
			incoming.Stream = s
			err = f.route.acceptVisitorForSession(live.ctx, incoming, live)
		}
		accepted <- err
		close(accepted)
	}()
	stream, err := f.open(0, false)
	if err != nil {
		t.Fatal(err)
	}
	client, err := f.secure(stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := awaitPublisherTest(t, accepted); err != nil {
		t.Fatal(err)
	}
	f.route.mu.Lock()
	a := f.route.streams[s]
	f.route.mu.Unlock()
	if a == nil {
		t.Fatal("real stream has no admission")
	}
	return retiringPublicVisitor{stream: s, admission: a, client: client, cancel: cancel}
}

func TestPublicCapacityRetirementJoinsPhysicalClose(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		for _, action := range []string{"cancel", "close", "drain"} {
			t.Run(fmt.Sprintf("admitted=%v/%s", admitted, action), func(t *testing.T) {
				f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
				visitor := openRetiringPublicVisitor(t, f)
				pending, authorized := 1, 0
				if admitted {
					response, err := capacityRequest(visitor.client, "/", false)
					if err != nil || response.StatusCode != 204 {
						t.Fatal("admission failed", err)
					}
					_ = response.Body.Close()
					pending, authorized = 0, 1
				}
				f.wait(pending, authorized)
				done := make(chan error, 1)
				t.Cleanup(func() { visitor.stream.release(); _ = awaitPublisherTest(t, done) })
				go func() {
					var err error
					switch action {
					case "cancel":
						visitor.cancel()
						visitor.admission.live.visitors.Wait()
					case "close":
						err = f.route.Close()
					case "drain":
						err = f.route.Drain(f.ctx)
					}
					done <- err
					close(done)
				}()
				awaitPublisherTest(t, visitor.stream.entered)
				if err := visitor.admission.commit(); err == nil {
					t.Fatal("authorization committed after physical close started")
				}
				second := make(chan struct{})
				go func() { _ = visitor.admission.connection.Close(); close(second) }()
				t.Cleanup(func() { visitor.stream.release(); awaitPublisherTest(t, second) })
				select {
				case <-visitor.admission.done:
					t.Fatal("permit released before physical close")
				case <-second:
					t.Fatal("second close skipped physical cleanup")
				case <-time.After(20 * time.Millisecond):
				}
				f.wait(pending, authorized)
				visitor.stream.release()
				awaitPublisherTest(t, visitor.admission.done)
				awaitPublisherTest(t, second)
				if err := awaitPublisherTest(t, done); err != nil {
					t.Fatal(err)
				}
				visitor.admission.retire()
				f.wait(0, 0)
			})
		}
	}
}

func TestPublicCapacityRetiringRelayCannotBorrowOnReconnect(t *testing.T) {
	f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	var held []retiringPublicVisitor
	for n := range PendingSetupsPerRelay {
		visitor := openRetiringPublicVisitor(t, f)
		visitor.cancel()
		awaitPublisherTest(t, visitor.stream.entered)
		held = append(held, visitor)
		f.wait(n+1, 0)
	}
	f.refs[0].PublisherConnectionID = "reconnected"
	f.refs[0].ConnectionAssignmentRevision++
	f.connect(0)
	_, err := f.open(0, false)
	var denied *tunnel.ProtocolError
	if !errors.As(err, &denied) || denied.Code != tunnelv1.CapacityExceeded {
		t.Fatal("same-domain reconnect borrowed retiring allowance", err)
	}
	stream, err := f.open(1, false)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.request(stream, "/healthy")
	if err != nil || response.StatusCode != 204 {
		t.Fatal("retiring relay starved healthy domain", err)
	}
	_ = response.Body.Close()
	for _, visitor := range held {
		visitor.stream.release()
		awaitPublisherTest(t, visitor.admission.done)
	}
	f.wait(0, 0)
}

func TestPublicCapacityRetirementJoinsRequestHandlers(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(204)
	}))
	visitor := openRetiringPublicVisitor(t, f)
	requested := make(chan struct{})
	go func() { _, _ = capacityRequest(visitor.client, "/held", false); close(requested) }()
	t.Cleanup(func() { unblock(); _ = visitor.client.Close(); awaitPublisherTest(t, requested) })
	awaitPublisherTest(t, entered)
	visitor.cancel()
	awaitPublisherTest(t, visitor.stream.entered)
	visitor.stream.release()
	awaitPublisherTest(t, visitor.admission.connection.done)
	select {
	case <-visitor.admission.done:
		t.Fatal("capacity retired while authorized handler was still active")
	default:
	}
	f.wait(0, 1)
	unblock()
	awaitPublisherTest(t, visitor.admission.done)
	f.wait(0, 0)
}

func TestPublicCapacityDrainDeadlineWhilePhysicalCloseHeld(t *testing.T) {
	f := newPublicCapacityFixture(t, 1, http.NotFoundHandler())
	visitor := openRetiringPublicVisitor(t, f)
	f.wait(1, 0)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	drained := make(chan error, 1)
	go func() { drained <- f.route.Drain(ctx); close(drained) }()
	t.Cleanup(func() {
		visitor.stream.release()
		awaitPublisherTest(t, drained)
	})
	awaitPublisherTest(t, visitor.stream.entered)
	cancel()
	select {
	case err := <-drained:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("drain after cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("drain ignored cancellation while physical close was held")
	}
	select {
	case <-visitor.admission.done:
		t.Fatal("canceled drain released capacity before physical cleanup joined")
	default:
	}
	f.wait(1, 0)
	visitor.stream.release()
	awaitPublisherTest(t, visitor.admission.done)
	f.wait(0, 0)
}

func TestPublicCapacityCommitDrainRace(t *testing.T) {
	for range 100 {
		// each race owns a fresh run; a drained run cannot restart admission.
		route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", StreamCapacity: 1, Handler: http.NotFoundHandler()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = route.Close() })
		connection, peer := net.Pipe()
		a, err := reserveTestPublicSetup(route, connection)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.retire(); _ = peer.Close() })
		start, committed, drained := make(chan struct{}), make(chan error, 1), make(chan struct{})
		go func() { <-start; committed <- a.commit() }()
		go func() { <-start; route.stopAdmissions(); close(drained) }()
		close(start)
		err = <-committed
		<-drained
		stopped := a.stopPending()
		if err == nil && stopped != nil {
			t.Fatal("drain selected a committed visitor from a stale snapshot")
		}
		if err != nil && stopped == nil {
			t.Fatal("drain retained an uncommitted setup")
		}
		a.retire()
		_ = peer.Close()
		if err := route.Close(); err != nil {
			t.Fatal(err)
		}
		if route.pendingStreams != 0 || route.authorizedStreams != 0 || len(route.pendingRelays) != 0 {
			t.Fatal("commit/drain race retained retired capacity")
		}
	}
}

func TestPublicCapacityDrainExpiredAndDeadlineContexts(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("admitted=%v/expired=%v", admitted, expired), func(t *testing.T) {
				f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
				visitor := openRetiringPublicVisitor(t, f)
				pending, authorized := 1, 0
				if admitted {
					response, err := capacityRequest(visitor.client, "/", false)
					if err != nil || response.StatusCode != 204 {
						t.Fatal("admission failed", err)
					}
					_ = response.Body.Close()
					pending, authorized = 0, 1
				}
				deadline := time.Now().Add(100 * time.Millisecond)
				if expired {
					deadline = time.Now().Add(-time.Second)
				}
				ctx, cancel := context.WithDeadline(f.ctx, deadline)
				defer cancel()
				drained := make(chan error, 1)
				go func() { drained <- f.route.Drain(ctx); close(drained) }()
				t.Cleanup(func() { visitor.stream.release(); awaitPublisherTest(t, drained) })
				awaitPublisherTest(t, visitor.stream.entered)
				if err := awaitPublisherTest(t, drained); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("drain lost its deadline", err)
				}
				f.wait(pending, authorized)
				closed := make(chan error, 1)
				go func() { closed <- f.route.Close(); close(closed) }()
				t.Cleanup(func() { visitor.stream.release(); awaitPublisherTest(t, closed) })
				select {
				case <-closed:
					t.Fatal("run close did not join held shutdown")
				case <-visitor.admission.done:
					t.Fatal("drain released capacity before physical close")
				case <-time.After(20 * time.Millisecond):
				}
				visitor.stream.release()
				if err := awaitPublisherTest(t, closed); err != nil {
					t.Fatal(err)
				}
				awaitPublisherTest(t, visitor.admission.done)
				f.wait(0, 0)
			})
		}
	}
}

type queuedPublicClose struct {
	net.Conn
	entered, release chan struct{}
}

func (c *queuedPublicClose) Close() error {
	close(c.entered)
	<-c.release
	return c.Conn.Close()
}

func TestPublicCapacityDrainDeadlineWhileQueueCloseHeld(t *testing.T) {
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Handler: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	connection, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	queued := &queuedPublicClose{Conn: connection, entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(queued.release) })
	defer release()
	a, err := reserveTestPublicSetup(route, queued)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.commit(); err != nil {
		t.Fatal(err)
	}
	if !route.queue.enqueue(a.connection) {
		t.Fatal("fixture queue rejected its connection")
	}
	// register the real queue with net/http, without consuming its connection.
	// shutdown calls the listener's Close synchronously before checking ctx.
	listener := &heldAcceptListener{publicURLListener: route.queue, entered: make(chan struct{})}
	served := make(chan error, 1)
	go func() { served <- route.http.Serve(listener); close(served) }()
	awaitPublisherTest(t, listener.entered)
	retired := make(chan struct{})
	go func() { <-a.connection.done; a.retire(); close(retired) }()
	t.Cleanup(func() { release(); awaitPublisherTest(t, served); awaitPublisherTest(t, retired) })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	drained := make(chan error, 1)
	go func() { drained <- route.Drain(ctx); close(drained) }()
	t.Cleanup(func() { release(); awaitPublisherTest(t, drained) })
	awaitPublisherTest(t, queued.entered)
	cancel()
	if err := awaitPublisherTest(t, drained); !errors.Is(err, context.Canceled) {
		t.Fatal("queue close hid drain cancellation", err)
	}
	route.mu.Lock()
	count := route.authorizedStreams
	route.mu.Unlock()
	if count != 1 {
		t.Fatal("queue close released unjoined capacity", count)
	}
	release()
	awaitPublisherTest(t, retired)
}

type heldAcceptListener struct {
	*publicURLListener
	entered chan struct{}
}

func (l *heldAcceptListener) Accept() (net.Conn, error) {
	close(l.entered)
	<-l.closed
	return nil, net.ErrClosed
}
