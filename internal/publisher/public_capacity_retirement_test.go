package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// model a concurrent-idempotent transport close: the first close wakes readers
// but still owns retiring cleanup, while later closes return. yamux CloseWrite
// likewise marks halfClosed before sending its close frame.
type retiringPublicStream struct {
	muxsession.Stream
	first   atomic.Bool
	entered chan struct{}
	gate    chan struct{}
	joined  chan struct{}
	release func()
}

func (s *retiringPublicStream) Close() error {
	if !s.first.CompareAndSwap(false, true) {
		return s.Stream.Close()
	}
	err := s.Stream.Close()
	close(s.entered)
	<-s.gate
	close(s.joined)
	return err
}

type retiringPublicVisitor struct {
	stream    *retiringPublicStream
	admission *publicVisitorAdmission
	client    *tls.Conn
	cancel    context.CancelFunc
}

// each visitor comes from a real, newer session in the same trusted domain.
// install gate cleanup before any opening/handshake can fail.
func openRetiringPublicVisitor(t *testing.T, f *publicCapacityFixture, sequence uint64) retiringPublicVisitor {
	t.Helper()
	ref := f.refs[0]
	ref.ConnectionAssignmentRevision++
	ref.PublisherConnectionID = fmt.Sprintf("retiring-session-%d", sequence)
	publisher, relay := promotionSessionPair(t, ref)
	ctx, cancel := context.WithCancel(f.ctx)
	live, err := f.route.registerPublisherSession(ctx, publisher, ref)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f.refs[0], f.relays[0] = ref, relay
	s := &retiringPublicStream{entered: make(chan struct{}), gate: make(chan struct{}), joined: make(chan struct{})}
	s.release = sync.OnceFunc(func() { close(s.gate) })
	accepted := make(chan error, 1)
	t.Cleanup(func() {
		s.release()
		cancel()
		_ = publisher.Close()
		// join the accept worker even if opening or visitor TLS failed early.
		_ = awaitPublisherTest(t, accepted)
		if s.Stream != nil {
			_ = s.Close()
			awaitPublisherTest(t, s.joined)
		}
		f.route.unregisterPublisherSession(live)
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
	client, err := f.open(0, 0, sequence)
	if err != nil {
		t.Fatal(err)
	}
	secured, err := f.secure(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := awaitPublisherTest(t, accepted); err != nil {
		t.Fatal(err)
	}
	f.route.mu.Lock()
	admission := f.route.streams[s]
	f.route.mu.Unlock()
	if admission == nil {
		t.Fatal("missing real public admission")
	}
	return retiringPublicVisitor{stream: s, admission: admission, client: secured, cancel: cancel}
}

func assertPublicVisitorRetiring(t *testing.T, f *publicCapacityFixture, visitor retiringPublicVisitor) {
	t.Helper()
	awaitPublisherTest(t, visitor.stream.entered)
	select {
	case <-visitor.admission.done:
		f.route.mu.Lock()
		pending, domains := f.route.pendingStreams, len(f.route.pendingRelays)
		f.route.mu.Unlock()
		t.Fatalf("pending permit released before cancellation close callback joined: pending=%d domains=%d", pending, domains)
	case <-time.After(100 * time.Millisecond):
		// the pending owner must remain until the close callback can join.
	}
}

func TestPublicURLStreamCapacityPendingPermitWaitsForCancellationCloseCallback(t *testing.T) {
	f := newPublicCapacityFixture(t, 1, http.NotFoundHandler())
	visitor := openRetiringPublicVisitor(t, f, 1)
	f.wait(1, 0)
	visitor.cancel()
	assertPublicVisitorRetiring(t, f, visitor)
	f.wait(1, 0)
	liveDone, handlersDone := make(chan struct{}), make(chan struct{})
	go func() { visitor.admission.live.visitors.Wait(); close(liveDone) }()
	go func() { f.route.handlers.Wait(); close(handlersDone) }()
	t.Cleanup(func() {
		visitor.stream.release()
		awaitPublisherTest(t, liveDone)
		awaitPublisherTest(t, handlersDone)
	})
	for _, done := range []<-chan struct{}{visitor.admission.done, liveDone, handlersDone} {
		select {
		case <-done:
			t.Fatal("public completion escaped the gated close owner")
		default:
		}
	}
	visitor.stream.release()
	awaitPublisherTest(t, visitor.stream.joined)
	awaitPublisherTest(t, visitor.admission.done)
	awaitPublisherTest(t, liveDone)
	awaitPublisherTest(t, handlersDone)
	f.wait(0, 0)
}

func TestPublicURLStreamCapacityConcurrentCloseOwnersJoin(t *testing.T) {
	f := newPublicCapacityFixture(t, 1, http.NotFoundHandler())
	visitor := openRetiringPublicVisitor(t, f, 1)
	first, second := make(chan error, 1), make(chan error, 1)
	secondStarted := false
	t.Cleanup(func() {
		visitor.stream.release()
		_ = awaitPublisherTest(t, first)
		if secondStarted {
			_ = awaitPublisherTest(t, second)
		}
	})
	go func() { first <- visitor.admission.connection.Close(); close(first) }()
	awaitPublisherTest(t, visitor.stream.entered)
	// force another close to own retirement before the life callback or
	// net/http closes. idempotence alone must not let either caller skip it.
	secondStarted = true
	go func() { second <- visitor.admission.connection.Close(); close(second) }()
	select {
	case err := <-second:
		t.Fatal("concurrent close returned before the physical close joined", err)
	case <-time.After(100 * time.Millisecond):
	}
	assertPublicVisitorRetiring(t, f, visitor)
	f.wait(1, 0)
	visitor.stream.release()
	if err := awaitPublisherTest(t, first); err != nil {
		t.Fatal(err)
	}
	if err := awaitPublisherTest(t, second); err != nil {
		t.Fatal(err)
	}
	awaitPublisherTest(t, visitor.admission.done)
	f.wait(0, 0)
}

func TestPublicURLStreamCapacityRetiringDomainCannotBorrowOnReconnect(t *testing.T) {
	for _, capacity := range []int{1, 2} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			var reached atomic.Int32
			f := newPublicCapacityFixture(t, capacity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached.Add(1)
				if r.Header.Get(visitorTokenHeader) != "" {
					t.Error("visitor credential reached target")
				}
				if r.URL.Path == "/hold" {
					_, _ = io.WriteString(w, "prefix")
					w.(http.Flusher).Flush()
					select {
					case <-release:
						_, _ = io.WriteString(w, "finished")
					case <-r.Context().Done():
					}
					return
				}
				_, _ = io.WriteString(w, "fresh")
			}))
			var retiring []retiringPublicVisitor
			for sequence := uint64(1); sequence <= PendingSetupsPerRelay; sequence++ {
				visitor := openRetiringPublicVisitor(t, f, sequence)
				visitor.cancel()
				assertPublicVisitorRetiring(t, f, visitor)
				retiring = append(retiring, visitor)
				f.wait(int(sequence), 0)
			}
			// a fifth real session cannot reset the run-owned domain quota, even
			// with a newer valid MAC/sequence on the same canonical C-sized slot.
			f.refs[0].PublisherConnectionID = "retiring-domain-reconnected"
			f.refs[0].ConnectionAssignmentRevision++
			f.connect(0)
			extra, err := f.open(0, 0, 5)
			if err != nil {
				t.Fatal(err)
			}
			_, err = extra.Read(make([]byte, 1))
			_ = extra.Close()
			var denied *tunnel.ProtocolError
			if !errors.As(err, &denied) || denied.Code != tunnelv1.CapacityExceeded {
				t.Fatal("same-domain reconnect borrowed retiring allowance", err)
			}
			f.wait(PendingSetupsPerRelay, 0)
			var responses []*http.Response
			for slot := range uint32(capacity) {
				stream, err := f.open(1, slot, 10)
				if err != nil {
					t.Fatal(err)
				}
				response, err := f.request(stream, "/hold")
				if err != nil {
					t.Fatal("retiring domain starved healthy relay", err)
				}
				t.Cleanup(func() { _ = response.Body.Close() })
				prefix := make([]byte, 6)
				if response.StatusCode != http.StatusOK {
					t.Fatal("healthy relay did not serve all C", response.StatusCode)
				}
				if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
					t.Fatal("healthy target did not stream", err)
				}
				responses = append(responses, response)
			}
			f.wait(PendingSetupsPerRelay, capacity)
			for _, visitor := range retiring {
				assertPublicVisitorRetiring(t, f, visitor)
				visitor.stream.release()
				awaitPublisherTest(t, visitor.stream.joined)
				awaitPublisherTest(t, visitor.admission.done)
				visitor.admission.close()
				visitor.admission.close()
			}
			f.wait(0, capacity)
			unblock()
			for _, response := range responses {
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || string(body) != "finished" {
					t.Fatal("retirement preempted authorized visitor", err)
				}
			}
			f.wait(0, 0)
			fresh, err := f.open(0, 0, 11)
			if err != nil {
				t.Fatal(err)
			}
			response, err := f.request(fresh, "/fresh")
			if err != nil {
				t.Fatal("joined domain could not serve a fresh replacement", err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK || string(body) != "fresh" || reached.Load() != int32(capacity+1) {
				t.Fatal("replacement failed or unproven/replayed work reached target", string(body), reached.Load(), err)
			}
			f.wait(0, 0)
		})
	}
}

func TestPublicURLStreamCapacityCloseOwnersJoinBeforeRetirement(t *testing.T) {
	for _, action := range []string{"cancel", "replacement", "close", "drain", "eof"} {
		t.Run(action, func(t *testing.T) {
			f := newPublicCapacityFixture(t, 1, http.NotFoundHandler())
			visitor := openRetiringPublicVisitor(t, f, 1)
			f.wait(1, 0)
			var replace func() error
			if action == "replacement" {
				ref := f.refs[0]
				ref.ConnectionAssignmentRevision++
				ref.PublisherConnectionID = "replacement-while-retiring"
				publisher, _ := promotionSessionPair(t, ref)
				replace = func() error {
					live, err := f.route.registerPublisherSession(f.ctx, publisher, ref)
					if live != nil {
						f.route.unregisterPublisherSession(live)
					}
					return err
				}
			}
			done := make(chan error, 1)
			t.Cleanup(func() {
				visitor.stream.release()
				_ = awaitPublisherTest(t, done)
			})
			go func() {
				var err error
				switch action {
				case "cancel":
					visitor.cancel()
				case "replacement":
					err = replace()
				case "close":
					err = f.route.Close()
				case "drain":
					err = f.route.Drain(f.ctx)
				case "eof":
					err = visitor.client.Close()
				}
				done <- err
				close(done)
			}()
			assertPublicVisitorRetiring(t, f, visitor)
			f.wait(1, 0)
			if action == "close" || action == "drain" {
				select {
				case err := <-done:
					t.Fatal("close/drain returned before physical retirement joined", err)
				default:
				}
			}
			visitor.stream.release()
			awaitPublisherTest(t, visitor.stream.joined)
			awaitPublisherTest(t, visitor.admission.done)
			if err := awaitPublisherTest(t, done); err != nil {
				t.Fatal("close owner failed", err)
			}
			f.wait(0, 0)
		})
	}
}
