package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestCopyVisitorReportsRecoveryOnFirstPublisherByte(t *testing.T) {
	type recovery struct {
		run     ingressv1.ServiceRunReference
		visitor string
		episode uint64
		at      time.Time
	}
	recovered := make(chan recovery, 2)
	server, control, _, _ := publicServiceTestSetup(t)
	control.recoveryEpisodeID = new(int64(7))
	server.config.ObserveRecovery = func(run ingressv1.ServiceRunReference, visitor string, episode uint64, at time.Time) {
		recovered <- recovery{run, visitor, episode, at}
	}
	upstream, publisher := net.Pipe()
	for _, connection := range []net.Conn{upstream, publisher} {
		ownIngressConn(t, connection)
	}
	forwarder := &recoveryForwarder{connection: upstream, header: make(chan tunnelv1.ServiceForwardingHeader, 1)}
	server.config.Forwarder = forwarder
	metadata := ingressWorker(t, func() { _ = publisher.Close() }, func() error {
		_, _, err := proxyproto.Decode(publisher)
		return err
	})
	visitor, _, stop := publicServiceTestConnect(t, server)
	header := ingressAwait(t, forwarder.header)
	if err := ingressAwait(t, metadata); err != nil {
		t.Fatal(err)
	}
	select {
	case <-recovered:
		t.Fatal("recovery reported before a publisher byte")
	default:
	}
	for _, value := range []string{"pong", "more"} {
		written := ingressWorker(t, func() { _ = publisher.Close() }, func() error {
			_, err := publisher.Write([]byte(value))
			return err
		})
		response := make([]byte, len(value))
		if _, err := io.ReadFull(visitor, response); err != nil || string(response) != value {
			t.Fatal("publisher bytes did not reach the visitor", string(response), err)
		}
		if err := ingressAwait(t, written); err != nil {
			t.Fatal(err)
		}
		if value == "pong" {
			r := ingressAwait(t, recovered)
			if r.run != (ingressv1.ServiceRunReference{ServiceId: control.service, ServiceRunId: control.run, RunNumber: 1}) ||
				r.visitor != header.VisitorConnectionID || r.episode != 7 || r.at.IsZero() {
				t.Fatalf("recovery = %+v", r)
			}
		}
	}
	_ = publisher.Close()
	_ = visitor.Close()
	stop()
	if len(recovered) != 0 {
		t.Fatal("recovery reported more than once")
	}
}

type recoveryForwarder struct {
	connection net.Conn
	header     chan tunnelv1.ServiceForwardingHeader
}

func (f *recoveryForwarder) OpenPrivate(_ context.Context, _ ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	f.header <- header
	return f.connection, nil
}

type failedRecoveryDelivery struct{ net.Conn }

func (failedRecoveryDelivery) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestRecoveryDoesNotCompleteOnFailedVisitorWrite(t *testing.T) {
	server, control, _, _ := publicServiceTestSetup(t)
	control.recoveryEpisodeID = new(int64(7))
	recovered := make(chan struct{}, 1)
	server.config.ObserveRecovery = func(ingressv1.ServiceRunReference, string, uint64, time.Time) {
		recovered <- struct{}{}
	}
	public, visitor := net.Pipe()
	upstream, publisher := net.Pipe()
	for _, connection := range []net.Conn{public, visitor, upstream, publisher} {
		ownIngressConn(t, connection)
	}
	server.config.Forwarder = &recoveryForwarder{connection: upstream, header: make(chan tunnelv1.ServiceForwardingHeader, 1)}
	sent := ingressWorker(t, func() { _ = publisher.Close() }, func() error {
		if _, _, err := proxyproto.Decode(publisher); err != nil {
			return err
		}
		_, err := publisher.Write([]byte("publisher byte"))
		return err
	})
	done := ingressWorker(t, func() { _ = public.Close(); _ = upstream.Close() }, func() error {
		return server.AcceptPublic(t.Context(), failedRecoveryDelivery{public},
			netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:20000"), "", nil)
	})
	if err := ingressAwait(t, sent); err != nil {
		t.Fatal("publisher byte never reached ingress", err)
	}
	if err := ingressAwait(t, done); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("visitor write failure was not retained", err)
	}
	if len(recovered) != 0 {
		t.Fatal("a publisher read without a successful visitor write completed recovery")
	}
}

func TestNewRecoveryReporterRejectsNegativeRetryInterval(t *testing.T) {
	t.Parallel()
	if _, err := NewRecoveryReporter(t.Context(), &testRecoveryControl{}, -time.Second, nil); err == nil {
		t.Fatal("NewRecoveryReporter accepted a negative retry interval")
	}
}

func TestRecoveryReporterRetriesAndDeduplicates(t *testing.T) {
	synctest.Test(t, testRecoveryReporterRetriesAndDeduplicates)
}

func testRecoveryReporterRetriesAndDeduplicates(t *testing.T) {
	control := &testRecoveryControl{attempted: make(chan struct{}, 2)}
	ctx, cancel := context.WithCancel(t.Context())
	reporter, err := NewRecoveryReporter(ctx, control, time.Second, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := reporter.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	observedAt := time.Now().UTC()
	run := ingressv1.ServiceRunReference{ServiceId: "service", ServiceRunId: "run", RunNumber: 3}
	reporter.Observe(run, "visitor", 7, observedAt)
	synctest.Wait()
	reporter.Observe(run, "visitor", 7, observedAt.Add(time.Second))

	for range 2 {
		select {
		case <-control.attempted:
		case <-time.After(2 * time.Second):
			t.Fatal("recovery observation was not retried")
		}
	}
	closeCtx, stop := context.WithTimeout(t.Context(), 2*time.Second)
	defer stop()
	if err := reporter.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.attempts != 2 || control.run != run || control.visitor != "visitor" ||
		control.recoveryEpisodeID != 7 || !control.observedAt.Equal(observedAt) {
		t.Fatalf("recovery attempts = %#v", control)
	}
}

type testRecoveryControl struct {
	mu                sync.Mutex
	attempted         chan struct{}
	attempts          int
	run               ingressv1.ServiceRunReference
	visitor           string
	recoveryEpisodeID uint64
	observedAt        time.Time
}

func (c *testRecoveryControl) ObserveRecovery(
	_ context.Context,
	run ingressv1.ServiceRunReference,
	visitor string,
	recoveryEpisodeID uint64,
	observedAt time.Time,
) (ingressv1.ServiceRecoveryObservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	c.run = run
	c.visitor = visitor
	c.recoveryEpisodeID = recoveryEpisodeID
	c.observedAt = observedAt
	c.attempted <- struct{}{}
	if c.attempts == 1 {
		return ingressv1.ServiceRecoveryObservation{}, errors.New("temporary failure")
	}
	return ingressv1.ServiceRecoveryObservation{}, nil
}

type recoveryControlFunc func(context.Context, ingressv1.ServiceRunReference, string, uint64, time.Time) (ingressv1.ServiceRecoveryObservation, error)

func (f recoveryControlFunc) ObserveRecovery(ctx context.Context, run ingressv1.ServiceRunReference, visitor string, episode uint64, at time.Time) (ingressv1.ServiceRecoveryObservation, error) {
	return f(ctx, run, visitor, episode, at)
}

func TestRecoveryReporterCloseCancelsAndJoinsBlockedDelivery(t *testing.T) {
	entered, stopped := make(chan struct{}), make(chan struct{})
	control := recoveryControlFunc(func(ctx context.Context, _ ingressv1.ServiceRunReference, _ string, _ uint64, _ time.Time) (ingressv1.ServiceRecoveryObservation, error) {
		close(entered)
		<-ctx.Done()
		close(stopped)
		return ingressv1.ServiceRecoveryObservation{}, ctx.Err()
	})
	reporter, err := NewRecoveryReporter(t.Context(), control, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter.Observe(ingressv1.ServiceRunReference{ServiceId: "service", ServiceRunId: "run", RunNumber: 1}, "visitor", 7, time.Now())
	ingressAwait(t, entered)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := reporter.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("bounded close lost its deadline", err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("reporter returned before its blocked delivery joined")
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.pending) != 0 {
		t.Fatal("joined reporter retained pending work")
	}
}
