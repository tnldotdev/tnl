package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestCopyVisitorReportsRecoveryOnFirstPublisherByte(t *testing.T) {
	type recovery struct {
		id               string
		version, episode uint64
		at               time.Time
	}
	recovered := make(chan recovery, 2)
	server := &Server{config: Config{ObserveRecovery: func(id string, version, episode uint64, at time.Time) {
		recovered <- recovery{id, version, episode, at}
	}}}
	public, visitor := net.Pipe()
	upstream, publisher := net.Pipe()
	for _, connection := range []net.Conn{public, visitor, upstream, publisher} {
		ownIngressConn(t, connection)
	}
	copied := ingressWorker(t, func() { _ = public.Close(); _ = upstream.Close() }, func() error {
		return server.copyVisitor(public, upstream, public, PublicURL{ID: "public_url_test", PublishRunNumber: 1, RecoveryEpisodeID: 7}, false)
	})
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
			if r.id != "public_url_test" || r.version != 1 || r.episode != 7 || r.at.IsZero() {
				t.Fatalf("recovery = %+v", r)
			}
		}
	}
	_ = publisher.Close()
	_ = visitor.Close()
	ingressAwait(t, copied)
	if len(recovered) != 0 {
		t.Fatal("recovery reported more than once")
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
	reporter.Observe("public_url_test", 3, 7, observedAt)
	synctest.Wait()
	reporter.Observe("public_url_test", 3, 7, observedAt.Add(time.Second))

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
	if control.attempts != 2 || control.publicURLID != "public_url_test" || control.publishRunNumber != 3 ||
		control.recoveryEpisodeID != 7 || !control.observedAt.Equal(observedAt) {
		t.Fatalf("recovery attempts = %#v", control)
	}
}

type testRecoveryControl struct {
	mu                sync.Mutex
	attempted         chan struct{}
	attempts          int
	publicURLID       string
	publishRunNumber  uint64
	recoveryEpisodeID uint64
	observedAt        time.Time
}

func (c *testRecoveryControl) ObserveRecovery(
	_ context.Context,
	publicURLID string,
	publishRunNumber, recoveryEpisodeID uint64,
	observedAt time.Time,
) (ingressv1.PublicURLRecoveryObservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	c.publicURLID = publicURLID
	c.publishRunNumber = publishRunNumber
	c.recoveryEpisodeID = recoveryEpisodeID
	c.observedAt = observedAt
	c.attempted <- struct{}{}
	if c.attempts == 1 {
		return ingressv1.PublicURLRecoveryObservation{}, errors.New("temporary failure")
	}
	return ingressv1.PublicURLRecoveryObservation{}, nil
}
