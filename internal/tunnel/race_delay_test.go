package tunnel

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
)

func TestRaceStartsFallbackWhenPrimaryRemainsBlocked(t *testing.T) {
	synctest.Test(t, testRaceStartsFallbackWhenPrimaryRemainsBlocked)
}

func testRaceStartsFallbackWhenPrimaryRemainsBlocked(t *testing.T) {
	primaryStarted := make(chan struct{})
	primaryDone := make(chan struct{})
	t.Cleanup(func() { await(t, primaryDone) })
	primary := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
		defer close(primaryDone)
		close(primaryStarted)
		<-ctx.Done()
		return nil, context.Cause(ctx)
	})
	var fallbackCalls atomic.Int32
	fallback := authenticatedConnector(t, &fallbackCalls)

	const fallbackDelay = 25 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	startedAt := time.Now()
	session, transport, err := Race(
		ctx,
		Candidate{Connector: primary, Transport: TransportQUIC},
		Candidate{Connector: fallback, Transport: TransportTLSTCP},
		fallbackDelay,
		publisherHello(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	if transport != TransportTLSTCP {
		t.Fatalf("transport = %q; want %q", transport, TransportTLSTCP)
	}
	select {
	case <-primaryStarted:
	default:
		t.Fatal("primary transport was not attempted")
	}
	if fallbackCalls.Load() != 1 {
		t.Fatalf("fallback calls = %d; want 1", fallbackCalls.Load())
	}
	if elapsed := time.Since(startedAt); elapsed < fallbackDelay {
		t.Fatalf("fallback won after %s; want at least %s", elapsed, fallbackDelay)
	}
}
