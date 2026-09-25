package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
)

type gatedRelayConnector struct {
	started chan struct{}
	release <-chan struct{}
	next    relayConnector
	calls   atomic.Int32
	failure error
}

func (c *gatedRelayConnector) Credential() string { return forwardingClusterSecret }
func (c *gatedRelayConnector) Connect(ctx context.Context, target relayTarget) (muxsession.Session, error) {
	if c.calls.Add(1) == 1 {
		close(c.started)
	}
	select {
	case <-c.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if c.next == nil {
		return nil, c.failure
	}
	return c.next.Connect(ctx, target)
}

func TestForwarderConcurrentOpensShareConnection(t *testing.T) {
	material := newForwardingTestMaterial(t)
	const count = 8
	requests := make(chan forwardingTestRequest, count)
	server := startForwardingTestServer(t, material, func(ctx context.Context, s muxsession.Session) error {
		return captureForwardingRequests(ctx, s, requests)
	})
	f := newTestForwarder(t, material)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	connector := &gatedRelayConnector{started: make(chan struct{}), release: release, next: f.connector}
	f.connector = connector
	backend := mustOnlyBackend(t, f, forwardingTestEntry(time.Now(), server.address()))
	ctx, cancel := context.WithTimeout(t.Context(), fixtureTimeout)
	var workers sync.WaitGroup
	done, results := make(chan struct{}), make(chan error, count)
	t.Cleanup(func() { unblock(); cancel(); _ = f.Close(); ingressAwait(t, done) })
	for i := range count {
		workers.Go(func() {
			connection, err := backend.Open(ctx, fmt.Sprintf("visitor_%d", i))
			if err != nil {
				results <- err
				return
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(fixtureTimeout))
			_, err = connection.Write([]byte("ping"))
			var reply [4]byte
			if err == nil {
				_, err = io.ReadFull(connection, reply[:])
			}
			if err == nil && string(reply[:]) != "pong" {
				err = fmt.Errorf("reply=%q", reply)
			}
			results <- err
		})
	}
	go func() { workers.Wait(); close(done) }()
	ingressAwait(t, connector.started)
	unblock()
	for range count {
		if err := ingressAwait(t, results); err != nil {
			t.Error(err)
		}
	}
	seen := make(map[string]bool)
	for range count {
		r := ingressAwait(t, requests)
		if r.payload != "ping" || seen[r.header.VisitorConnectionID] {
			t.Fatalf("request=%+v", r)
		}
		seen[r.header.VisitorConnectionID] = true
	}
	if connector.calls.Load() != 1 || server.accepted.Load() != 1 {
		t.Fatalf("connect=%d accept=%d", connector.calls.Load(), server.accepted.Load())
	}
}

func TestForwarderWaiterCancellationAndCloseWhileConnecting(t *testing.T) {
	for _, closePool := range []bool{false, true} {
		t.Run(fmt.Sprintf("close=%t", closePool), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				failure := errors.New("connect failed")
				connector := &gatedRelayConnector{started: make(chan struct{}), release: release, failure: failure}
				f := newForwarder(connector)
				t.Cleanup(func() { _ = f.Close() })
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)
				target := relayTarget{address: "relay:443", relayID: "relay_1"}
				owner := ingressWorker(t, cancel, func() error { _, _, err := f.session(ctx, target); return err })
				ingressAwait(t, connector.started)
				waitCtx, stop := context.WithCancel(ctx)
				waiter := ingressWorker(t, stop, func() error { _, _, err := f.session(waitCtx, target); return err })
				synctest.Wait() // The second caller is now waiting on the pooled entry.
				if closePool {
					if err := f.Close(); err != nil {
						t.Fatal(err)
					}
					if err := ingressAwait(t, owner); !errors.Is(err, context.Canceled) {
						t.Fatalf("owner=%v", err)
					}
					if err := ingressAwait(t, waiter); !errors.Is(err, context.Canceled) {
						t.Fatalf("waiter=%v", err)
					}
					if _, _, err := f.session(ctx, target); !errors.Is(err, net.ErrClosed) {
						t.Fatalf("open after close=%v", err)
					}
				} else {
					stop()
					if err := ingressAwait(t, waiter); !errors.Is(err, context.Canceled) {
						t.Fatalf("waiter=%v", err)
					}
					select {
					case err := <-owner:
						t.Fatalf("waiter canceled owner: %v", err)
					default:
					}
					close(release)
					if err := ingressAwait(t, owner); !errors.Is(err, failure) {
						t.Fatalf("owner=%v", err)
					}
				}
				if connector.calls.Load() != 1 {
					t.Fatalf("connect calls=%d", connector.calls.Load())
				}
			})
		})
	}
}

func TestForwarderSessionSetupOutlivesFirstWaiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		failure := errors.New("connect failed")
		connector := &gatedRelayConnector{started: make(chan struct{}), release: release, failure: failure}
		forwarder := newForwarder(connector)
		t.Cleanup(func() { _ = forwarder.Close() })
		target := relayTarget{address: "relay:443", relayID: "relay_1"}

		firstCtx, cancelFirst := context.WithCancel(t.Context())
		first := ingressWorker(t, cancelFirst, func() error {
			_, _, err := forwarder.session(firstCtx, target)
			return err
		})
		ingressAwait(t, connector.started)
		second := ingressWorker(t, func() {}, func() error {
			_, _, err := forwarder.session(t.Context(), target)
			return err
		})
		t.Cleanup(unblock)
		synctest.Wait()
		cancelFirst()
		if err := ingressAwait(t, first); !errors.Is(err, context.Canceled) {
			t.Fatalf("first waiter = %v", err)
		}
		select {
		case err := <-second:
			t.Fatalf("first waiter canceled shared setup: %v", err)
		default:
		}
		unblock()
		if err := ingressAwait(t, second); !errors.Is(err, failure) {
			t.Fatalf("second waiter = %v", err)
		}
		if connector.calls.Load() != 1 {
			t.Fatalf("connect calls = %d", connector.calls.Load())
		}
	})
}
