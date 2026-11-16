package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type promotionTestControl struct {
	PublicServiceControl
	status                  func(context.Context) (ingressv1.PublicServiceVisitorStatus, error)
	promote                 func(context.Context) error
	statusCalls, promotions atomic.Int32
	active                  atomic.Int32
}

func (c *promotionTestControl) PublicServiceVisitorStatus(ctx context.Context, _ string, _ ingressv1.PublicServiceVisitorLookup) (ingressv1.PublicServiceVisitorStatus, error) {
	c.statusCalls.Add(1)
	c.active.Add(1)
	defer c.active.Add(-1)
	return c.status(ctx)
}

func (c *promotionTestControl) PromotePublicServiceVisitor(ctx context.Context, _ string, _ ingressv1.PublicServiceVisitorLookup) error {
	c.promotions.Add(1)
	c.active.Add(1)
	defer c.active.Add(-1)
	return c.promote(ctx)
}

type promotionTestForwarder func(context.Context, ingressv1.ServiceRelay, tunnelv1.ServiceForwardingHeader, func(context.Context) error) (net.Conn, error)

func (f promotionTestForwarder) OpenService(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, reserveCapacity func(context.Context) error) (net.Conn, error) {
	return f(ctx, relay, header, reserveCapacity)
}

type servicePromotionFixture struct {
	server      *Server
	receipt     *publicServiceControlFixture
	control     *promotionTestControl
	lease       atomic.Pointer[ingressv1.IngressLease]
	until       time.Time
	events      chan serviceaudit.Observation
	allowed     atomic.Bool
	targetBytes atomic.Int64
	publisher   <-chan error
	visitor     net.Conn
	done        <-chan error
	stop        func()
}

func newServicePromotionFixture(t *testing.T) *servicePromotionFixture {
	t.Helper()
	server, receipt, _, lease := publicServiceTestSetup(t)
	f := &servicePromotionFixture{server: server, receipt: receipt, until: time.Now().Add(125 * time.Millisecond),
		events: make(chan serviceaudit.Observation, 4)}
	f.lease.Store(&lease)
	server.config.CurrentLease = func() ingressv1.IngressLease { return *f.lease.Load() }
	server.config.RecheckInterval, server.config.RecheckTimeout, server.config.HardAuthorizationTTL = 200*time.Millisecond, 200*time.Millisecond, time.Second
	receipt.initialValidUntil, receipt.traffic.TotalConnections = f.until, new(int64(1))
	f.control = &promotionTestControl{PublicServiceControl: receipt}
	f.control.status = func(context.Context) (ingressv1.PublicServiceVisitorStatus, error) {
		return ingressv1.PublicServiceVisitorStatus{State: ingressv1.PublicServiceVisitorAuthenticated, ValidUntil: time.Now().Add(time.Minute)}, nil
	}
	server.config.Control = f.control
	authorized, closed := make(chan struct{}), make(chan struct{})
	authorize := sync.OnceFunc(func() { f.allowed.Store(true); close(authorized) })
	server.config.AuditSink = auditSinkFunc(func(event serviceaudit.Observation) bool {
		f.events <- event
		if event.EventType == "connection.open" && event.Outcome == "allowed" {
			authorize()
		}
		return true
	})
	connection, publisher := net.Pipe()
	ownIngressConn(t, connection)
	ownIngressConn(t, publisher)
	backend := &ownedConn{Conn: connection, close: sync.OnceValue(func() error { close(closed); return connection.Close() })}
	var opens atomic.Int32
	capacity := make(chan func(context.Context) error, 1)
	server.config.Forwarder = promotionTestForwarder(func(_ context.Context, _ ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, reserveCapacity func(context.Context) error) (net.Conn, error) {
		if opens.Add(1) != 1 || header.Validate() != nil || header.ServiceID != receipt.service || header.ServiceRunID != receipt.run ||
			header.RunNumber != 1 || header.PublicService == nil || header.PublicService.DestinationPort != 20000 {
			return nil, errors.New("promotion changed the admitted stream or opened another relay")
		}
		capacity <- reserveCapacity
		return backend, nil
	})
	f.publisher = ingressWorker(t, func() { _ = backend.Close(); _ = publisher.Close() }, func() error {
		defer publisher.Close()
		_, replay, err := proxyproto.Decode(publisher)
		if err != nil {
			return err
		}
		check, cancel := context.WithDeadline(t.Context(), f.until)
		defer cancel()
		if err := (<-capacity)(check); err != nil {
			return nil
		}
		// this publisher admits target bytes only after ingress acknowledges
		// capacity. connection setup itself must not reach the target.
		select {
		case <-authorized:
		case <-closed:
			return nil
		}
		var request [4]byte
		n, err := io.ReadFull(replay, request[:])
		f.targetBytes.Add(int64(n))
		if err != nil {
			return err
		}
		if string(request[:]) != "ping" {
			return errors.New("promotion changed target bytes")
		}
		if _, err := publisher.Write([]byte("pong")); err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, replay)
		return nil
	})
	return f
}

func (f *servicePromotionFixture) start(t *testing.T) {
	t.Helper()
	f.receipt.initialValidUntil = f.until
	f.visitor, f.done, f.stop = publicServiceTestConnect(t, f.server)
	if _, err := f.visitor.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
}

func (f *servicePromotionFixture) assertDeniedAndJoined(t *testing.T, deadline time.Time) {
	t.Helper()
	_ = f.visitor.SetReadDeadline(deadline.Add(time.Millisecond))
	var response [4]byte
	n, err := io.ReadFull(f.visitor, response[:])
	var timeout net.Error
	if n != 0 || err == nil || errors.As(err, &timeout) && timeout.Timeout() || time.Now().After(deadline) {
		t.Fatal("late promotion extended authorization or delivered target bytes", n, err, time.Since(deadline))
	}
	if err := ingressAwait(t, f.done); !errors.Is(err, ErrServiceAdmission) {
		t.Fatal("expired promotion did not reject the visitor", err)
	}
	f.stop()
	if err := ingressAwait(t, f.publisher); err != nil {
		t.Fatal("publisher did not join after denied promotion", err)
	}
	if f.allowed.Load() || f.targetBytes.Load() != 0 || f.control.active.Load() != 0 ||
		f.server.Load() != 0 || !publicServiceCapacityReleased(f.server) || f.receipt.closed != 1 {
		t.Fatal("late promotion retained authority, target bytes, workers, load, or quota")
	}
	event := ingressAwait(t, f.events)
	if event.Validate() != nil || event.EventType != "connection.open" || event.Outcome != "denied" ||
		event.RunID != f.receipt.run || len(f.events) != 0 {
		t.Fatal("unacknowledged promotion emitted authorized admission", event)
	}
	run := f.server.traffic.runs[trafficKey{service: f.receipt.service, id: f.receipt.run, run: 1}]
	if run == nil || run.active != 0 || run.connections != 1 {
		t.Fatal("late promotion duplicated or refunded its reservation", run)
	}
}

func TestPublicServiceLatePromotionCannotExtendOriginalDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newServicePromotionFixture(t)
		var committed atomic.Bool
		f.control.status = func(context.Context) (ingressv1.PublicServiceVisitorStatus, error) {
			state := ingressv1.PublicServiceVisitorAuthenticated
			if committed.Load() {
				state = ingressv1.PublicServiceVisitorAllowed
			}
			return ingressv1.PublicServiceVisitorStatus{State: state, ValidUntil: time.Now().Add(time.Minute)}, nil
		}
		f.control.promote = func(ctx context.Context) error {
			deadline, _ := ctx.Deadline()
			if !deadline.Equal(f.until) {
				t.Error("promotion did not retain the original authorization deadline")
			}
			<-ctx.Done()
			committed.Store(true)
			return nil
		}
		f.start(t)
		f.assertDeniedAndJoined(t, f.until)
		if !committed.Load() || f.control.promotions.Load() != 1 || f.control.statusCalls.Load() != 0 {
			t.Fatal("expired promotion was retried or its future allowed status was consulted")
		}
	})
}

func TestPublicServicePromotionRechecksLeaseAndDrainBeforeAuthorization(t *testing.T) {
	for _, change := range []string{"expired", "replacement", "drain deadline"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newServicePromotionFixture(t)
				entered, release := make(chan struct{}), make(chan struct{})
				resume := sync.OnceFunc(func() { close(release) })
				t.Cleanup(resume)
				f.control.promote = func(ctx context.Context) error {
					close(entered)
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				f.start(t)
				ingressAwait(t, entered)
				now := time.Now()
				current := *f.lease.Load()
				switch change {
				case "expired":
					current.ServingUntil = now
				case "replacement":
					current.IngressLeaseRevision++
				case "drain deadline":
					current.Draining, current.DrainDeadline = true, &now
				}
				f.lease.Store(&current)
				resume()
				f.assertDeniedAndJoined(t, now)
			})
		})
	}
}

func TestPublicServiceTimedOutPromotionRecoversOnlyFromFreshAcknowledgment(t *testing.T) {
	for _, fresh := range []ingressv1.PublicServiceVisitorStatusState{ingressv1.PublicServiceVisitorAllowed, ingressv1.PublicServiceVisitorAuthenticated} {
		t.Run(string(fresh), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newServicePromotionFixture(t)
				f.until = time.Now().Add(300 * time.Millisecond)
				f.server.config.RecheckTimeout = 10 * time.Millisecond
				promotionReturned, freshStarted, acceptFresh := make(chan struct{}), make(chan struct{}), make(chan struct{})
				resume := sync.OnceFunc(func() { close(acceptFresh) })
				t.Cleanup(resume)
				f.control.status = func(ctx context.Context) (ingressv1.PublicServiceVisitorStatus, error) {
					state := ingressv1.PublicServiceVisitorAuthenticated
					if f.control.statusCalls.Load() >= 1 {
						state = fresh
						if f.control.promotions.Load() >= 2 {
							state = ingressv1.PublicServiceVisitorAllowed
						}
						if f.control.statusCalls.Load() == 1 {
							close(freshStarted)
							select {
							case <-acceptFresh:
							case <-ctx.Done():
								return ingressv1.PublicServiceVisitorStatus{}, ctx.Err()
							}
						}
					}
					return ingressv1.PublicServiceVisitorStatus{State: state, ValidUntil: time.Now().Add(time.Minute)}, nil
				}
				f.control.promote = func(ctx context.Context) error {
					deadline, _ := ctx.Deadline()
					if deadline.After(f.until) {
						t.Error("promotion retry extended the original deadline")
					}
					if f.control.promotions.Load() == 1 {
						<-ctx.Done()
						close(promotionReturned)
					}
					return nil
				}
				f.start(t)
				ingressAwait(t, promotionReturned)
				synctest.Wait()
				if f.allowed.Load() || f.targetBytes.Load() != 0 || len(f.events) != 0 {
					t.Fatal("timed-out nil promotion authorized before a fresh acknowledgment")
				}
				ingressAwait(t, freshStarted)
				resume()
				_ = f.visitor.SetReadDeadline(f.until)
				var response [4]byte
				if _, err := io.ReadFull(f.visitor, response[:]); err != nil || string(response[:]) != "pong" {
					t.Fatal("fresh acknowledgment did not recover the same visitor", string(response[:]), err)
				}
				opened := ingressAwait(t, f.events)
				if opened.Outcome != "allowed" || !opened.OccurredAt.Before(f.until) || f.targetBytes.Load() != 4 {
					t.Fatal("recovery did not wait for an in-deadline acknowledgment", opened)
				}
				key := trafficKey{service: f.receipt.service, id: f.receipt.run, run: 1}
				f.server.traffic.mu.Lock()
				run := *f.server.traffic.runs[key]
				f.server.traffic.mu.Unlock()
				if run.connections != 1 || run.active != 1 || run.newConnections.tokens != float64(f.server.config.Traffic.Default.Burst-1) {
					t.Fatal("promotion retry spent another connection or rate token", run)
				}
				f.stop()
				if err := ingressAwait(t, f.publisher); err != nil {
					t.Fatal(err)
				}
				if f.control.active.Load() != 0 || f.server.Load() != 0 || !publicServiceCapacityReleased(f.server) {
					t.Fatal("recovered visitor did not join or release capacity")
				}
				wantPromotions := int32(1)
				if fresh == ingressv1.PublicServiceVisitorAuthenticated {
					wantPromotions = 2
				}
				if f.control.promotions.Load() != wantPromotions {
					t.Fatal("recovery duplicated an acknowledged promotion", f.control.promotions.Load())
				}
			})
		})
	}
}
