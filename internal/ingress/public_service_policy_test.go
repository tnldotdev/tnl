package ingress

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func publicServiceWaitCapacity(t *testing.T, p *Server) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, active := publicServiceAdmissionCounts(p)
		if active == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("public service visitor did not reserve capacity")
}

func TestPublicServiceLiveVisitorClosesOnExplicitDenial(t *testing.T) {
	p, c, f, _ := publicServiceTestSetup(t)
	p.config.RecheckInterval, p.config.RecheckTimeout, p.config.HardAuthorizationTTL = 20*time.Millisecond, 10*time.Millisecond, 150*time.Millisecond
	stream, stop := publicServiceActiveStream(t, p, f)
	publicServiceWaitCapacity(t, p)
	c.mu.Lock()
	c.deny = true
	c.mu.Unlock()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked visitor kept an active stream")
	}
	stop()
	if c.recheckActive.Load() != 0 {
		t.Fatal("recheck survived denial")
	}
	select {
	case <-f.relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay copy survived denial")
	}
}

func TestPublicServiceLiveVisitorOutageHonorsLastSuccessfulDeadline(t *testing.T) {
	for _, grant := range []bool{false, true} {
		name := "hard ttl"
		if grant {
			name = "earlier grant"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, c, f, _ := publicServiceTestSetup(t)
				p.config.RecheckInterval, p.config.RecheckTimeout = 20*time.Millisecond, 10*time.Millisecond
				p.config.HardAuthorizationTTL = 125 * time.Millisecond
				c.recheckStarted = make(chan struct{}, 1)
				bound := 300 * time.Millisecond
				if grant {
					p.config.HardAuthorizationTTL = 250 * time.Millisecond
					c.recheckValidUntil = time.Now().Add(135 * time.Millisecond)
					bound = 190 * time.Millisecond
				}
				stream, stop := publicServiceActiveStream(t, p, f)
				publicServiceWaitCapacity(t, p)
				ingressAwait(t, c.recheckStarted)
				synctest.Wait()
				c.mu.Lock()
				c.recheckErr = errors.New("control unavailable after last check")
				c.mu.Unlock()
				started := time.Now()
				_ = stream.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := stream.Read(make([]byte, 1)); err == nil {
					t.Fatal("outage left visitor open")
				}
				if elapsed := time.Since(started); elapsed > bound || !grant && elapsed < 35*time.Millisecond {
					t.Fatalf("outage deadline = %v", elapsed)
				}
				stop()
				c.mu.Lock()
				checks := c.rechecks
				c.mu.Unlock()
				if checks < 2 || c.recheckActive.Load() != 0 {
					t.Fatalf("recheck retries/join: checks=%d active=%d", checks, c.recheckActive.Load())
				}
				select {
				case <-f.relayDone:
				case <-time.After(time.Second):
					t.Fatal("relay copy survived deadline")
				}
			})
		})
	}
}

func TestPublicServiceLiveVisitorOutageHonorsInitialClaimDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, c, f, _ := publicServiceTestSetup(t)
		c.initialValidUntil = time.Now().Add(175 * time.Millisecond)
		c.recheckErr = errors.New("control unavailable immediately after admission")
		stream, stop := publicServiceActiveStream(t, p, f)
		started := time.Now()
		_ = stream.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := stream.Read(make([]byte, 1)); err == nil {
			t.Fatal("initial expiry did not end visitor")
		}
		if elapsed := time.Since(started); elapsed > 230*time.Millisecond {
			t.Fatalf("ignored initial deadline for %v", elapsed)
		}
		stop()
		c.mu.Lock()
		checks := c.rechecks
		c.mu.Unlock()
		if checks < 2 || c.recheckActive.Load() != 0 {
			t.Fatalf("initial outage scheduling/join: checks=%d active=%d", checks, c.recheckActive.Load())
		}
		select {
		case <-f.relayDone:
		case <-time.After(time.Second):
			t.Fatal("relay copy survived initial expiry")
		}
	})
}

type delayedServiceVisitorStatus struct {
	PublicServiceControl
	status func(context.Context, string, ingressv1.PublicServiceVisitorLookup) (ingressv1.PublicServiceVisitorStatus, error)
}

func (c delayedServiceVisitorStatus) PublicServiceVisitorStatus(ctx context.Context, id string, lookup ingressv1.PublicServiceVisitorLookup) (ingressv1.PublicServiceVisitorStatus, error) {
	return c.status(ctx, id, lookup)
}

func TestPublicServiceLiveVisitorCannotExtendExpiredLeaseOrTimedOutCheck(t *testing.T) {
	for _, boundary := range []string{"ingress lease", "drain deadline", "timed-out check"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server, control, forwarder, lease := publicServiceTestSetup(t)
				server.config.RecheckInterval, server.config.RecheckTimeout = 30*time.Millisecond, 10*time.Millisecond
				server.config.HardAuthorizationTTL = 125 * time.Millisecond
				until := time.Now().Add(server.config.HardAuthorizationTTL)
				events := make(chan serviceaudit.Observation, 2)
				server.config.AuditSink = auditSinkFunc(func(event serviceaudit.Observation) bool { events <- event; return true })
				var lateChecks, activeChecks atomic.Int32
				var draining atomic.Pointer[ingressv1.IngressLease]
				if boundary == "ingress lease" {
					lease.LeaseExpiresAt = until
					server.config.HardAuthorizationTTL = time.Second
					server.config.CurrentLease = func() ingressv1.IngressLease { return lease }
				} else if boundary == "drain deadline" {
					server.config.HardAuthorizationTTL = time.Second
					draining.Store(&lease)
					server.config.CurrentLease = func() ingressv1.IngressLease { return *draining.Load() }
				} else {
					server.config.Control = delayedServiceVisitorStatus{PublicServiceControl: control,
						status: func(ctx context.Context, id string, lookup ingressv1.PublicServiceVisitorLookup) (ingressv1.PublicServiceVisitorStatus, error) {
							if lateChecks.Add(1) == 1 {
								return control.PublicServiceVisitorStatus(ctx, id, lookup)
							}
							activeChecks.Add(1)
							defer activeChecks.Add(-1)
							<-ctx.Done()
							// a late success cannot count as a fresh authorization.
							return ingressv1.PublicServiceVisitorStatus{State: ingressv1.PublicServiceVisitorAllowed, ValidUntil: time.Now().Add(time.Minute)}, nil
						}}
				}
				stream, stop := publicServiceActiveStream(t, server, forwarder)
				opened := ingressAwait(t, events)
				if opened.EventType != "connection.open" || opened.Outcome != "allowed" {
					t.Fatal("visitor was not authorized before the expiry check", opened)
				}
				if boundary == "drain deadline" {
					current := lease
					current.Draining, current.DrainDeadline = true, &until
					draining.Store(&current)
				}
				_ = stream.SetReadDeadline(until.Add(time.Millisecond))
				_, err := stream.Read(make([]byte, 1))
				var timeout net.Error
				if err == nil || errors.As(err, &timeout) && timeout.Timeout() || time.Now().After(until) {
					t.Fatal("idle visitor survived its exact authority deadline", boundary, time.Since(until), err)
				}
				stop()
				if control.recheckActive.Load() != 0 || activeChecks.Load() != 0 || server.Load() != 0 || !publicServiceCapacityReleased(server) {
					t.Fatal("expired visitor retained rechecks, physical load, or quota")
				}
				ingressAwait(t, forwarder.relayDone)
				closed := ingressAwait(t, events)
				if closed.EventType != "connection.close" || closed.VisitorConnectionID != opened.VisitorConnectionID {
					t.Fatal("expiry lost the visitor's close record", closed)
				}
			})
		})
	}
}

func TestPublicServiceLiveVisitorDefaultsRefreshShortInitialLease(t *testing.T) {
	p, c, f, _ := publicServiceTestSetup(t)
	c.initialValidUntil = time.Now().Add(250 * time.Millisecond)
	c.recheckStarted = make(chan struct{}, 1)
	stream, _ := publicServiceActiveStream(t, p, f)
	select {
	case <-c.recheckStarted:
	case <-time.After(time.Second):
		t.Fatal("default scheduling missed initial lease")
	}
	_ = stream.SetReadDeadline(c.initialValidUntil.Add(100 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected bytes")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("successful check did not preserve same stream: %v", err)
	}
}

func TestPublicServiceLiveVisitorCloseJoinsBlockedRecheckAndCopy(t *testing.T) {
	p, c, f, _ := publicServiceTestSetup(t)
	p.config.RecheckInterval, p.config.RecheckTimeout, p.config.HardAuthorizationTTL = 120*time.Millisecond, 100*time.Millisecond, 350*time.Millisecond
	_, stop := publicServiceActiveStream(t, p, f)
	publicServiceWaitCapacity(t, p)
	c.mu.Lock()
	c.recheckStarted, c.recheckGate = make(chan struct{}, 1), make(chan struct{})
	started := c.recheckStarted
	c.mu.Unlock()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("blocked check never started")
	}
	_ = p.Close()
	stop()
	if c.recheckActive.Load() != 0 || p.Load() != 0 || !publicServiceCapacityReleased(p) {
		t.Fatal("close did not join policy and release capacity")
	}
	select {
	case <-f.relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay copy survived close")
	}
}
