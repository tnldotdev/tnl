package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type privatePolicyFaults struct {
	mu          sync.Mutex
	unavailable bool
	checks      int
	until       time.Time
	allocations map[string]time.Time
	blocked     chan struct{}
	once        sync.Once
}

type defaultPublisherPolicy struct {
	publisherservice.RunControl
	faults *privatePolicyFaults
}

func (c defaultPublisherPolicy) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	c.faults.mu.Lock()
	unavailable := c.faults.unavailable
	c.faults.mu.Unlock()
	if unavailable {
		c.faults.once.Do(func() { close(c.faults.blocked) })
		return controlv1.VisitorPolicyUpdate{}, clientcontrol.ErrUnavailable
	}
	started := time.Now()
	policy, err := c.RunControl.ReadPublisherVisitorPolicy(ctx, request, token)
	if err == nil {
		c.faults.mu.Lock()
		c.faults.checks++
		c.faults.until = started.Add(policy.Policy.ValidUntil.Sub(policy.Policy.ObservedAt))
		c.faults.allocations = make(map[string]time.Time)
		for _, allocation := range policy.Policy.StreamAllocations {
			c.faults.allocations[allocation.Id] = started.Add(allocation.ValidUntil.Sub(policy.Policy.ObservedAt))
		}
		c.faults.mu.Unlock()
	}
	return policy, err
}

func TestIntegrationPrivateDefaultLeaseCycles(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "renewal-and-outage", true: "revocation"}[revoke], func(t *testing.T) {
			opened := make(chan privateObservation, 8)
			f := newServiceRuntimeFixtureTiming(t, false, opened, true)
			for slot := range 2 {
				startSeparatedPrivateIngress(t, f, slot, "tls-tcp", opened)
			}
			target := startPrivateEchoTarget(t)
			key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				t.Fatal(err)
			}
			service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "default-leases", key)
			if err != nil {
				t.Fatal(err)
			}
			faults := &privatePolicyFaults{blocked: make(chan struct{})}
			startPrivateHTTPPublisher(t, f, service, target.address, defaultPublisherPolicy{RunControl: f.identity.routes, faults: faults})
			person, err := f.identity.authority.IdentityContext(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			device, err := control.ConnectorSigner(t.Context(), person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			ready, done := make(chan struct{}), make(chan error, 1)
			go func() {
				done <- connectorstream.Serve(ctx, listener, connectorstream.Config{Control: control, ServiceID: service.Id, IdentityID: person.Identity.Id, Protocol: string(service.Protocol), TrustRevision: service.TrustRevision, Endpoint: service.Endpoint, ServiceTLS: f.visitorRoots, Ready: func() error { close(ready); return nil }})
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					reason, _ := failure.ReasonOf(err)
					expected := revoke && (errors.Is(err, clientcontrol.ErrNotFound) || reason == failure.ServerDenied)
					if err != nil && !expected {
						t.Error(err)
					}
				case <-time.After(10 * time.Second):
					t.Error("connector did not join")
				}
			})
			select {
			case <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("connector did not become ready")
			}
			connectorReadinessObservation(t, opened)
			connection, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			exchange := func(conn net.Conn, step int) {
				t.Helper()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				message := fmt.Sprintf("same-stream-%d\n", step)
				if _, err := io.WriteString(conn, message); err != nil {
					t.Fatal(err)
				}
				data := make([]byte, len(message))
				if _, err := io.ReadFull(conn, data); err != nil || string(data) != message {
					t.Fatalf("default lease cycle changed or closed the stream: %v", err)
				}
				_ = conn.SetDeadline(time.Time{})
			}
			exchange(connection, 0)
			original := <-opened
			if !revoke {
				// retain the production proof across more than two complete
				// 30-second infrastructure lease cycles on the same visitor.
				for step := 1; step <= 14; step++ {
					waitRuntimeTime(t, time.Now().Add(5*time.Second))
					exchange(connection, step)
				}
				select {
				case <-opened:
					t.Fatal("permission renewal replaced the active visitor")
				default:
				}
				faults.mu.Lock()
				checks := faults.checks
				faults.unavailable = true
				faults.mu.Unlock()
				if checks < 2 {
					t.Fatal("native stream did not cross policy refresh cycles")
				}
				select {
				case <-faults.blocked:
				case <-time.After(3 * time.Second):
					t.Fatal("publisher did not attempt background policy renewal")
				}
				faults.mu.Lock()
				deadline := faults.until
				allocationDeadline := faults.allocations[original.header.Reservation.AllocationID]
				faults.mu.Unlock()
				if allocationDeadline.IsZero() {
					t.Fatal("publisher did not install the active visitor's allocation")
				}
				deadline = minTime(deadline, allocationDeadline)
				_ = connection.SetReadDeadline(deadline.Add(2 * time.Second))
				if _, err := connection.Read(make([]byte, 1)); err == nil {
					t.Fatal("outage retained native traffic")
				} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("native stream exceeded its last policy deadline")
				}
				if time.Now().Before(deadline.Add(-100 * time.Millisecond)) {
					t.Fatal("outage discarded unexpired native permission")
				}
			} else {
				other, err := net.Dial("tcp", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				exchange(other, 1)
				sibling := <-opened
				if sibling.header.VisitorConnectionID == original.header.VisitorConnectionID {
					t.Fatal("sibling reused the original visitor ID")
				}
				if err := f.identity.routes.RevokeVisitorDevice(t.Context(), device.Subject.DeviceID); err != nil {
					t.Fatal(err)
				}
				for _, conn := range []net.Conn{connection, other} {
					_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
					if _, err := conn.Read(make([]byte, 1)); err == nil {
						t.Fatal("revocation retained native traffic")
					} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
						t.Fatal("revocation missed the policy fence")
					}
				}
			}
		})
	}
}
