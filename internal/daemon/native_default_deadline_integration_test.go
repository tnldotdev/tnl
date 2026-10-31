package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// hold the same lock across actual HTTP decisions and the outage transition.
// an already-entered success cannot extend the captured bound after the fault.
type nativeDefaultFaults struct {
	mu                                      sync.Mutex
	pair                                    string
	outage                                  bool
	renewals                                int
	initial, connectorUntil, publisherUntil time.Time
	changedPair                             bool
}

type defaultNativeOwnerControl struct {
	connectorstream.Control
	faults *nativeDefaultFaults
}

func (c defaultNativeOwnerControl) PrepareNativePeerPair(ctx context.Context, service string, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
	c.faults.mu.Lock()
	defer c.faults.mu.Unlock()
	if c.faults.outage {
		return controlv1.NativePeerPair{}, clientcontrol.ErrUnavailable
	}
	started := time.Now()
	pair, err := c.Control.PrepareNativePeerPair(ctx, service, body)
	if err == nil {
		until := started.Add(pair.ExpiresAt.Sub(pair.ObservedAt))
		if c.faults.pair == "" {
			c.faults.pair, c.faults.initial = pair.PairId, until
		}
		c.faults.changedPair = c.faults.changedPair || c.faults.pair != pair.PairId
		c.faults.connectorUntil = until
		if body.Action == controlv1.Renew {
			c.faults.renewals++
		}
	}
	return pair, err
}

type defaultNativePublisherControl struct {
	publisherservice.RunControl
	faults *nativeDefaultFaults
}

func (c defaultNativePublisherControl) DeliverNativePeerPair(ctx context.Context, service, run, pair string, generation int64, token credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error) {
	c.faults.mu.Lock()
	defer c.faults.mu.Unlock()
	if c.faults.outage && pair == c.faults.pair {
		return controlv1.NativePeerPairDelivery{}, clientcontrol.ErrUnavailable
	}
	started := time.Now()
	delivery, err := c.RunControl.DeliverNativePeerPair(ctx, service, run, pair, generation, token)
	if err == nil && pair == c.faults.pair {
		c.faults.publisherUntil = started.Add(delivery.ExpiresAt.Sub(delivery.ObservedAt))
	}
	return delivery, err
}

func TestIntegrationPrivateDefaultLeaseCycles(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newServiceRuntimeFixtureTiming(t, false, nil, true)
	faults := new(nativeDefaultFaults)
	target := startPrivateEchoTarget(t)
	key, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
	service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "default-leases", key)
	if err != nil {
		t.Fatal(err)
	}
	startPrivateHTTPPublisher(t, f, service, target.address, defaultNativePublisherControl{f.identity.routes, faults})
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	firstDevice, err := control.ConnectorSigner(t.Context(), person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	_, tcp := f.connectors()
	startOwner := func(name string, control connectorstream.Control) (net.Listener, func(func(error) bool)) {
		t.Helper()
		listener := serviceRuntimeListener(t)
		ctx, cancel := context.WithCancel(t.Context())
		ready, done := make(chan struct{}), make(chan error, 1)
		go func() {
			done <- connectorstream.Serve(ctx, listener, connectorstream.Config{Control: control, ServiceID: service.Id, IdentityID: person.Identity.Id, Protocol: string(service.Protocol), TrustRevision: service.TrustRevision, Endpoint: service.Endpoint, ServiceTLS: f.visitorRoots, TransportTLS: f.roots, RelayQUIC: privateDisabledConnector(), RelayTCP: tcp, Ready: func() error { close(ready); return nil }})
		}()
		joined := false
		join := func(accept func(error) bool) {
			t.Helper()
			if joined {
				t.Fatal("native owner already joined", name)
			}
			select {
			case err := <-done:
				joined = true
				t.Logf("%s owner terminal cause: %v", name, err)
				if !accept(err) {
					t.Fatal("unexpected native owner terminal cause", name, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("connector did not join", name)
			}
		}
		t.Cleanup(func() {
			cancel()
			if !joined {
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("connector cleanup did not join", name)
				}
			}
		})
		select {
		case <-ready:
		case err := <-done:
			done <- err
			t.Fatal("connector startup", err)
		case <-time.After(10 * time.Second):
			t.Fatal("connector did not become ready")
		}
		return listener, join
	}
	listener, joinOutage := startOwner("outage", defaultNativeOwnerControl{control, faults})
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	exchange := func(n int) {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		payload := fmt.Sprintf("same-stream-%d\n", n)
		if _, err := io.WriteString(conn, payload); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, data); err != nil || string(data) != payload {
			t.Fatalf("default lease cycle changed the stream: %v", err)
		}
	}
	exchange(0)
	faults.mu.Lock()
	pairID, initial := faults.pair, faults.initial
	faults.mu.Unlock()
	var initialBinding string
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT concat(service_run_id,':',run_number,':',delivery_id,':',delivery_generation,':',encode(key_ciphertext,'hex'),':',slots::text) FROM control.native_peer_pairs WHERE id=$1`, pairID).Scan(&initialBinding); err != nil {
		t.Fatal(err)
	}
	// cross more than two full production 30-second lease cycles on this socket.
	for n := 1; n <= 14; n++ {
		select {
		case <-time.After(5 * time.Second):
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
		exchange(n)
	}
	var binding string
	var count int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*),min(concat(service_run_id,':',run_number,':',delivery_id,':',delivery_generation,':',encode(key_ciphertext,'hex'),':',slots::text)) FROM control.native_peer_pairs WHERE service_id=$1`, service.Id).Scan(&count, &binding); err != nil || count != 1 || binding != initialBinding {
		t.Fatal("default renewal replaced the exact native owner", count, err)
	}
	target.mu.Lock()
	first, last := target.receivedOn["same-stream-0\n"], target.receivedOn["same-stream-14\n"]
	for n := range 15 {
		if target.received[fmt.Sprintf("same-stream-%d\n", n)] != 1 {
			t.Error("default renewal replayed application bytes")
		}
	}
	target.mu.Unlock()
	if first == nil || first != last {
		t.Fatal("default renewal reopened the target")
	}
	faults.mu.Lock()
	checks, latest, publisherUntil := faults.renewals, faults.connectorUntil, faults.publisherUntil
	changed := faults.changedPair
	faults.outage = true
	faults.mu.Unlock()
	if checks < 2 || changed || !latest.After(initial.Add(30*time.Second)) || publisherUntil.IsZero() {
		t.Fatalf("default authority did not renew in place: checks=%d changed=%t", checks, changed)
	}
	latest = minTime(latest, publisherUntil)
	// native policy is run-owned, not selectively fetched per stream. use an
	// independently enrolled sibling device: its current revocation must close
	// that owner without extending or prematurely closing the unavailable owner.
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "sibling-state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	profile, err := state.Server(t.Context(), f.controlConfig.ControlOrigin())
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := connectorstream.NewControl(f.identity.routes, profile, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	device, err := sibling.ConnectorSigner(t.Context(), person.Identity.Id)
	if err != nil || device.Subject.DeviceID == firstDevice.Subject.DeviceID {
		t.Fatal("sibling borrowed the unavailable owner's key", err)
	}
	otherListener, joinRevoked := startOwner("revoked sibling", sibling)
	other, err := net.Dial("tcp", otherListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	_ = other.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(other, "revoked\n")
	if _, err := io.ReadFull(other, make([]byte, len("revoked\n"))); err != nil {
		t.Fatal(err)
	}
	assertClosed := func(c net.Conn, deadline time.Time) {
		t.Helper()
		_ = c.SetReadDeadline(deadline.Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("visitor remained open")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("visitor exceeded authorization deadline")
		}
	}
	assertClosed(conn, latest)
	if time.Now().Before(latest.Add(-100 * time.Millisecond)) {
		t.Fatalf("outage ended %v before the captured binding deadline", time.Until(latest))
	}
	joinOutage(func(err error) bool { return errors.Is(err, connectorstream.ErrServiceConnection) })
	// revocation publishes shared run policy, so test it after the isolated
	// outage deadline rather than changing the unavailable owner's policy early.
	if err := f.identity.routes.RevokeVisitorDevice(t.Context(), device.Subject.DeviceID); err != nil {
		t.Fatal(err)
	}
	assertClosed(other, time.Now().Add(30*time.Second))
	joinRevoked(defaultNativeRevocationDenied)
}

// only the deliberately revoked sibling may end with these typed denials:
// selection hides denied access as not found; pair/permission refresh uses
// forbidden. a status alone, a transient failure, or another code is not evidence.
func defaultNativeRevocationDenied(err error) bool {
	var problem *clientcontrol.ProblemError
	reason, _, typed := failure.Describe(err)
	if errors.Is(err, clientcontrol.ErrNotFound) {
		return typed && reason == failure.ServerResourceNotFound
	}
	return typed && reason == failure.ServerDenied && errors.As(err, &problem) && problem != nil &&
		problem.Status == http.StatusForbidden && problem.Problem.Code == controlv1.Forbidden
}

func TestDefaultNativeRevocationDenial(t *testing.T) {
	denial := &clientcontrol.ProblemError{Status: http.StatusForbidden, Problem: controlv1.Problem{Code: controlv1.Forbidden}}
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"typed visitor denial", failure.Wrap("request control API", failure.ServerDenied, denial), true},
		{"wrapped visitor denial", fmt.Errorf("owner: %w", failure.Wrap("request control API", failure.ServerDenied, denial)), true},
		{"unclassified forbidden", denial, false},
		{"other forbidden code", failure.Wrap("request control API", failure.ServerDenied, &clientcontrol.ProblemError{Status: 403, Problem: controlv1.Problem{Code: controlv1.Conflict}}), false},
		{"wrong status", failure.Wrap("request control API", failure.ServerDenied, &clientcontrol.ProblemError{Status: 500, Problem: controlv1.Problem{Code: controlv1.Forbidden}}), false},
		{"wrong classification", failure.Wrap("request control API", failure.ServerRequestInvalid, denial), false},
		{"outage expiry", connectorstream.ErrServiceConnection, false},
		{"selection hides revoked device", clientcontrol.ErrNotFound, true},
		{"wrapped selection denial", fmt.Errorf("owner: %w", clientcontrol.ErrNotFound), true},
		{"unclassified not found", &clientcontrol.ProblemError{Status: 404, Problem: controlv1.Problem{Code: controlv1.NotFound}}, false},
		{"unavailable", clientcontrol.ErrUnavailable, false},
		{"nil", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := defaultNativeRevocationDenied(test.err); got != test.want {
				t.Fatalf("revocation denial = %t, want %t: %v", got, test.want, test.err)
			}
		})
	}
}
