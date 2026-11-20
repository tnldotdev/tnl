package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// hold the same lock across actual HTTP decisions and the outage transition.
// an already-entered success cannot extend the captured bound after the fault.
type nativeDefaultFaults struct {
	mu                                                           sync.Mutex
	pair                                                         string
	outage                                                       bool
	renewals                                                     int
	initial, connectorUntil, publisherUntil, publisherOwnerUntil time.Time
	runUntil, permissionUntil, tokenUntil                        time.Time
	changedPair                                                  bool
	connectorLease, publisherLease, publisherOwnerLease          nativeDefaultLeaseObservation
}

type nativeDefaultLeaseObservation struct {
	reported, observed, until time.Time
}

func (f *nativeDefaultFaults) outageReady(now, sessionUntil time.Time) bool {
	// pair authority is capped by the signed visitor permission, whose expiry
	// has whole-second precision rather than the parent session's microseconds.
	sessionUntil = sessionUntil.Truncate(time.Second)
	connectorDeadline := minTime(f.connectorUntil, minTime(f.runUntil, f.permissionUntil))
	publisherDeadline := minTime(f.publisherOwnerUntil, f.tokenUntil)
	earliest := minTime(connectorDeadline, publisherDeadline)
	// leave ten seconds of margin before the unchanged 30-second inner QUIC
	// idle timeout. both endpoints must reach real authority expiry first.
	beforeIdle := f.publisherUntil.Add(20 * time.Second)
	return f.connectorLease.reported.Equal(sessionUntil) && f.publisherOwnerLease.reported.Equal(sessionUntil) &&
		f.publisherUntil.After(now.Add(10*time.Second)) && earliest.After(f.publisherUntil.Add(2*time.Second)) &&
		connectorDeadline.Before(beforeIdle) && publisherDeadline.Before(beforeIdle)
}

func (o *nativeDefaultLeaseObservation) record(started, observed, reported time.Time) time.Time {
	if !o.observed.IsZero() && !observed.After(o.observed) {
		return o.until
	}
	until := started.Add(reported.Sub(observed))
	if !o.reported.IsZero() && !reported.After(o.reported) {
		until = minTime(until, o.until)
	}
	o.reported, o.observed, o.until = reported, observed, until
	return until
}

type defaultConnectorOwnerControl struct {
	connectorstream.Control
	faults *nativeDefaultFaults
}

func (c defaultConnectorOwnerControl) PrepareConnectorPeerPair(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	// the caller's authority interval includes time waiting for the fault lock.
	started := time.Now()
	c.faults.mu.Lock()
	defer c.faults.mu.Unlock()
	if c.faults.outage {
		return controlv1.ConnectorPeerPair{}, clientcontrol.ErrUnavailable
	}
	pair, err := c.Control.PrepareConnectorPeerPair(ctx, service, body)
	if err == nil {
		until := c.faults.connectorLease.record(started, pair.ObservedAt, pair.ExpiresAt)
		if c.faults.pair == "" {
			c.faults.pair, c.faults.initial = pair.PairId, until
		}
		c.faults.changedPair = c.faults.changedPair || c.faults.pair != pair.PairId
		c.faults.connectorUntil = until
	}
	return pair, err
}

func (c defaultConnectorOwnerControl) RenewConnectorPeerPair(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
	started := time.Now()
	c.faults.mu.Lock()
	defer c.faults.mu.Unlock()
	if c.faults.outage {
		return controlv1.ConnectorPeerPairRenewal{}, clientcontrol.ErrUnavailable
	}
	renewal, err := c.Control.RenewConnectorPeerPair(ctx, service, body)
	if err == nil {
		c.faults.changedPair = c.faults.changedPair || c.faults.pair != renewal.Pair.PairId
		bound := c.faults.connectorLease.record(started, renewal.Pair.ObservedAt, renewal.Pair.ExpiresAt)
		c.faults.connectorUntil = bound
		c.faults.runUntil = bound.Add(renewal.RunValidUntil.Sub(renewal.Pair.ExpiresAt))
		c.faults.permissionUntil = bound.Add(renewal.VisitorPermission.ExpiresAt.Sub(renewal.Pair.ExpiresAt))
		// signed visitor tokens carry whole-second expiry, independently of the
		// API interval. account for that exact fence rather than widening tolerance.
		c.faults.tokenUntil = bound.Add(renewal.VisitorPermission.ExpiresAt.Truncate(time.Second).Sub(renewal.Pair.ExpiresAt))
		c.faults.renewals++
	}
	return renewal, err
}

func (c defaultConnectorOwnerControl) RebindConnectorPeerPair(ctx context.Context, service, pair string, body controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
	c.faults.mu.Lock()
	defer c.faults.mu.Unlock()
	if c.faults.outage {
		return controlv1.ConnectorPeerPairRebindState{}, clientcontrol.ErrUnavailable
	}
	return c.Control.RebindConnectorPeerPair(ctx, service, pair, body)
}

type defaultConnectorPublisherControl struct {
	publisherservice.RunControl
	faults *nativeDefaultFaults
}

func (c defaultConnectorPublisherControl) ListConnectorPeerPairs(ctx context.Context, service, run, after string, token credentials.ServiceRunToken) (controlv1.ConnectorPeerPairCandidates, error) {
	started := time.Now()
	c.faults.mu.Lock()
	defer c.faults.mu.Unlock()
	page, err := c.RunControl.ListConnectorPeerPairs(ctx, service, run, after, token)
	for index := range page.Items {
		candidate := &page.Items[index]
		if candidate.PairId != c.faults.pair || candidate.OwnerAuthority == nil {
			continue
		}
		if c.faults.outage {
			candidate.OwnerAuthority = nil // the sibling may still observe its own authority.
			continue
		}
		observation := candidate.OwnerAuthority
		c.faults.publisherOwnerUntil = c.faults.publisherOwnerLease.record(started, observation.ObservedAt, observation.ExpiresAt)
	}
	return page, err
}

func (c defaultConnectorPublisherControl) DeliverConnectorPeerPair(ctx context.Context, service, run, pair string, generation int64, token credentials.ServiceRunToken) (controlv1.ConnectorPeerPairDelivery, error) {
	started := time.Now()
	c.faults.mu.Lock()
	defer c.faults.mu.Unlock()
	if c.faults.outage && pair == c.faults.pair {
		return controlv1.ConnectorPeerPairDelivery{}, clientcontrol.ErrUnavailable
	}
	delivery, err := c.RunControl.DeliverConnectorPeerPair(ctx, service, run, pair, generation, token)
	if err == nil && pair == c.faults.pair {
		c.faults.publisherUntil = c.faults.publisherLease.record(started, delivery.ObservedAt, delivery.ExpiresAt)
		c.faults.publisherOwnerUntil = c.faults.publisherOwnerLease.record(started, delivery.ObservedAt, delivery.ExpiresAt)
	}
	return delivery, err
}

func TestIntegrationPrivateDefaultLeaseCycles(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	// refresh near 40 seconds leaves an installation cap near 120 seconds;
	// refresh after the 70-second healthy phase reaches the fixed 135-second cap.
	const accessLifetime = 80 * time.Second
	f := newServiceRuntimeFixtureTiming(t, false, nil, true, func(config *daemonconfig.Config, _ *http.Transport, _ *testCertificateAuthority) {
		config.AccessTokenLifetime = accessLifetime
	})
	faults := new(nativeDefaultFaults)
	target := startPrivateEchoTarget(t, f.owner)
	key, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
	service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "default-leases", key, controlv1.ServiceMetadata{Protocol: controlv1.Tcp}, nil)
	if err != nil {
		t.Fatal(err)
	}
	startPrivateHTTPPublisher(t, f, service, target.address, func(cfg *publisherservice.RunConfig) {
		cfg.Control = defaultConnectorPublisherControl{f.identity.routes, faults}
	})
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// only the outage connector uses this finite parent session. refresh rotates
	// its credentials but cannot move the committed refresh expiry. publisher
	// and sibling authority remain independent and long-lived.
	outageState, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "outage-state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outageState.Close() })
	origin := f.controlConfig.ControlOrigin()
	session, err := controltest.Session(t.Context(), f.database, f.controlConfig.ManagedDomain, accessLifetime, 135*time.Second, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if session.Identity.Identity.ID != person.Identity.Id {
		t.Fatal("outage session changed the visitor identity")
	}
	if err := controltest.SaveSession(t.Context(), outageState, origin, session); err != nil {
		t.Fatal(err)
	}
	outageClient, err := clientauth.Authenticate(t.Context(), clientauth.Config{ServerEndpoint: origin, State: outageState, HTTPClient: f.publicHTTP, Diagnostics: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	outageProfile, err := outageState.Server(t.Context(), origin)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(origin, f.publicHTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	refreshSession := func() clientstate.ControlSession {
		t.Helper()
		// use the same protected-state lock and single-use checkpoint as normal
		// client refresh, so automatic refresh cannot race this fixture step.
		lock, err := clientstate.LockControlSessionContext(t.Context(), outageProfile)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		stored, found, err := outageProfile.ControlSession(t.Context())
		if err != nil || !found || stored.RefreshPhase(time.Now()) != clientstate.RefreshAvailable {
			t.Fatal("outage session is not refreshable", err)
		}
		if err := outageProfile.MarkControlSessionRefreshPending(t.Context()); err != nil {
			t.Fatal(err)
		}
		response, err := authority.Refresh(t.Context(), credentials.RefreshToken(stored.RefreshToken))
		if err != nil {
			t.Fatal(err)
		}
		refreshed, err := clientauthority.ValidateControlSessionResponse(response, session.SessionID, session.RefreshExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		if err := outageProfile.SaveControlSession(t.Context(), refreshed); err != nil {
			t.Fatal(err)
		}
		return refreshed
	}
	control, err := connectorstream.NewControl(outageClient.Control, outageProfile, person.Identity.Id)
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
		listener := serviceRuntimeListener(t, f.owner)
		ctx, cancel := context.WithCancel(t.Context())
		ready, done := make(chan struct{}), make(chan error, 1)
		go func() {
			done <- connectorstream.Serve(ctx, listener, connectorstream.Config{Control: control, ServiceID: service.Id, IdentityID: person.Identity.Id, Protocol: string(service.Protocol), TrustRevision: service.TrustRevision, Endpoint: service.Endpoint, ServiceTLS: f.visitorRoots, TransportTLS: f.roots, RelayQUIC: privateDisabledConnector(), RelayWebSocket: tcp, Ready: func() error { close(ready); return nil }})
		}()
		joined := false
		join := func(accept func(error) bool) {
			t.Helper()
			if joined {
				t.Fatal("connector owner already joined", name)
			}
			select {
			case err := <-done:
				joined = true
				t.Logf("%s owner terminal cause: %v", name, err)
				if !accept(err) {
					t.Fatal("unexpected connector owner terminal cause", name, err)
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
	listener, joinOutage := startOwner("outage", defaultConnectorOwnerControl{control, faults})
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
	var initialBinding, runID, deliveryID, parentSessionID string
	var runNumber, deliveryGeneration int64
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT concat(service_run_id,':',run_number,':',delivery_id,':',delivery_generation,':',encode(key_ciphertext,'hex'),':',slots::text,':',parent_control_session_id),
		service_run_id, run_number, encode(delivery_id,'hex'), delivery_generation, parent_control_session_id
		FROM control.connector_peer_pairs WHERE id=$1`, pairID).Scan(&initialBinding, &runID, &runNumber, &deliveryID, &deliveryGeneration, &parentSessionID); err != nil {
		t.Fatal(err)
	}
	if parentSessionID != session.SessionID {
		t.Fatal("connector pair is not bound to the finite parent session")
	}
	// cross more than two full production 30-second lease cycles on this socket.
	lastExchange := 0
	for n := 1; n <= 14; n++ {
		select {
		case <-time.After(5 * time.Second):
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
		exchange(n)
		lastExchange = n
		if n == 8 {
			// advance owner authority by more than 30 seconds without changing
			// the pair. publisher delivery can observe this intermediate cap.
			refreshSession()
		}
	}
	// extend the same live session once more, after the publisher's intermediate
	// installation. the fixed refresh expiry now caps all later credentials.
	finalSession := refreshSession()
	if !finalSession.AccessExpiresAt.Equal(session.RefreshExpiresAt) {
		t.Fatal("final access credential did not reach the fixed session expiry")
	}
	// choose an actual renewal phase where installation expires before both
	// endpoint owners and application permission. otherwise a permission expiry
	// could close the target first and make the packet-pause assertion vacuous.
	var checks int
	var latest, publisherUntil, publisherOwnerUntil, runUntil, permissionUntil, tokenUntil time.Time
	var connectorReported, publisherOwnerReported time.Time
	var changed bool
	phaseDeadline := time.Now().Add(20 * time.Second)
	for {
		faults.mu.Lock()
		checks, latest, publisherUntil, publisherOwnerUntil = faults.renewals, faults.connectorUntil, faults.publisherUntil, faults.publisherOwnerUntil
		runUntil, permissionUntil, tokenUntil = faults.runUntil, faults.permissionUntil, faults.tokenUntil
		connectorReported, publisherOwnerReported = faults.connectorLease.reported, faults.publisherOwnerLease.reported
		changed = faults.changedPair
		if faults.outageReady(time.Now(), session.RefreshExpiresAt) {
			faults.outage = true
			faults.mu.Unlock()
			break
		}
		faults.mu.Unlock()
		if !time.Now().Before(phaseDeadline) {
			t.Fatalf("default renewal did not leave a retained-owner interval between installation expiry and inner QUIC idleness: session=%s connector_reported=%s publisher_owner_reported=%s connector=%s run=%s permission=%s token=%s delivery=%s publisher_owner=%s",
				session.RefreshExpiresAt.Format(time.RFC3339Nano), connectorReported.Format(time.RFC3339Nano), publisherOwnerReported.Format(time.RFC3339Nano),
				latest.Format(time.RFC3339Nano), runUntil.Format(time.RFC3339Nano), permissionUntil.Format(time.RFC3339Nano), tokenUntil.Format(time.RFC3339Nano), publisherUntil.Format(time.RFC3339Nano), publisherOwnerUntil.Format(time.RFC3339Nano))
		}
		select {
		case <-time.After(time.Second):
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
		lastExchange++
		exchange(lastExchange)
	}
	var binding string
	var count int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*),min(concat(service_run_id,':',run_number,':',delivery_id,':',delivery_generation,':',encode(key_ciphertext,'hex'),':',slots::text,':',parent_control_session_id)) FROM control.connector_peer_pairs WHERE service_id=$1`, service.Id).Scan(&count, &binding); err != nil || count != 1 || binding != initialBinding {
		t.Fatal("default renewal replaced the exact connector owner", count, err)
	}
	target.mu.Lock()
	first, last := target.receivedOn["same-stream-0\n"], target.receivedOn[fmt.Sprintf("same-stream-%d\n", lastExchange)]
	targetClosed := target.closedOn[first]
	for n := range lastExchange + 1 {
		if target.received[fmt.Sprintf("same-stream-%d\n", n)] != 1 {
			t.Error("default renewal replayed application bytes")
		}
	}
	target.mu.Unlock()
	if first == nil || first != last || targetClosed == nil {
		t.Fatal("default renewal reopened the target")
	}
	t.Logf("outage at=%s connector=%s run=%s permission=%s token=%s publisher delivery=%s publisher owner=%s", time.Now().Format(time.RFC3339Nano), latest.Format(time.RFC3339Nano), runUntil.Format(time.RFC3339Nano), permissionUntil.Format(time.RFC3339Nano), tokenUntil.Format(time.RFC3339Nano), publisherUntil.Format(time.RFC3339Nano), publisherOwnerUntil.Format(time.RFC3339Nano))
	t.Logf("outage binding service=%s run=%s run_number=%d pair=%s delivery_hex=%s delivery_generation=%d device=%s parent_session=%s fixed_expiry=%s",
		service.Id, runID, runNumber, pairID, deliveryID, deliveryGeneration, firstDevice.Subject.DeviceID, parentSessionID, session.RefreshExpiresAt.Format(time.RFC3339Nano))
	if checks < 2 || changed || !latest.After(initial.Add(30*time.Second)) || publisherUntil.IsZero() || publisherOwnerUntil.IsZero() || runUntil.IsZero() || permissionUntil.IsZero() || tokenUntil.IsZero() {
		t.Fatalf("default authority did not renew in place: checks=%d changed=%t", checks, changed)
	}
	// installation expiry pauses packets. each endpoint must close its local
	// sockets by its own owner or application deadline: the paused path cannot
	// carry a remote close. the outage blocks both forms of owner observation.
	latest = minTime(latest, minTime(runUntil, permissionUntil))
	publisherDeadline := minTime(publisherOwnerUntil, tokenUntil)
	earliestExpiry := minTime(latest, publisherDeadline)
	type closure struct {
		at  time.Time
		err error
	}
	readClosure := func(c net.Conn, deadline time.Time) closure {
		_ = c.SetReadDeadline(deadline.Add(2 * time.Second))
		_, err := c.Read(make([]byte, 1))
		return closure{at: time.Now(), err: err}
	}
	// observe EOF immediately, even while the sibling is starting or the target
	// deadline is pending, so those waits cannot hide premature loopback closure.
	localClosed := make(chan closure, 1)
	localReadDone := make(chan struct{})
	go func() { defer close(localReadDone); localClosed <- readClosure(conn, latest) }()
	defer func() { _ = conn.Close(); <-localReadDone }()
	// native policy is run-owned, not selectively fetched per stream. use an
	// independently enrolled sibling device: its current revocation must close
	// that owner without extending or prematurely closing the unavailable owner.
	if runtime.GOOS == "darwin" {
		clientstate.UseMemoryKeychainForTesting()
	}
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
	assertClosed := func(result closure) {
		t.Helper()
		if result.err == nil {
			t.Fatal("visitor remained open")
		} else if timeout, ok := result.err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("visitor exceeded authorization deadline")
		}
	}
	const fenced = "must-not-flow-after-installation-expiry\n"
	wait := time.NewTimer(time.Until(publisherUntil))
	defer wait.Stop()
	select {
	case <-wait.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	select {
	case <-targetClosed:
		t.Fatal("installation expiry retired the still-authorized target socket")
	case <-localClosed:
		t.Fatal("installation expiry retired the still-authorized loopback socket")
	default:
	}
	_ = conn.SetWriteDeadline(latest.Add(2 * time.Second))
	if _, err := io.WriteString(conn, fenced); err != nil {
		t.Fatal("retained loopback socket closed before its authority expired", err)
	}
	targetDeadline := time.NewTimer(time.Until(publisherDeadline.Add(2 * time.Second)))
	defer targetDeadline.Stop()
	select {
	case <-targetClosed:
	case <-targetDeadline.C:
		t.Fatal("target socket exceeded publisher owner or application permission deadline")
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	closed := <-localClosed
	assertClosed(closed)
	t.Logf("outage TCP stream closed at=%s connector_deadline=%s publisher_deadline=%s earliest_deadline=%s",
		closed.at.Format(time.RFC3339Nano), latest.Format(time.RFC3339Nano), publisherDeadline.Format(time.RFC3339Nano), earliestExpiry.Format(time.RFC3339Nano))
	target.mu.Lock()
	fencedArrivals := target.received[fenced]
	target.mu.Unlock()
	if fencedArrivals != 0 {
		t.Fatal("expired publisher installation carried new application bytes")
	}
	if closed.at.Before(earliestExpiry.Add(-100 * time.Millisecond)) {
		t.Fatalf("outage ended %v before the captured owner and permission deadlines", earliestExpiry.Sub(closed.at))
	}
	joinOutage(func(err error) bool { return errors.Is(err, connectorstream.ErrServiceConnection) })
	// revocation publishes shared run policy, so test it after the isolated
	// outage deadline rather than changing the unavailable owner's policy early.
	_ = other.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(other, "still-connected\n"); err != nil {
		t.Fatal("sibling closed before revocation:", err)
	}
	if _, err := io.ReadFull(other, make([]byte, len("still-connected\n"))); err != nil {
		t.Fatal("sibling closed before revocation:", err)
	}
	if err := f.identity.routes.RevokeVisitorDevice(t.Context(), device.Subject.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.identity.routes.SelectServiceRun(t.Context(), service.Id, device.Subject.DeviceID); !defaultConnectorRevocationDenied(err) {
		t.Fatalf("control did not deny the revoked sibling: %v", err)
	}
	assertClosed(readClosure(other, time.Now().Add(30*time.Second)))
	// the relay may close both legs before the owner receives a typed denial.
	// control above must independently deny this exact device in either case.
	joinRevoked(func(err error) bool {
		var denial *tunnel.ProtocolError
		return defaultConnectorRevocationDenied(err) || errors.Is(err, connectorstream.ErrServiceConnection) ||
			errors.As(err, &denial) && denial.Code == tunnelv1.Unauthenticated
	})
}

func TestDefaultNativeOutagePhase(t *testing.T) {
	now := time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)
	sessionUntil := now.Add(65*time.Second + 900*time.Millisecond)
	until := sessionUntil.Truncate(time.Second)
	for _, test := range []struct {
		name   string
		change func(*nativeDefaultFaults)
		want   bool
	}{
		{"authority before idle", func(*nativeDefaultFaults) {}, true},
		{"old connector credential", func(f *nativeDefaultFaults) { f.connectorLease.reported = until.Add(-time.Second) }, false},
		{"old publisher observation", func(f *nativeDefaultFaults) { f.publisherOwnerLease.reported = until.Add(-time.Second) }, false},
		{"insufficient startup interval", func(f *nativeDefaultFaults) { f.publisherUntil = now.Add(10 * time.Second) }, false},
		{"permission before packet pause", func(f *nativeDefaultFaults) { f.tokenUntil = f.publisherUntil.Add(time.Second) }, false},
		{"connector could idle first", func(f *nativeDefaultFaults) {
			f.connectorUntil, f.runUntil, f.permissionUntil = until.Add(20*time.Second), until.Add(20*time.Second), until.Add(20*time.Second)
		}, false},
		{"publisher could idle first", func(f *nativeDefaultFaults) {
			f.publisherOwnerUntil, f.tokenUntil = until.Add(20*time.Second), until.Add(20*time.Second)
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := &nativeDefaultFaults{
				connectorUntil: until, runUntil: until, permissionUntil: until, tokenUntil: until.Add(-time.Second),
				publisherUntil: now.Add(50 * time.Second), publisherOwnerUntil: until,
				connectorLease: nativeDefaultLeaseObservation{reported: until}, publisherOwnerLease: nativeDefaultLeaseObservation{reported: until},
			}
			test.change(f)
			if got := f.outageReady(now, sessionUntil); got != test.want {
				t.Fatalf("outage ready = %t, want %t", got, test.want)
			}
		})
	}
}

func TestDefaultNativeLeaseObservation(t *testing.T) {
	at := time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)
	var observation nativeDefaultLeaseObservation
	started := at.Add(-400 * time.Millisecond)
	reported := at.Add(30 * time.Second)
	want := started.Add(30 * time.Second)
	if got := observation.record(started, at, reported); !got.Equal(want) {
		t.Fatal("observation restored time spent waiting for the fixture fault lock")
	}
	if got := observation.record(at.Add(time.Second), at.Add(time.Second), reported); !got.Equal(want) {
		t.Fatal("unchanged absolute expiry slid its local fence")
	}
	if got := observation.record(at.Add(-time.Second), at.Add(-time.Second), reported.Add(time.Minute)); !got.Equal(want) {
		t.Fatal("older evidence replaced the current observation")
	}
	next := reported.Add(10 * time.Second)
	if got := observation.record(at.Add(2*time.Second), at.Add(2*time.Second), next); !got.Equal(next) {
		t.Fatal("new authority did not advance the original owner's fence")
	}
	shorter := next.Add(-time.Second)
	if got := observation.record(at.Add(3*time.Second), at.Add(3*time.Second), shorter); !got.Equal(shorter) {
		t.Fatal("shorter authority did not narrow the current fence")
	}
}

// only the deliberately revoked sibling may end with these typed denials:
// selection hides denied access as not found; pair/permission refresh uses
// forbidden. a status alone, a transient failure, or another code is not evidence.
func defaultConnectorRevocationDenied(err error) bool {
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
			if got := defaultConnectorRevocationDenied(test.err); got != test.want {
				t.Fatalf("revocation denial = %t, want %t: %v", got, test.want, test.err)
			}
		})
	}
}
