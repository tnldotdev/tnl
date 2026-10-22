package tnldruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	tcpconnect "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	privatepublisher "github.com/tnldotdev/tnl/internal/publisher/managed"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type privateRecheckFaults struct {
	mu             sync.Mutex
	outage         string
	checks         map[string]int
	publisherUntil map[string]time.Time
}

type defaultPrivateRecheck struct {
	ingress.PrivateControl
	faults *privateRecheckFaults
}

func (c defaultPrivateRecheck) RecheckPrivateServiceVisitor(ctx context.Context, id string, body ingressv1.PrivateServiceVisitorRecheck) (ingressv1.PrivateServiceVisitorRecheckResult, error) {
	c.faults.mu.Lock()
	defer c.faults.mu.Unlock()
	if c.faults.outage == body.VisitorConnectionId {
		return ingressv1.PrivateServiceVisitorRecheckResult{}, errors.New("control recheck unavailable")
	}
	result, err := c.PrivateControl.RecheckPrivateServiceVisitor(ctx, id, body)
	if err == nil && result.Allowed {
		c.faults.checks[body.VisitorConnectionId]++
	}
	return result, err
}

type defaultPublisherRecheck struct {
	privatepublisher.RunControl
	faults *privateRecheckFaults
}

func (c defaultPublisherRecheck) AuthorizeServiceConnector(ctx context.Context, service, run string, token credentials.ManagedRunToken, body controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	c.faults.mu.Lock()
	defer c.faults.mu.Unlock()
	if c.faults.outage == body.VisitorConnectionId {
		return controlv1.ServiceClientCertificateDecision{}, controlclient.ErrUnavailable
	}
	decision, err := c.RunControl.AuthorizeServiceConnector(ctx, service, run, token, body)
	if err == nil && decision.Allowed {
		c.faults.publisherUntil[body.VisitorConnectionId] = decision.ValidUntil
	}
	return decision, err
}

func TestIntegrationPrivateDefaultLeaseCycles(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	opened := make(chan privateObservation, 4)
	f := newPrivateRuntimeFixtureTiming(t, false, opened, true)
	faults := &privateRecheckFaults{checks: make(map[string]int), publisherUntil: make(map[string]time.Time)}
	f.configurePrivate = func(config *ingress.PrivateConnectorConfig) {
		// observe real control decisions without changing scheduling hints or TTLs.
		config.Control = defaultPrivateRecheck{config.Control, faults}
	}
	startSeparatedPrivateIngress(t, f, 0, "tls-tcp", opened)
	startSeparatedPrivateIngress(t, f, 1, "tls-tcp", opened)
	target := startPrivateEchoTarget(t)
	key, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
	service, err := f.identity.routes.CreatePrivateService(t.Context(), f.identity.teamID, "default-leases", key)
	if err != nil {
		t.Fatal(err)
	}
	startPrivateHTTPPublisher(t, f, service, target.address, defaultPublisherRecheck{RunControl: f.identity.routes, faults: faults})
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	control, err := tcpconnect.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	device, err := control.PrivateConnectorSigner(t.Context(), person.Identity.Id)
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
		done <- tcpconnect.Serve(ctx, listener, tcpconnect.Config{Control: control, PrivateServiceID: service.Id, IdentityID: person.Identity.Id,
			Protocol: string(service.Protocol), TrustRevision: service.TrustRevision, ManagedTLS: service.ManagedTls, ServiceTLS: f.visitorRoots, Ready: func() error { close(ready); return nil }})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
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
			t.Fatalf("default lease cycle closed or changed the stream: %v", err)
		}
	}
	exchange(0)
	observation := <-opened
	visitorID := observation.header.VisitorConnectionID
	var initial time.Time
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT valid_until FROM control.private_visitor_streams WHERE visitor_connection_id=$1`, visitorID).Scan(&initial); err != nil {
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
	var count int
	var latest time.Time
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*),max(valid_until) FROM control.private_visitor_streams WHERE connector_session_id=$1 AND closed_at IS NULL`, observation.header.Connector.SessionID).Scan(&count, &latest); err != nil || count != 1 || !latest.After(initial.Add(30*time.Second)) {
		t.Fatalf("did not renew the same admitted visitor: count=%d err=%v", count, err)
	}
	select {
	case <-opened:
		t.Fatal("long-lived stream was replaced")
	default:
	}
	faults.mu.Lock()
	checks := faults.checks[visitorID]
	faults.outage = visitorID
	publisherUntil := faults.publisherUntil[visitorID]
	faults.mu.Unlock()
	if checks < 2 {
		t.Fatalf("only %d successful default rechecks", checks)
	}
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT valid_until FROM control.private_visitor_streams WHERE visitor_connection_id=$1`, visitorID).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if !publisherUntil.IsZero() && publisherUntil.Before(latest) {
		latest = publisherUntil
	}
	// a second stream can still reach control and must observe device revocation;
	// the original stream's unavailable recheck must honor its last hard deadline.
	other, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	_ = other.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(other, "revoked\n")
	if _, err := io.ReadFull(other, make([]byte, len("revoked\n"))); err != nil {
		t.Fatal(err)
	}
	<-opened
	if err := f.identity.routes.RevokeVisitorDevice(t.Context(), device.Subject.DeviceID); err != nil {
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
		t.Fatal("outage did not preserve admitted stream until its deadline")
	}
	assertClosed(other, time.Now().Add(30*time.Second))
}
