package service

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

type sourceDenialClose struct {
	net.Conn
	entered chan struct{}
	release <-chan struct{}
	cause   error
}

func (c sourceDenialClose) Close() error {
	err := c.Conn.Close()
	close(c.entered)
	<-c.release
	return errors.Join(err, c.cause)
}

func TestServiceHTTPSourceDenialIsObservedBeforeJoinedCleanup(t *testing.T) {
	f := newSourceForwardingFixture(t)
	entry, err := ippolicy.Hash([32]byte{1}, netip.MustParsePrefix("198.51.100.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	restriction, err := ippolicy.New([32]byte{1}, []ippolicy.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	update := f.update
	update.IP = &restriction
	update.View.VisitorPolicyRevision++
	update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(visitortoken.PolicyLifetime)
	if err := f.prepared.policy.Apply(f.prepared.policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	events := make(chan serviceaudit.Observation, 2)
	f.bound.audit = connectorAuditSink(func(o serviceaudit.Observation) bool { events <- o; return true })
	ref := f.prepared.connectionRef(f.bound.connections[0])
	client, server := net.Pipe()
	defer client.Close()
	release, entered := make(chan struct{}), make(chan struct{})
	unblock := func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}
	defer unblock()
	cleanup := errors.New("independent physical cleanup failure")
	wire := sourceDenialClose{Conn: server, entered: entered, release: release, cause: cleanup}
	owned, _ := f.bound.reserveHTTP(t.Context(), ref, wire, f.header)
	if owned == nil {
		t.Fatal("source denial did not enter the real pending admission")
	}
	done := make(chan error, 1)
	go func() {
		err := f.bound.serveBody(owned.http.ctx, ref, owned, f.header, nil, func(context.Context) error {
			f.capacity.Add(1)
			return nil
		}, owned)
		done <- errors.Join(err, owned.http.retire())
	}()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(f.metadata); err != nil {
		t.Fatal(err)
	}
	secured := tls.Client(client, f.verification)
	if err := secured.HandshakeContext(t.Context()); err == nil {
		t.Fatal("excluded source completed visitor TLS")
	}
	<-entered
	select {
	case event := <-events:
		if event.Reason != "ip_policy" || event.Outcome != "denied" || event.EventType != "connection.open" ||
			event.ServiceID != f.header.ServiceID || event.RunID != f.header.ServiceRunID ||
			event.RunNumber != int64(f.header.RunNumber) || event.SourceIP != f.header.SourceIP ||
			event.VisitorConnectionID != f.header.VisitorConnectionID || event.Validate() != nil {
			t.Fatal("source denial lost its safe exact audit facts", event)
		}
	default:
		t.Error("source denial was not observed before physical cleanup")
	}
	select {
	case <-done:
		t.Fatal("source denial returned before owned cleanup joined")
	default:
	}
	unblock()
	err = sourceForwardingJoined(t, done)
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.VisitorAccessDenied || !errors.Is(err, cleanup) {
		t.Error("source denial or independent cleanup cause was lost", err)
	}
	if f.delivered.Load() != 0 || f.capacity.Load() != 0 {
		t.Fatal("excluded source spent target or application capacity")
	}
	assertHTTPAdmissionCharges(t, owned.http, 0, 0, 0)
	select {
	case event := <-events:
		t.Fatal("pre-TLS source denial emitted a duplicate observation", event)
	default:
	}
}
