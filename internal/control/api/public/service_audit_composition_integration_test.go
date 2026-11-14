package public

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	controlingress "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type auditCompositionSink struct {
	queue    *serviceaudit.Queue
	events   chan serviceaudit.Observation
	promoted chan struct{}
}

func (s auditCompositionSink) Observe(o serviceaudit.Observation) bool {
	if !s.queue.Observe(o) {
		return false
	}
	s.events <- o
	if o.EventType == "connection.open" && o.Outcome == "allowed" {
		s.promoted <- struct{}{}
	}
	return true
}

// only the target transport is local to this fixture. service transport admission,
// ingress producers, queue and audit HTTP all use production
// code against the same database and exact ingress lease.
type auditCompositionTarget struct {
	tls      *tls.Config
	ctx      context.Context
	promoted <-chan struct{}
	workers  sync.WaitGroup
}

func (f *auditCompositionTarget) OpenPrivate(context.Context, ingressv1.ServiceRelay, tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	return f.open(), nil
}

func (f *auditCompositionTarget) open() net.Conn {
	front, back := net.Pipe()
	f.workers.Add(1)
	go func() {
		defer f.workers.Done()
		defer back.Close()
		_ = back.SetDeadline(time.Now().Add(10 * time.Second))
		_, reader, err := proxyproto.Decode(back)
		if err != nil {
			return
		}
		secure := tls.Server(&auditReaderConn{Conn: back, reader: reader}, f.tls)
		defer secure.Close()
		if err = secure.Handshake(); err != nil {
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(secure))
		if err == nil {
			body, err := io.ReadAll(request.Body)
			_ = request.Body.Close()
			if err != nil {
				return
			}
			if len(body) == 0 {
				body = []byte("ok")
			}
			// synchronize on actual transport promotion, not a delay. otherwise
			// a fast response may close before the guard can report an open.
			select {
			case <-f.promoted:
			case <-f.ctx.Done():
				return
			}
			_, _ = fmt.Fprintf(secure, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		}
	}()
	return front
}

type auditReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *auditReaderConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

type auditCompositionRun struct {
	service       controlstate.ServiceRecord
	prepared      controlstate.ServiceRunPreparation
	run           controlstate.ServiceRunState
	publisher     controlstate.PublisherIdentity
	enrollmentKey string
}

func newAuditCompositionRelays(t *testing.T, d *controlstate.Database, now time.Time) map[string]controlstate.RelayLease {
	t.Helper()
	relays := map[string]controlstate.RelayLease{}
	for _, name := range []string{"audit-a", "audit-b"} {
		process, _ := opaqueid.New(opaqueid.RelayRunPrefix)
		r, err := d.RegisterRelay(t.Context(), controlstate.RelayRegistration{RelayServiceID: name, RelayID: name, RelayRunID: process, ProtocolVersion: 1,
			RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test", InternalRelayAddress: "127.0.0.1:8443", ConnectionCapacity: 20, StreamCapacity: 20}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		relays[name] = r
	}
	return relays
}

func newAuditCompositionRun(t *testing.T, d *controlstate.Database, inspect *pgxpool.Pool, relays map[string]controlstate.RelayLease,
	actor, team, member, name string, now time.Time) auditCompositionRun {
	t.Helper()
	ctx := t.Context()
	service, err := d.CreateServiceAt(ctx, team, actor, name, name, controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "http"})
	if err != nil {
		t.Fatal(err)
	}
	var policy int64
	if err = inspect.QueryRow(ctx, `SELECT policy_revision FROM control.teams WHERE id=$1`, team).Scan(&policy); err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{Scope: controlstate.PublisherScope{TeamID: team, Kind: "service", ServiceID: service.ID},
		Name: name, Kind: "installed", EditorID: actor, EditorMembershipID: member, PolicyRevision: uint64(policy), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, name, now, controlstate.ServiceMetadata{Protocol: "http", TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	managedcert.Install(t, d, prepared, run, now)
	for _, slot := range run.Connections {
		r := relays[slot.RelayServiceID]
		if _, err = d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, r.RelayLeaseIdentity, now); err != nil {
			t.Fatal(err)
		}
		if _, err = d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, r.RelayLeaseIdentity, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect.Exec(ctx, `UPDATE control.services SET public=true WHERE id=$1`, service.ID); err != nil {
		t.Fatal(err)
	}
	return auditCompositionRun{service: service, prepared: prepared, run: run, publisher: publisher, enrollmentKey: enrollment.Key}
}

func exerciseServiceAuditQueueComposition(t *testing.T, d *controlstate.Database, inspect *pgxpool.Pool, lease controlstate.IngressLease,
	fixture auditCompositionRun, report serviceaudit.Reporter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()
	service, prepared, run, publisher := fixture.service, fixture.prepared, fixture.run, fixture.publisher
	// a pending HTTP transport has no person/device identity. only actual
	// promotion permits an allowed transport audit; it never grants app access.
	pendingID, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := d.AdmitPublicServiceVisitor(ctx, lease.IngressLeaseIdentity, controlstate.PrimaryIngressPoolID, pendingID, prepared.Hostname, 443, netip.MustParseAddr("127.0.0.1"), now)
	if err != nil {
		t.Fatal(err)
	}
	unpromoted := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: service.ID, ServiceKind: "service", RunID: pending.RunID, RunNumber: pending.RunNumber,
		VisitorConnectionID: pendingID, SourceIP: "127.0.0.1", EventType: "connection.open", OccurredAt: now, Outcome: "allowed"}
	if _, err := d.IngestIngressServiceObservations(ctx, lease.IngressLeaseIdentity, serviceaudit.Batch{Events: []serviceaudit.Observation{unpromoted}}, now); !errors.Is(err, controlstate.ErrServiceAuditAccess) {
		t.Fatal("unpromoted HTTP transport reported allowed access", err)
	}
	if err := d.ClosePublicServiceVisitor(ctx, lease.IngressLeaseIdentity, pendingID, now); err != nil {
		t.Fatal(err)
	}
	var dropped uint64
	rejected, retried := 0, false
	queue, err := serviceaudit.NewQueue(ctx, serviceaudit.QueueConfig{FlushInterval: time.Hour, RetryMin: time.Millisecond, RetryMax: time.Millisecond,
		Dropped: func(n uint64) { dropped += n }, Report: func(ctx context.Context, b serviceaudit.Batch) error {
			err := report(ctx, b)
			if errors.Is(err, serviceaudit.ErrRejected) && len(b.Events) == 1 {
				rejected++
			}
			if err == nil && !retried {
				retried = true
				return errors.New("lost audit acknowledgement after commit")
			}
			return err
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close(context.Background()) })
	sink := auditCompositionSink{queue: queue, events: make(chan serviceaudit.Observation, 16), promoted: make(chan struct{}, 2)}
	badRun, _ := opaqueid.New(opaqueid.ServiceRunPrefix)
	bad := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: service.ID, ServiceKind: "service", RunID: badRun, RunNumber: 1,
		VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", SourceIP: "127.0.0.1", EventType: "connection.open", OccurredAt: now, Outcome: "denied", Reason: "authorization"}
	if !queue.Observe(bad) {
		t.Fatal("regression event must pass syntax to exercise control scope rejection")
	}
	serverTLS, clientTLS := auditCompositionTLS(t, prepared.Hostname)
	clientTLS.ServerName = prepared.Hostname
	target := &auditCompositionTarget{tls: serverTLS, ctx: ctx, promoted: sink.promoted}
	direct, err := controlingress.NewDirectClient(controlingress.DirectConfig{Store: d, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	connector, err := ingress.NewPublicServices(ingress.PublicServicesConfig{Control: direct, Forwarder: target,
		AuditSink: sink, CurrentLease: func() ingressv1.IngressLease {
			return ingressv1.IngressLease{IngressId: lease.IngressID, IngressRunId: lease.IngressRunID, IngressLeaseRevision: int64(lease.IngressLeaseRevision), LeaseExpiresAt: lease.LeaseExpiresAt}
		}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ingress.New(listener, ingress.Config{MaxConnections: 20, PublicServices: connector,
		RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		_ = connector.Close()
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Drain(stop); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
		target.workers.Wait()
	})
	valid, accepted := net.Pipe()
	defer valid.Close()
	forwarded := make(chan error, 1)
	go func() {
		defer accepted.Close()
		forwarded <- connector.AcceptPublic(ctx, accepted, netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("203.0.113.1:443"), prepared.Hostname)
	}()
	secureDirect := tls.Client(valid, clientTLS.Clone())
	defer secureDirect.Close()
	_ = secureDirect.SetDeadline(time.Now().Add(5 * time.Second))
	const secretPayload = "private-query-target-and-command-never-audit"
	if _, err = fmt.Fprintf(secureDirect, "POST /never-audit-path HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", prepared.Hostname, len(secretPayload), secretPayload); err != nil {
		select {
		case forwarding := <-forwarded:
			t.Fatalf("direct request write failed: %v; forwarding: %v", err, forwarding)
		case <-ctx.Done():
			t.Fatal("direct request write failed", err)
		}
	}
	directResponse, err := http.ReadResponse(bufio.NewReader(secureDirect), nil)
	if err != nil {
		t.Fatal("direct service stream did not carry a response", err)
	}
	reply, err := io.ReadAll(directResponse.Body)
	_ = directResponse.Body.Close()
	if err != nil || directResponse.StatusCode != http.StatusOK || string(reply) != secretPayload {
		t.Fatal("direct service stream changed application bytes", err)
	}
	var opened serviceaudit.Observation
	select {
	case opened = <-sink.events:
	case <-ctx.Done():
		t.Fatal("direct transport was not promoted", ctx.Err())
	}
	if opened.Outcome != "allowed" || opened.RunID != run.RunID {
		t.Fatal("direct admission lost its run")
	}
	_ = valid.Close()
	select {
	case <-forwarded:
	case <-ctx.Done():
		t.Fatal("direct producer did not join")
	}
	visitor, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("127.0.0.1:40001"), Destination: netip.MustParseAddrPort("203.0.113.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = visitor.Write(metadata); err != nil {
		_ = visitor.Close()
		t.Fatal(err)
	}
	publicTLS := clientTLS.Clone()
	secure := tls.Client(visitor, publicTLS)
	defer secure.Close()
	_ = secure.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = fmt.Fprintf(secure, "GET /never-audit-path?secret=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", secretPayload, prepared.Hostname); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), nil)
	if err != nil {
		t.Fatal("public stream did not carry a response", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = secure.Close()
	if response.StatusCode != 200 {
		t.Fatal("public visitor failed", response.StatusCode)
	}
	events := []serviceaudit.Observation{opened}
	for range 3 {
		select {
		case o := <-sink.events:
			events = append(events, o)
		case <-ctx.Done():
			t.Fatal("real producers did not emit all open/close/denial events", ctx.Err())
		}
	}
	if n, _ := queue.Pending(); n != 5 {
		t.Fatalf("events did not share one batch: %d", n)
	}
	if err = queue.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if dropped != 1 || rejected != 1 || !retried {
		t.Fatalf("wrong isolation/retry counts: dropped=%d rejected=%d retried=%t", dropped, rejected, retried)
	}
	serviceEvents := 0
	for _, o := range events {
		var e serviceaudit.Event
		var raw []byte
		if err = inspect.QueryRow(ctx, `SELECT to_jsonb(e) || jsonb_build_object('cursor',e.cursor::text,'source_ip',host(e.source_ip)) FROM control.service_audit_events e WHERE id=$1`, o.EventID).Scan(&raw); err != nil {
			t.Fatal("valid event lost beside rejected event", err)
		}
		if err = json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		if e.TeamID != service.TeamID || e.SourceIP != "127.0.0.1" {
			t.Fatalf("incorrect durable team/source: %+v", e)
		}
		serviceEvents++
		if e.ServiceKind != "service" || e.ServiceID != service.ID || e.RunID != run.RunID || e.PublisherIdentityID != publisher.ID || e.ActorIdentityID != "" || e.DeviceID != "" {
			t.Fatal("admitted stream lost its verified service binding")
		}
		for _, secret := range []string{secretPayload, "never-audit-path", fixture.enrollmentKey, run.Token} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("audit retained credentials or application bytes")
			}
		}
	}
	var invalid int
	if err = inspect.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events WHERE id=$1 OR run_id=$2`, bad.EventID, badRun).Scan(&invalid); err != nil || invalid != 0 || serviceEvents != 4 {
		t.Fatalf("invalid scope persisted or valid events missing: invalid=%d service=%d %v", invalid, serviceEvents, err)
	}
}

func auditCompositionTLS(t *testing.T, hosts ...string) (*tls.Config, *tls.Config) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: hosts, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, &tls.Config{RootCAs: roots}
}
