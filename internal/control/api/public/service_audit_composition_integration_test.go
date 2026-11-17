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
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	controlingress "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type auditCompositionSink struct {
	queue  *serviceaudit.Queue
	events chan serviceaudit.Observation
}

func (s auditCompositionSink) Observe(o serviceaudit.Observation) bool {
	if !s.queue.Observe(o) {
		return false
	}
	s.events <- o
	return true
}

// relay transport and the application are local to this fixture. routing,
// HTTP access, capacity callbacks, request producers, queue and audit HTTP use
// production code against the same database and exact ingress lease. connection
// lifecycle producers are exercised with the run owner in daemon runtime tests.
type auditCompositionTarget struct {
	tls         *tls.Config
	ctx         context.Context
	frontend    publisherservice.HTTP
	application http.Handler
	workers     sync.WaitGroup
}

func (f *auditCompositionTarget) OpenService(_ context.Context, _ ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, reserveCapacity func(context.Context) error) (net.Conn, error) {
	return f.open(header, reserveCapacity), nil
}

func (f *auditCompositionTarget) open(header tunnelv1.ServiceForwardingHeader, reserveCapacity func(context.Context) error) net.Conn {
	front, back := net.Pipe()
	f.workers.Add(1)
	go func() {
		defer f.workers.Done()
		defer back.Close()
		_ = back.SetDeadline(time.Now().Add(10 * time.Second))
		metadata, reader, err := proxyproto.Decode(back)
		if err != nil {
			return
		}
		secure := tls.Server(&auditReaderConn{Conn: back, reader: reader}, f.tls)
		defer secure.Close()
		if err = secure.Handshake(); err != nil {
			return
		}
		frontend := f.frontend
		frontend.Header = header
		frontend.Source = metadata.Source
		frontend.ReserveCapacity = reserveCapacity
		_ = frontend.Forward(f.ctx, secure, servicestream.HTTPTarget{Handler: f.application})
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
	service, err := d.CreateServiceAt(ctx, team, actor, name, name, controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "http"},
		&controlstate.ProjectServiceConfiguration{Target: "http://127.0.0.1:3000", Public: new(true)})
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
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, name, now, controlstate.ServiceRunRequest{Metadata: controlstate.ServiceMetadata{Protocol: "http", TrustRevision: 1}})
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
		if _, err = d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), r.RelayLeaseIdentity, now); err != nil {
			t.Fatal(err)
		}
		if _, err = d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, r.RelayLeaseIdentity, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 20}); err != nil {
		t.Fatal(err)
	}
	return auditCompositionRun{service: service, prepared: prepared, run: run, publisher: publisher, enrollmentKey: enrollment.Key}
}

func exerciseServiceAuditQueueComposition(t *testing.T, d *controlstate.Database, inspect *pgxpool.Pool, lease controlstate.IngressLease,
	fixture auditCompositionRun, control publisherservice.HTTPControl, permission string, report serviceaudit.Reporter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()
	service, prepared, run, publisher := fixture.service, fixture.prepared, fixture.run, fixture.publisher
	// ingress routing grants no application access. only the exact publisher
	// run may report an allowed HTTP connection, with no control visitor row.
	pendingID, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.ReadIngressServices(ctx, lease.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Runs) == 0 {
		t.Fatal(err)
	}
	unpromoted := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: service.ID, ServiceKind: "service", RunID: run.RunID, RunNumber: run.RunNumber,
		VisitorConnectionID: pendingID, SourceIP: "127.0.0.1", EventType: "connection.open", OccurredAt: now, Outcome: "allowed"}
	if _, err := d.IngestIngressServiceObservations(ctx, lease.IngressLeaseIdentity, serviceaudit.Batch{Events: []serviceaudit.Observation{unpromoted}}, now); !errors.Is(err, controlstate.ErrServiceAuditAccess) {
		t.Fatal("unpromoted HTTP transport reported allowed access", err)
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
	sink := auditCompositionSink{queue: queue, events: make(chan serviceaudit.Observation, 16)}
	badRun, _ := opaqueid.New(opaqueid.ServiceRunPrefix)
	bad := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: service.ID, ServiceKind: "service", RunID: badRun, RunNumber: 1,
		VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", SourceIP: "127.0.0.1", EventType: "connection.open", OccurredAt: now, Outcome: "denied", Reason: "authorization"}
	if !queue.Observe(bad) {
		t.Fatal("regression event must pass syntax to exercise control scope rejection")
	}
	serverTLS, clientTLS := auditCompositionTLS(t, prepared.Hostname)
	clientTLS.ServerName = prepared.Hostname
	frontend, closeHTTP, err := publisherservice.PrepareHTTP(ctx, publisherservice.HTTP{
		Control: control, Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID},
		RunID: run.RunID, Number: run.RunNumber, Token: credentials.ServiceRunToken(run.Token),
		Hostname: prepared.Hostname, Port: 443,
		AuditSink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeHTTP()
	var applications atomic.Int32
	target := &auditCompositionTarget{tls: serverTLS, ctx: ctx, frontend: frontend, application: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applications.Add(1)
		if r.Header.Get(httpaccess.VisitorTokenHeader) != "" {
			t.Error("visitor permission reached the target")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if len(body) == 0 {
			body = []byte("ok")
		}
		_, _ = w.Write(body)
	})}
	direct, err := controlingress.NewDirectClient(controlingress.DirectConfig{Store: d, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ingress.New(listener, ingress.Config{MaxConnections: 20, Control: direct, Forwarder: target,
		AuditSink: sink, CurrentLease: func() ingressv1.IngressLease {
			return ingressv1.IngressLease{IngressId: lease.IngressID, IngressRunId: lease.IngressRunID, IngressLeaseRevision: int64(lease.IngressLeaseRevision), LeaseExpiresAt: lease.LeaseExpiresAt, ServingUntil: lease.ServingUntil}
		},
		RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	routingCtx, stopRouting := context.WithCancel(ctx)
	routingDone := make(chan error, 1)
	go func() { routingDone <- server.RefreshServices(routingCtx) }()
	defer func() {
		stopRouting()
		if err := <-routingDone; err != nil {
			t.Error("join routing observer", err)
		}
	}()
	t.Cleanup(func() {
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
	ready, stopReady := context.WithTimeout(ctx, 3*time.Second)
	tick := time.NewTicker(time.Millisecond)
	for server.RoutingObservedAt().IsZero() && ready.Err() == nil {
		select {
		case <-tick.C:
		case <-ready.Done():
		}
	}
	tick.Stop()
	if ready.Err() != nil {
		stopReady()
		t.Fatal("ingress did not apply prepared routing", ready.Err())
	}
	stopReady()
	valid, accepted := net.Pipe()
	defer valid.Close()
	forwarded := make(chan error, 1)
	go func() {
		defer accepted.Close()
		forwarded <- server.AcceptPublic(ctx, accepted, netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("203.0.113.1:443"), prepared.Hostname, nil)
	}()
	secureDirect := tls.Client(valid, clientTLS.Clone())
	defer secureDirect.Close()
	_ = secureDirect.SetDeadline(time.Now().Add(5 * time.Second))
	const secretPayload = "private-query-target-and-command-never-audit"
	if _, err = fmt.Fprintf(secureDirect, "POST /never-audit-path HTTP/1.1\r\nHost: %s\r\n%s: %s\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", prepared.Hostname, httpaccess.VisitorTokenHeader, permission, len(secretPayload), secretPayload); err != nil {
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
		t.Fatal("direct HTTP request did not emit its access decision", ctx.Err())
	}
	if opened.EventType != "http.decision" || opened.Outcome != "allowed" || opened.RunID != run.RunID {
		t.Fatal("direct HTTP decision lost its exact run")
	}
	_ = valid.Close()
	select {
	case <-forwarded:
	case <-ctx.Done():
		t.Fatal("direct producer did not join")
	}
	// retain both original application requests and add request denials that
	// never reach the target. open/close accounting belongs to the run owner,
	// not an ingress HTTP admission row.
	for _, test := range []struct {
		credential string
		status     int
	}{{permission, http.StatusOK}, {"", http.StatusForbidden}, {"invalid-secret", http.StatusForbidden}} {
		visitor, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("127.0.0.1:40001"), Destination: netip.MustParseAddrPort("203.0.113.1:443")})
		if err != nil {
			_ = visitor.Close()
			t.Fatal(err)
		}
		if _, err = visitor.Write(metadata); err != nil {
			_ = visitor.Close()
			t.Fatal(err)
		}
		secure := tls.Client(visitor, clientTLS.Clone())
		_ = secure.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = fmt.Fprintf(secure, "GET /never-audit-path?secret=%s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\nConnection: close\r\n\r\n", secretPayload, prepared.Hostname, httpaccess.VisitorTokenHeader, test.credential); err != nil {
			_ = secure.Close()
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(secure), nil)
		if err != nil {
			_ = secure.Close()
			t.Fatal("public stream did not carry a response", err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		bodyErr := response.Body.Close()
		_ = secure.Close()
		if readErr != nil || bodyErr != nil || response.StatusCode != test.status {
			t.Fatal("public visitor lost its complete response or access decision", response.StatusCode, readErr, bodyErr)
		}
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
	if applications.Load() != 2 {
		t.Fatal("HTTP audit denials reached the application or lost an original request", applications.Load())
	}
	if err = queue.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if dropped != 1 || rejected != 1 || !retried {
		t.Fatalf("wrong isolation/retry counts: dropped=%d rejected=%d retried=%t", dropped, rejected, retried)
	}
	serviceEvents, allowed, denied := 0, 0, 0
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
		if e.ServiceID != service.ID || e.RunID != run.RunID || e.PublisherIdentityID != publisher.ID || e.ActorIdentityID != "" || e.DeviceID != "" {
			t.Fatalf("admitted stream lost its verified service binding: %+v", e)
		}
		if e.EventType != "http.decision" {
			t.Fatal("request audit invented a connection lifecycle event", e.EventType)
		}
		switch e.Outcome {
		case "allowed":
			allowed++
		case "denied":
			if e.Reason != "authorization" {
				t.Fatal("request denial lost its authorization classification", e.Reason)
			}
			denied++
		default:
			t.Fatal("request audit lost its decision outcome", e.Outcome)
		}
		for _, secret := range []string{secretPayload, "never-audit-path", fixture.enrollmentKey, run.Token, permission} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("audit retained credentials or application bytes")
			}
		}
	}
	var invalid int
	if err = inspect.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events WHERE id=$1 OR run_id=$2`, bad.EventID, badRun).Scan(&invalid); err != nil || invalid != 0 || serviceEvents != 4 || allowed != 2 || denied != 2 {
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
