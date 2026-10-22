package controlapi

import (
	"bufio"
	"bytes"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	ingressapi "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/ingress"
	routebackend "github.com/tnldotdev/tnl/internal/ingress/backend"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
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

// only the target transport is local to this fixture. session proof, stream
// admission, public/private producers, queue and audit HTTP all use production
// code against the same database and exact ingress lease.
type auditCompositionTarget struct {
	tls     *tls.Config
	workers sync.WaitGroup
}

func (f *auditCompositionTarget) Open(context.Context, string) (net.Conn, error) {
	return f.open(true), nil
}

func (f *auditCompositionTarget) OpenPrivate(context.Context, ingressv1.PrivateServiceRelay, tunnelv1.PrivateForwardingHeader) (net.Conn, error) {
	return f.open(false), nil
}

func (f *auditCompositionTarget) open(public bool) net.Conn {
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
		if !public {
			_, _ = io.Copy(back, reader)
			return
		}
		secure := tls.Server(&auditReaderConn{Conn: back, reader: reader}, f.tls)
		defer secure.Close()
		if err = secure.Handshake(); err != nil {
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(secure))
		if err == nil {
			_ = request.Body.Close()
			_, _ = io.WriteString(secure, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		}
	}()
	return front
}

type auditReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *auditReaderConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func exerciseServiceAuditQueueComposition(t *testing.T, d *controlstate.Database, inspect *pgxpool.Pool, lease controlstate.IngressLease,
	actor, team, member, publicID, publicRun, publicHostname string, report serviceaudit.Reporter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()
	service, err := d.CreatePrivateService(ctx, team, actor, "audit-composition", "audit-composition", now)
	if err != nil {
		t.Fatal(err)
	}
	var policy int64
	if err = inspect.QueryRow(ctx, `SELECT policy_revision FROM control.teams WHERE id=$1`, team).Scan(&policy); err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{Scope: controlstate.PublisherScope{TeamID: team, Kind: "private_service", PrivateServiceID: service.ID},
		Name: "audit-composition", Kind: "installed", EditorID: actor, EditorMembershipID: member, PolicyRevision: uint64(policy), Now: now})
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
	relays := map[string]controlstate.RelayLease{}
	for _, name := range []string{"audit-a", "audit-b"} {
		process, _ := opaqueid.New(opaqueid.RelayRunPrefix)
		r, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: name, RelayID: name, RelayRunID: process, ProtocolVersion: 1,
			RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test", InternalRelayAddress: "127.0.0.1:8443", ConnectionCapacity: 20, StreamCapacity: 20}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		relays[name] = r
	}
	prepared, err := d.PreparePrivateServiceRun(ctx, service.ID, publisher, "audit-composition", now)
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartManagedServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	managedcert.Install(t, d, prepared, run, now)
	for _, slot := range run.Connections {
		r := relays[slot.RelayServiceID]
		if _, err = d.ClaimPrivatePublisherConnection(ctx, slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, r.RelayLeaseIdentity, now); err != nil {
			t.Fatal(err)
		}
		if _, err = d.ReadyPrivatePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, r.RelayLeaseIdentity, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = d.HeartbeatPrivateServiceRun(ctx, service.ID, run.RunID, run.Token, now, controlstate.PrivateRunHealth{Healthy: true, StreamCapacity: 20}); err != nil {
		t.Fatal(err)
	}
	public, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	device, err := d.EnrollVisitorDevice(ctx, actor, public, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RegisterIngress(ctx, controlstate.IngressRegistration{IngressID: "audit-second", IngressRunID: "audit-second-process", ProtocolVersion: 1, ConnectionCapacity: 10,
		PrivateConnectorAddress: "127.0.0.1:9442", PrivateConnectorTLSServerName: "private.example.test"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	assignments, err := d.CreateVisitorIngressAssignments(ctx, actor, device.ID, service.ID, "startup", now)
	if err != nil {
		t.Fatal(err)
	}
	var assignment controlstate.PrivateConnectorSession
	for _, a := range assignments {
		if a.IngressID == lease.IngressID {
			assignment = a
		}
	}
	if assignment.ID == "" {
		t.Fatal("missing assigned ingress")
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
	badRun, _ := opaqueid.New(opaqueid.PrivateRunPrefix)
	bad := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: service.ID, ServiceKind: "private_service", RunID: badRun, RunNumber: 1,
		ConnectorSessionID: assignment.ID, VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", SourceIP: "127.0.0.1", EventType: "connection.open", OccurredAt: now, Outcome: "denied", Reason: "authorization"}
	if !queue.Observe(bad) {
		t.Fatal("regression event must pass syntax to exercise control scope rejection")
	}
	serverTLS, clientTLS := auditCompositionTLS(t, "private.example.test", publicHostname)
	target := &auditCompositionTarget{tls: serverTLS}
	direct, err := ingressapi.NewDirectClient(ingressapi.DirectConfig{Store: d, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	connector, err := ingress.NewPrivateConnector(ingress.PrivateConnectorConfig{Hostname: "private.example.test", TLSConfig: serverTLS, Control: direct, Forwarder: target,
		Routing: &ingress.PrivateRoutingTable{}, AuditSink: sink, CurrentLease: func() ingressv1.IngressLease {
			return ingressv1.IngressLease{IngressId: lease.IngressID, IngressRunId: lease.IngressRunID, IngressLeaseRevision: int64(lease.IngressLeaseRevision), LeaseExpiresAt: lease.LeaseExpiresAt}
		}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ingress.New(listener, ingress.Config{MaxConnections: 20, PrivateHostname: "private.example.test", PrivateConnector: connector, AuditSink: sink,
		Lookup: func(host string) (ingress.PublicURL, ingress.LookupReason) {
			if host != publicHostname {
				return ingress.PublicURL{}, ingress.LookupNotFound
			}
			return ingress.PublicURL{ID: publicID, PublishRunID: publicRun, PublishRunNumber: 1, AllowAll: true, AccessMode: "anonymous", Backends: []routebackend.Backend{target}}, ingress.LookupCurrent
		}})
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
	transport, err := (muxsession.PrivateMuxTLSConnector{TLSConfig: clientTLS}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "private.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	hello := tunnelv1.PrivateConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "private_connector_session", PrivateServiceID: service.ID, SessionID: assignment.ID,
		Credential: assignment.Credential, Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: actor, DeviceID: device.ID}, Nonce: bytes.Repeat([]byte{3}, 32)}
	proof, err := hello.Claim().Digest()
	if err != nil {
		t.Fatal(err)
	}
	hello.Signature = ed25519.Sign(deviceKey, proof)
	session, err := tunnel.DialPrivateConnector(ctx, transport, hello)
	if err != nil {
		_ = transport.Close()
		t.Fatal(err)
	}
	defer session.Close()
	entry := tunnelv1.PrivateVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PrivateVisitorStream, PrivateServiceID: service.ID, PrivateRunID: badRun, RunNumber: 1}
	denied, err := session.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = denied.SetDeadline(time.Now().Add(5 * time.Second))
	if err = tunnelv1.WritePrivateVisitorEntry(denied, entry); err != nil {
		t.Fatal(err)
	}
	if _, err = tunnelv1.ReadPrivateVisitorAccepted(denied); err == nil {
		t.Fatal("nonexistent run was admitted")
	}
	_ = denied.Close()
	entry.PrivateRunID, entry.RunNumber = run.RunID, uint64(run.RunNumber)
	valid, err := session.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = valid.SetDeadline(time.Now().Add(5 * time.Second))
	if err = tunnelv1.WritePrivateVisitorEntry(valid, entry); err != nil {
		t.Fatal(err)
	}
	if _, err = tunnelv1.ReadPrivateVisitorAccepted(valid); err != nil {
		t.Fatal("valid private stream denied", err)
	}
	const secretPayload = "private-query-target-and-command-never-audit"
	if _, err = io.WriteString(valid, secretPayload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(secretPayload))
	if _, err = io.ReadFull(valid, reply); err != nil || string(reply) != secretPayload {
		t.Fatal("private stream did not carry bytes", err)
	}
	_ = valid.Reset(0)
	_ = valid.Close()
	visitor, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	publicTLS := clientTLS.Clone()
	publicTLS.ServerName = publicHostname
	secure := tls.Client(visitor, publicTLS)
	defer secure.Close()
	_ = secure.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = fmt.Fprintf(secure, "GET /never-audit-path?secret=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", secretPayload, publicHostname); err != nil {
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
	events := make([]serviceaudit.Observation, 0, 5)
	for range 5 {
		select {
		case o := <-sink.events:
			events = append(events, o)
		case <-ctx.Done():
			t.Fatal("real producers did not emit all open/close/denial events", ctx.Err())
		}
	}
	if n, _ := queue.Pending(); n != 6 {
		t.Fatalf("events did not share one batch: %d", n)
	}
	if err = queue.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if dropped != 1 || rejected != 1 || !retried {
		t.Fatalf("wrong isolation/retry counts: dropped=%d rejected=%d retried=%t", dropped, rejected, retried)
	}
	denials, publicEvents, privateEvents := 0, 0, 0
	for _, o := range events {
		var e serviceaudit.Event
		var raw []byte
		if err = inspect.QueryRow(ctx, `SELECT to_jsonb(e) || jsonb_build_object('cursor',e.cursor::text,'source_ip',host(e.source_ip)) FROM control.service_audit_events e WHERE id=$1`, o.EventID).Scan(&raw); err != nil {
			t.Fatal("valid event lost beside rejected event", err)
		}
		if err = json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		if e.TeamID != team || e.SourceIP != "127.0.0.1" {
			t.Fatalf("incorrect durable team/source: %+v", e)
		}
		if o.ServiceKind == "public_url" {
			publicEvents++
		} else if o.RunID == "" {
			denials++
			if e.RunID != "" || e.PublisherIdentityID != "" || e.ActorIdentityID != actor || e.DeviceID != device.ID || o.ServiceID != service.ID {
				t.Fatal("unverified entry supplied durable run/identity scope")
			}
		} else {
			privateEvents++
			if e.RunID != run.RunID || e.PublisherIdentityID != publisher.ID || e.ActorIdentityID != actor || e.DeviceID != device.ID {
				t.Fatal("admitted stream lost its verified binding")
			}
		}
		for _, secret := range []string{secretPayload, "never-audit-path", assignment.Credential, enrollment.Key, run.Token} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("audit retained credentials or application bytes")
			}
		}
	}
	var invalid int
	if err = inspect.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events WHERE id=$1 OR run_id=$2`, bad.EventID, badRun).Scan(&invalid); err != nil || invalid != 0 || denials != 1 || publicEvents != 2 || privateEvents != 2 {
		t.Fatalf("invalid scope persisted or valid events missing: invalid=%d denial=%d public=%d private=%d %v", invalid, denials, publicEvents, privateEvents, err)
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
