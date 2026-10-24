package public

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	controlingress "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/ingress"
	ingressbackend "github.com/tnldotdev/tnl/internal/ingress/backend"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
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

func (f *auditCompositionTarget) OpenPrivate(context.Context, ingressv1.ServiceRelay, tunnelv1.ServiceForwardingHeader, *tunnel.ReturnEvents) (net.Conn, error) {
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
			_, initial, err := tunnelv1.ReadConnectorVisitorOpening(reader)
			if err != nil {
				return
			}
			native := tunnel.NewNativeRequestReader(&auditReaderConn{Conn: back, reader: reader}, initial, func(tunnelv1.NativeVisitorPermission) error { return nil })
			_, _ = io.Copy(back, native)
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
	service, err := d.CreateServiceAt(ctx, team, actor, "audit-composition", "audit-composition", controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	var policy int64
	if err = inspect.QueryRow(ctx, `SELECT policy_revision FROM control.teams WHERE id=$1`, team).Scan(&policy); err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{Scope: controlstate.PublisherScope{TeamID: team, Kind: "service", ServiceID: service.ID},
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
		r, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: name, RelayID: name, RelayRunID: process, ProtocolVersion: tunnelv1.Version,
			RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test", InternalRelayAddress: "127.0.0.1:8443", ConnectionCapacity: 20, StreamCapacity: 20}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		relays[name] = r
	}
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "audit-composition", now, controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
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
	public, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	device, err := d.EnrollVisitorDevice(ctx, actor, public, now)
	if err != nil {
		t.Fatal(err)
	}
	secondProcess, err := opaqueid.New(opaqueid.IngressRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RegisterIngress(ctx, controlstate.IngressRegistration{IngressID: "audit-second", IngressRunID: secondProcess, IngressPoolID: controlstate.PrimaryIngressPoolID, ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 10,
		ConnectorAddress: "127.0.0.1:9442", ConnectorTLSServerName: "private.example.test"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	assignments, err := d.CreateVisitorIngressAssignments(ctx, actor, device.ID, service.ID, "startup", now)
	if err != nil {
		t.Fatal(err)
	}
	var assignment controlstate.ConnectorSession
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
	badRun, _ := opaqueid.New(opaqueid.ServiceRunPrefix)
	bad := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: service.ID, ServiceKind: "service", RunID: badRun, RunNumber: 1,
		ConnectorSessionID: assignment.ID, VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", SourceIP: "127.0.0.1", EventType: "connection.open", OccurredAt: now, Outcome: "denied", Reason: "authorization"}
	if !queue.Observe(bad) {
		t.Fatal("regression event must pass syntax to exercise control scope rejection")
	}
	serverTLS, clientTLS := auditCompositionTLS(t, "private.example.test", publicHostname)
	target := &auditCompositionTarget{tls: serverTLS}
	direct, err := controlingress.NewDirectClient(controlingress.DirectConfig{Store: d, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	const visitorIssuer = "https://control.example.test"
	if err := d.PrepareVisitorSigningKeys(ctx, visitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	connector, err := ingress.NewConnector(ingress.ConnectorConfig{Report: func(err error) { t.Logf("private preparation: %v", err) }, Hostname: "private.example.test", TLSConfig: serverTLS, Control: direct, VisitorControl: direct, Forwarder: target,
		Routing: &ingress.ServiceRoutingTable{}, AuditSink: sink, CurrentLease: func() ingressv1.IngressLease {
			return ingressv1.IngressLease{IngressId: lease.IngressID, IngressRunId: lease.IngressRunID, IngressLeaseRevision: int64(lease.IngressLeaseRevision), LeaseExpiresAt: lease.LeaseExpiresAt}
		}})
	if err != nil {
		t.Fatal(err)
	}
	preparationCtx, stopPreparation := context.WithCancel(ctx)
	preparedDone := make(chan error, 1)
	go func() { preparedDone <- connector.Run(preparationCtx) }()
	defer func() {
		stopPreparation()
		if err := <-preparedDone; err != nil {
			t.Error(err)
		}
	}()
	publisherPolicyDone := make(chan struct{})
	go func() {
		defer close(publisherPolicyDone)
		var observed []string
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			policy, err := d.ReadPublisherVisitorPolicy(preparationCtx, visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}, run.RunID, run.RunNumber, run.Token, 0, observed, time.Now())
			if err == nil {
				observed = nil
				for _, allocation := range policy.Policy.StreamAllocations {
					if allocation.RunId == run.RunID {
						observed = append(observed, allocation.Id)
					}
				}
			}
			select {
			case <-preparationCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { stopPreparation(); <-publisherPolicyDone }()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ingress.New(listener, ingress.Config{MaxConnections: 20, PrivateHostname: "private.example.test", Connector: connector, AuditSink: sink,
		Lookup: func(host string) (ingress.PublicURL, ingress.LookupReason) {
			if host != publicHostname {
				return ingress.PublicURL{}, ingress.LookupNotFound
			}
			return ingress.PublicURL{ID: publicID, PublishRunID: publicRun, PublishRunNumber: 1, AllowAll: true, AccessMode: "anonymous", Backends: []ingressbackend.Backend{target}}, ingress.LookupCurrent
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
	transport, err := (muxsession.ConnectorMuxTLS{TLSConfig: clientTLS}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "private.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	hello := tunnelv1.ConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "connector_session", ServiceID: service.ID, SessionID: assignment.ID,
		Credential: assignment.Credential, Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: actor, DeviceID: device.ID}, Nonce: bytes.Repeat([]byte{3}, 32)}
	proof, err := hello.Claim().Digest()
	if err != nil {
		t.Fatal(err)
	}
	hello.Signature = ed25519.Sign(deviceKey, proof)
	session, err := tunnel.DialConnector(ctx, transport, hello)
	if err != nil {
		_ = transport.Close()
		t.Fatal(err)
	}
	defer session.Close()
	var parentSession string
	if err := inspect.QueryRow(ctx, `SELECT id FROM control.control_sessions WHERE identity_id=$1 AND revoked_at IS NULL LIMIT 1`, actor).Scan(&parentSession); err != nil {
		t.Fatal(err)
	}
	issued, err := d.IssueVisitorToken(controlstate.WithControlPrincipal(ctx, controlstate.ControlPrincipal{IdentityID: actor, SessionID: parentSession}), visitorIssuer, visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}, controlstate.DeviceTokenSource{DeviceID: device.ID}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	visitorID, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	message, err := visitortoken.NativeProofMessage(issued.Token, assignment.ID, visitorID, uint64(service.TrustRevision), nil)
	if err != nil {
		t.Fatal(err)
	}
	entry := tunnelv1.ConnectorVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorVisitorStream, ServiceID: service.ID, ServiceRunID: badRun, RunNumber: 1, VisitorConnectionID: visitorID, MetadataRevision: uint64(service.TrustRevision), Permission: tunnelv1.NativeVisitorPermission{Token: issued.Token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(public), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(deviceKey, message))}}
	denied, err := session.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = denied.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = tunnelv1.WriteConnectorVisitorOpening(denied, entry, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = denied.Read(make([]byte, 1)); err == nil {
		t.Fatal("nonexistent run was admitted")
	}
	_ = denied.Close()
	entry.ServiceRunID, entry.RunNumber = run.RunID, uint64(run.RunNumber)
	entry.VisitorConnectionID, err = opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	message, err = visitortoken.NativeProofMessage(issued.Token, assignment.ID, entry.VisitorConnectionID, entry.MetadataRevision, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(deviceKey, message))
	valid, err := session.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = valid.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = tunnelv1.WriteConnectorVisitorOpening(valid, entry, nil); err != nil {
		t.Fatal(err)
	}
	const secretPayload = "private-query-target-and-command-never-audit"
	if _, err = io.WriteString(tunnel.NewNativeRequestWriter(valid), secretPayload); err != nil {
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
