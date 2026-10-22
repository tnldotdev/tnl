package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	controlrelay "github.com/tnldotdev/tnl/internal/control/api/private/relay"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// each dial traverses the real relay acceptor and its claim/readiness/cleanup
// path. a failed HTTP claim must not require restarting the relay process.
func dialPrivateClaim(t *testing.T, acceptor *PublisherAcceptor, hello tunnelv1.Message) (*tunnel.Session, <-chan error, error) {
	t.Helper()
	certificate := httptest.NewTLSServer(nil)
	t.Cleanup(certificate.Close)
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	done := relayWorker(t, cancel, func() error {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()
		transport, err := muxsession.AcceptTLSYamux(ctx, conn, certificate.TLS, muxsession.TLSYamuxConfig{})
		if err != nil {
			return err
		}
		return acceptor.Accept(ctx, transport)
	})
	transport, err := (muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{RootCAs: roots}}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := tunnel.Dial(ctx, transport, hello)
	if session != nil {
		t.Cleanup(func() { _ = session.Close() })
	}
	return session, done, err
}

func TestIntegrationPrivateClaimCommittedResponseLoss(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx, now := t.Context(), time.Now().UTC()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "private-claim-loss")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	inspect, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inspect.Close(context.Background()) })
	owner, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	member := owner.Identity.Memberships[0]
	service, err := d.CreateServiceAt(ctx, member.TeamID, owner.Identity.Identity.ID, "claims", "claims", controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{Scope: controlstate.PublisherScope{TeamID: member.TeamID, Kind: "service", ServiceID: service.ID},
		Name: "claims", Kind: "installed", EditorID: owner.Identity.Identity.ID, EditorMembershipID: member.ID, PolicyRevision: uint64(member.PolicyRevision), Now: now})
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
	leases := map[string]controlstate.RelayLease{}
	for _, id := range []string{"relay-a", "relay-b"} {
		runID, err := opaqueid.New(opaqueid.RelayRunPrefix)
		if err != nil {
			t.Fatal(err)
		}
		lease, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayID: id, RelayServiceID: id, RelayRunID: runID, RelayAddress: id + ".example.test:443", TLSServerName: id + ".example.test",
			InternalRelayAddress: "127.0.0.1:9443", ProtocolVersion: 1, ConnectionCapacity: 1, StreamCapacity: 8}, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		leases[id] = lease
	}
	prep, err := d.PrepareServiceRun(ctx, service.ID, publisher, "claims", now, controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prep.RunID, prep.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	managedcert.Install(t, d, prep, run, now)
	if _, err = d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 8}); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("s", 32)
	secrets, err := serviceapi.NewBearerSecrets(secret, "")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := controlrelay.NewHandler(controlrelay.Config{Store: d, ClusterSecrets: secrets, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	attempts := map[string][][]byte{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/claim") {
			handler.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		mu.Lock()
		attempts[r.URL.Path] = append(attempts[r.URL.Path], body)
		attempt := len(attempts[r.URL.Path])
		mu.Unlock()
		committed := httptest.NewRecorder()
		handler.ServeHTTP(committed, r)
		if attempt <= 2 && committed.Code == http.StatusOK {
			// the database transaction committed, but the relay receives EOF.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		for key, values := range committed.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(committed.Code)
		_, _ = w.Write(committed.Body.Bytes())
	}))
	t.Cleanup(server.Close)
	generated, err := relayv1.NewClientWithResponses(server.URL, relayv1.WithHTTPClient(server.Client()), relayv1.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+secret)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewHTTPControlClient(generated)
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range run.Connections {
		lease := leases[slot.RelayServiceID]
		// a live sibling process in the assigned service still cannot adopt a
		// claim committed to this process, even while it is only connected.
		otherRun, err := opaqueid.New(opaqueid.RelayRunPrefix)
		if err != nil {
			t.Fatal(err)
		}
		other, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: lease.RelayServiceID, RelayID: lease.RelayID + "-other", RelayRunID: otherRun,
			RelayAddress: lease.RelayAddress, TLSServerName: lease.TLSServerName, InternalRelayAddress: "127.0.0.1:9449", ProtocolVersion: 1, ConnectionCapacity: 1, StreamCapacity: 8}, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		wrongCredential, _, err := credentials.NewPublisherConnectionCredential()
		if err != nil {
			t.Fatal(err)
		}
		assertOwner := func(expectedState string) {
			t.Helper()
			for _, bad := range []struct {
				lease      controlstate.RelayLeaseIdentity
				credential string
				revision   int64
			}{
				{other.RelayLeaseIdentity, slot.Credential, slot.Revision},
				{leases[run.Connections[1-int(slot.ConnectionSlot)].RelayServiceID].RelayLeaseIdentity, slot.Credential, slot.Revision},
				{controlstate.RelayLeaseIdentity{RelayID: lease.RelayID, RelayRunID: "old-process", RelayLeaseRevision: lease.RelayLeaseRevision}, slot.Credential, slot.Revision},
				{lease.RelayLeaseIdentity, wrongCredential.String(), slot.Revision},
				{lease.RelayLeaseIdentity, slot.Credential, slot.Revision + 1},
			} {
				if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, bad.revision, bad.credential, bad.lease, now); err == nil {
					t.Fatal("different relay/process/credential/revision stole existing connection")
				}
			}
			var state, owner, ownerRun string
			var revision int64
			if err := inspect.QueryRow(ctx, `SELECT state,relay_id,relay_run_id,relay_lease_revision FROM control.service_connection_slots WHERE publisher_connection_id=$1`, slot.PublisherConnectionID).Scan(&state, &owner, &ownerRun, &revision); err != nil ||
				state != expectedState || owner != lease.RelayID || ownerRun != lease.RelayRunID || revision != int64(lease.RelayLeaseRevision) {
				t.Fatalf("exact owner changed: %s %s %s %d %v", state, owner, ownerRun, revision, err)
			}
		}
		controller := &Controller{client: client, now: time.Now, lease: relayv1.RelayLease{RelayServiceId: lease.RelayServiceID, RelayId: lease.RelayID, RelayRunId: lease.RelayRunID,
			RelayLeaseRevision: int64(lease.RelayLeaseRevision), LeaseExpiresAt: lease.LeaseExpiresAt, ConnectionCapacity: 1}}
		registry := NewServiceRegistry()
		acceptor, err := NewPublisherAcceptor(PublisherAcceptorConfig{Control: controller, Registry: NewRegistry(), Private: &ServicePublisherAcceptor{Select: func(string) (ServicePublisherTarget, bool) {
			return ServicePublisherTarget{Control: controller, Registry: registry}, true
		}}})
		if err != nil {
			t.Fatal(err)
		}
		ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: service.ID, ServiceRunID: run.RunID, RunNumber: uint64(run.RunNumber), PublisherConnectionID: slot.PublisherConnectionID,
			ConnectionSlot: uint8(slot.ConnectionSlot), ConnectionAssignmentRevision: uint64(slot.Revision), RelayServiceID: slot.RelayServiceID}
		hello := tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: 1, Role: tunnelv1.Publisher, Credential: slot.Credential, ServiceConnection: &ref}
		for attempt := range 2 {
			if _, done, err := dialPrivateClaim(t, acceptor, hello); err == nil {
				t.Fatal("committed claim response was not lost")
			} else {
				_ = relayAwait(t, done)
			}
			var state, owner string
			if err := inspect.QueryRow(ctx, `SELECT state,relay_id FROM control.service_connection_slots WHERE publisher_connection_id=$1`, slot.PublisherConnectionID).Scan(&state, &owner); err != nil || state != "connected" || owner != lease.RelayID {
				t.Fatalf("loss %d did not retain exact committed claim: %s %s %v", attempt, state, owner, err)
			}
			assertOwner("connected")
			if _, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now); err != nil {
				t.Fatal(err)
			}
		}
		session, _, err := dialPrivateClaim(t, acceptor, hello)
		if err != nil {
			t.Fatalf("exact committed claim could not recover through relay: %v", err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			var state string
			if err := inspect.QueryRow(ctx, `SELECT state FROM control.service_connection_slots WHERE publisher_connection_id=$1`, slot.PublisherConnectionID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state == "ready" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("recovered relay never became ready")
			}
			time.Sleep(time.Millisecond)
		}
		if _, done, err := dialPrivateClaim(t, acceptor, hello); err == nil {
			t.Fatal("duplicate relay handshake stole the owner")
		} else {
			_ = relayAwait(t, done)
		}
		assertOwner("ready")
		if count, _ := registry.Load(); count != 1 {
			t.Fatal("duplicate changed local ownership")
		}
		select {
		case <-session.Done():
			t.Fatal("duplicate or stale claimant closed the owner's tunnel")
		default:
		}
	}
	var state string
	if err := inspect.QueryRow(ctx, `SELECT state FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&state); err != nil || state != "ready" {
		t.Fatalf("initial two-slot startup did not reach ready: %s %v", state, err)
	}
	var ready int
	if err := inspect.QueryRow(ctx, `SELECT count(*) FROM control.service_connection_slots WHERE service_run_id=$1 AND state='ready' AND session_open`, run.RunID).Scan(&ready); err != nil || ready != 2 {
		t.Fatalf("startup did not retain two independent ready owners: %d %v", ready, err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, bodies := range attempts {
		if len(bodies) != 3 || !bytes.Equal(bodies[0], bodies[1]) || !bytes.Equal(bodies[0], bodies[2]) {
			t.Fatal("recovery changed the exact claim or duplicate reached control")
		}
	}
}
