package privatepublisher

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func privateFixture(t *testing.T, target string) (*Prepared, *Bound, tunnelv1.PrivatePublisherConnectionRef, ed25519.PublicKey) {
	t.Helper()
	id := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	identityKey, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, team := id(opaqueid.PrivateServicePrefix), id(opaqueid.TeamPrefix)
	identity := authorityv1.PublisherEnrollmentResult{ClientId: id(opaqueid.PublisherIdentityPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), TeamId: team, Kind: authorityv1.PrivateService, PrivateServiceId: &service}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	prepared := controlv1.PrivateServiceRunPreparation{TeamId: team, PrivateServiceId: service,
		PrivateRunId: id(opaqueid.PrivateRunPrefix), RunNumber: 7,
		PublisherIdentityId: identity.ClientId, PublisherGrantId: identity.GrantId, PublisherKeyId: identity.KeyId,
		IdempotencyKey: id(opaqueid.IdempotencyPrefix), BindingNonce: hex.EncodeToString(nonce), ExpiresAt: time.Now().Add(2 * time.Minute)}
	p, err := NewPrepared(prepared, identity, signing, target, "")
	if err != nil {
		t.Fatal(err)
	}
	public, err := hex.DecodeString(p.Request.StreamPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := tunnelv1.PrivateRunBindingDigest(tunnelv1.PrivateRunKeyBinding{
		TeamID: team, PrivateServiceID: service, PrivateRunID: prepared.PrivateRunId, RunNumber: 7,
		PublisherIdentityID: identity.ClientId, PublisherGrantID: identity.GrantId, PublisherKeyID: identity.KeyId,
		IdempotencyKey: prepared.IdempotencyKey, BindingNonce: nonce, StreamPublicKey: public,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(p.Request.BindingSignature)
	if err != nil || !ed25519.Verify(identityKey, digest, signature) {
		t.Fatal("run key was not bound to the enrolled identity")
	}
	setup := controlv1.PrivateServiceRunSetup{PrivateServiceId: service, PrivateRunId: prepared.PrivateRunId,
		RunNumber: 7, StreamPublicKey: p.Request.StreamPublicKey, RunToken: "private-token-do-not-log"}
	for slot := range 2 {
		setup.PublisherConnections = append(setup.PublisherConnections, controlv1.ConnectionAssignment{
			PublisherConnectionId: id(opaqueid.PublisherConnectionPrefix), ConnectionSlot: slot,
			ConnectionAssignmentRevision: 3, RelayServiceId: fmt.Sprintf("relay-%d", slot),
			RelayAddress: fmt.Sprintf("relay-%d.example:443", slot), TlsServerName: fmt.Sprintf("relay-%d.example", slot),
			PublisherConnectionCredential: "private-credential-do-not-log", PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute),
		})
	}
	bound, err := p.Bind(setup)
	if err != nil {
		t.Fatal(err)
	}
	return p, bound, bound.assignments[setup.PublisherConnections[0].PublisherConnectionId], public
}

func privateHeader(t *testing.T, ref tunnelv1.PrivatePublisherConnectionRef, ticket string) tunnelv1.PrivateForwardingHeader {
	t.Helper()
	id := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	ticketDigest := sha256.Sum256([]byte(ticket))
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return tunnelv1.PrivateForwardingHeader{PrivateStreamHeader: tunnelv1.PrivateStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PrivateForwardingStream,
		PrivateServiceID: ref.PrivateServiceID, PrivateRunID: ref.PrivateRunID, RunNumber: ref.RunNumber,
		ConnectorSessionID: id(opaqueid.PrivateConnectorSessionPrefix), IdentityID: id(opaqueid.IdentityPrefix),
		SourceIP: "192.0.2.10", VisitorConnectionID: id(opaqueid.VisitorConnectionPrefix),
		PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision,
		TicketDigest: ticketDigest[:], Nonce: nonce, ExpiresAt: time.Now().Add(time.Minute),
	}, ConnectionSlot: ref.ConnectionSlot, RelayServiceID: ref.RelayServiceID, RelayID: "relay-instance",
		RelayRunID: id(opaqueid.RelayRunPrefix), RelayLeaseRevision: 2, LeaseExpiresAt: time.Now().Add(time.Minute)}
}

func TestOpaquePrivateStreamPinsPerRunKeyAndWithholdsAuthUntilProof(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	auth := make(chan string, 1)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		payload := make([]byte, len("mysql-auth"))
		if _, err := io.ReadFull(conn, payload); err == nil {
			var extra [1]byte
			if _, err := conn.Read(extra[:]); errors.Is(err, io.EOF) {
				auth <- string(payload)
				_, _ = conn.Write([]byte("ok"))
			}
		}
	}()
	_, bound, ref, pin := privateFixture(t, target.Addr().String())
	upstream, downstream := net.Pipe()
	defer upstream.Close()
	defer downstream.Close()
	ticket := "one-use-visitor-ticket"
	header := privateHeader(t, ref, ticket)
	done := make(chan error, 1)
	go func() { done <- bound.serveOpaque(t.Context(), ref, downstream) }()
	if err := tunnelv1.WritePrivateForwardingHeader(upstream, header); err != nil {
		t.Fatal(err)
	}
	if response, err := tunnelv1.ReadStreamResponse(upstream); err != nil || response.Type != tunnelv1.StreamAccepted {
		t.Fatalf("private assignment was not acknowledged before PROXY v2: %+v %v", response, err)
	}
	proxy, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:54321"), Destination: netip.MustParseAddrPort("203.0.113.10:443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upstream.Write(proxy); err != nil {
		t.Fatal(err)
	}
	secure := tls.Client(upstream, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].PublicKey.(ed25519.PublicKey), pin) {
			return errors.New("publisher TLS key did not match the per-run pin")
		}
		return nil
	}})
	if err := secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	proof, err := tunnelv1.ReadPrivateStreamProof(secure)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-auth:
		t.Fatal("target received auth before visitor checked proof")
	default:
	}
	entry := tunnelv1.PrivateVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PrivateVisitorStream,
		PrivateServiceID: ref.PrivateServiceID, PrivateRunID: ref.PrivateRunID, RunNumber: ref.RunNumber,
		Ticket: ticket, Nonce: header.Nonce}
	accepted := tunnelv1.PrivateVisitorAccepted{ProtocolVersion: tunnelv1.Version, Kind: "private_visitor_accepted",
		ConnectorSessionID: header.ConnectorSessionID, IdentityID: header.IdentityID,
		SourceIP: header.SourceIP, VisitorConnectionID: header.VisitorConnectionID}
	if !tunnelv1.VerifyPrivateStreamProof(pin, entry, accepted, proof) {
		t.Fatal("stream proof did not cover the claimed ticket and source")
	}
	other := accepted
	other.SourceIP = "192.0.2.11"
	if tunnelv1.VerifyPrivateStreamProof(pin, entry, other, proof) {
		t.Fatal("replayed stream proof authorized a different source")
	}
	if _, err := secure.Write([]byte("mysql-auth")); err != nil {
		t.Fatal(err)
	}
	if err := secure.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(secure, response); err != nil || string(response) != "ok" {
		t.Fatalf("opaque target response: %q %v", response, err)
	}
	select {
	case value := <-auth:
		if value != "mysql-auth" {
			t.Fatalf("target changed auth bytes: %q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("target did not receive opaque auth")
	}
	_ = secure.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("publisher stream did not join")
	}
}

func TestPerRunCertificateRenewsAcrossRepeatedConnectionsWithTheSamePin(t *testing.T) {
	p, bound, ref, pin := privateFixture(t, "127.0.0.1:1")
	var clock atomic.Int64
	start := time.Now().Add(time.Minute)
	clock.Store(start.UnixNano())
	p.clock = func() time.Time {
		if value := clock.Load(); value != 0 {
			return time.Unix(0, value)
		}
		return time.Time{}
	}
	var serials []string
	for _, current := range []time.Time{start, start.Add(23*time.Hour + 45*time.Minute), start.Add(49 * time.Hour)} {
		clock.Store(current.UnixNano())
		if _, _, err := bound.Hello(0); err != nil {
			t.Fatalf("usable run key failed to renew: %v", err)
		}
		client, server := net.Pipe()
		result := make(chan error, 1)
		go func() { result <- bound.serveOpaque(t.Context(), ref, server) }()
		header := privateHeader(t, ref, "one-use-ticket")
		if err := tunnelv1.WritePrivateForwardingHeader(client, header); err != nil {
			t.Fatal(err)
		}
		if answer, err := tunnelv1.ReadStreamResponse(client); err != nil || answer.Type != tunnelv1.StreamAccepted {
			t.Fatalf("renewed private run rejected assignment: %+v %v", answer, err)
		}
		proxy, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:54321"), Destination: netip.MustParseAddrPort("203.0.113.10:443")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(proxy); err != nil {
			t.Fatal(err)
		}
		secure := tls.Client(client, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, Time: p.clock,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].PublicKey.(ed25519.PublicKey), pin) {
					return errors.New("rotated TLS pin")
				}
				leaf := state.PeerCertificates[0]
				if leaf.NotBefore.After(current) || !leaf.NotAfter.After(current.Add(certificateRenewBefore)) {
					return errors.New("expired TLS leaf offered to a new visitor")
				}
				serials = append(serials, leaf.SerialNumber.String())
				return nil
			}})
		if err := secure.Handshake(); err != nil {
			t.Fatal(err)
		}
		if _, err := tunnelv1.ReadPrivateStreamProof(secure); err != nil {
			t.Fatal(err)
		}
		_ = secure.Close()
		select {
		case <-result:
		case <-time.After(3 * time.Second):
			t.Fatal("renewed visitor stream did not join")
		}
	}
	if len(serials) != 3 || serials[0] == serials[1] || serials[1] == serials[2] ||
		p.Request.StreamPublicKey != hex.EncodeToString(pin) {
		t.Fatalf("run binding or TLS pin rotated while renewing leaves: serials=%v", serials)
	}
	clock.Store(0)
	if _, _, err := bound.Hello(1); !errors.Is(err, ErrPrivateStream) {
		t.Fatalf("run admitted a claim without a usable certificate: %v", err)
	}
	state := controlv1.PrivateServiceRunState{PrivateServiceId: p.Preparation.PrivateServiceId,
		PrivateRunId: p.Preparation.PrivateRunId, RunNumber: p.Preparation.RunNumber,
		StreamPublicKey: p.Request.StreamPublicKey, PublisherExpiresAt: time.Now().Add(time.Minute),
		State: "ready", PublisherConnections: []controlv1.ConnectionAssignment{bound.connections[0], bound.connections[1]}}
	if bound.MatchesHeartbeat(state) {
		t.Fatal("run could be marked ready without a usable TLS certificate")
	}
}

func TestPrivateStreamRejectsWrongRunAssignmentAndSourceBeforeTarget(t *testing.T) {
	_, bound, ref, _ := privateFixture(t, "127.0.0.1:1")
	for name, change := range map[string]func(*tunnelv1.PrivateForwardingHeader){
		"old run":             func(h *tunnelv1.PrivateForwardingHeader) { h.RunNumber-- },
		"replaced assignment": func(h *tunnelv1.PrivateForwardingHeader) { h.ConnectionAssignmentRevision++ },
		"wrong relay":         func(h *tunnelv1.PrivateForwardingHeader) { h.RelayServiceID = "other-relay" },
	} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			result := make(chan error, 1)
			go func() { result <- bound.serveOpaque(t.Context(), ref, server) }()
			h := privateHeader(t, ref, "ticket")
			change(&h)
			if err := tunnelv1.WritePrivateForwardingHeader(client, h); err != nil {
				t.Fatal(err)
			}
			if response, err := tunnelv1.ReadStreamResponse(client); err != nil || response.Type != tunnelv1.StreamRejected {
				t.Fatalf("unclaimed relay stream was acknowledged: %+v %v", response, err)
			}
			if err := <-result; !errors.Is(err, ErrPrivateStream) {
				t.Fatalf("invalid forwarding reached target: %v", err)
			}
		})
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	result := make(chan error, 1)
	go func() { result <- bound.serveOpaque(t.Context(), ref, server) }()
	if err := tunnelv1.WritePrivateForwardingHeader(client, privateHeader(t, ref, "ticket")); err != nil {
		t.Fatal(err)
	}
	if response, err := tunnelv1.ReadStreamResponse(client); err != nil || response.Type != tunnelv1.StreamAccepted {
		t.Fatalf("valid assignment rejected: %+v %v", response, err)
	}
	wrongSource, _ := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.11:54321"), Destination: netip.MustParseAddrPort("203.0.113.10:443")})
	if _, err := client.Write(wrongSource); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrPrivateStream) {
		t.Fatalf("untrusted source reached target: %v", err)
	}
}

func TestPrivateBindingRejectsStaleGrantAndUnsupportedTargetModes(t *testing.T) {
	p, bound, ref, _ := privateFixture(t, "127.0.0.1:5432")
	endpoint, hello, err := bound.Hello(0)
	if err != nil || hello.Validate() != nil || hello.PrivateConnection == nil || hello.PublisherConnection != nil ||
		hello.PrivateConnection.PrivateServiceID != p.Preparation.PrivateServiceId ||
		endpoint.Address != "relay-0.example:443" || endpoint.ServerName != "relay-0.example" {
		t.Fatalf("private slot used a public URL or wrong relay: %+v %+v %v", endpoint, hello, err)
	}
	if _, err := p.Bind(controlv1.PrivateServiceRunSetup{PrivateServiceId: p.Preparation.PrivateServiceId}); !errors.Is(err, ErrPrivateStream) {
		t.Fatalf("incomplete setup was accepted: %v", err)
	}
	ref.ConnectionAssignmentRevision++
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if err := bound.serveOpaque(t.Context(), ref, server); !errors.Is(err, ErrPrivateStream) {
		t.Fatalf("replaced claim was accepted: %v", err)
	}
	if _, err := NewPrepared(p.Preparation, authorityv1.PublisherEnrollmentResult{}, nil, "127.0.0.1:5432", "mysql"); !errors.Is(err, ErrUnsupportedTargetTLS) {
		t.Fatalf("target TLS silently fell back to opaque forwarding: %v", err)
	}
	bound.Invalidate()
	if _, _, err := bound.Hello(1); !errors.Is(err, ErrPrivateStream) {
		t.Fatalf("closed run permitted a second relay claim: %v", err)
	}
	if fmt.Sprint(p) != "private publisher preparation" || fmt.Sprintf("%#v", *p) != "private publisher preparation" ||
		fmt.Sprint(bound) != "private publisher run" {
		t.Fatal("private run state was included in a diagnostic")
	}
}
