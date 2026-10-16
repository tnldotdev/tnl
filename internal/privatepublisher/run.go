// package privatepublisher owns a private run's publisher-held TLS key and
// authenticated visitor streams. it never creates public URLs or certificates.
package privatepublisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/tcptarget"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrPrivateStream = errors.New("private publisher: stream is not bound to the current claimed connection")
var ErrUnsupportedTargetTLS = errors.New("private publisher: verified target TLS mode is not available")

const certificateLifetime = 24 * time.Hour
const certificateRenewBefore = 30 * time.Minute

// Prepared retains the per-run key and binding request for retries. a new
// preparation needs a new key; retries must submit this same request.
type Prepared struct {
	Preparation controlv1.PrivateServiceRunPreparation
	Request     controlv1.BindPrivateServiceRunKeyRequest
	private     ed25519.PrivateKey
	certMu      sync.Mutex
	certificate tls.Certificate
	certValidTo time.Time
	clock       func() time.Time
	target      string
}

func (Prepared) String() string   { return "private publisher preparation" }
func (Prepared) GoString() string { return "private publisher preparation" }

// NewPrepared accepts only opaque TCP targets. TLS negotiation with a database
// target needs a separate verified mode, never an implicit plaintext fallback.
func NewPrepared(prep controlv1.PrivateServiceRunPreparation, identity authorityv1.PublisherEnrollmentResult, signing ed25519.PrivateKey, target, targetTLSMode string) (*Prepared, error) {
	if targetTLSMode != "" {
		return nil, ErrUnsupportedTargetTLS
	}
	selected, err := tcptarget.Normalize(target)
	if err != nil || identity.Kind != authorityv1.PrivateService || identity.PrivateServiceId == nil ||
		prep.PrivateServiceId != *identity.PrivateServiceId || prep.TeamId != identity.TeamId ||
		prep.PublisherIdentityId != identity.ClientId || prep.PublisherGrantId != identity.GrantId || prep.PublisherKeyId != identity.KeyId ||
		prep.RunNumber <= 0 || !prep.ExpiresAt.After(time.Now()) || len(signing) != ed25519.PrivateKeySize ||
		!bytes.Equal(ed25519.NewKeyFromSeed(signing.Seed()), signing) {
		return nil, ErrPrivateStream
	}
	nonce, err := hex.DecodeString(prep.BindingNonce)
	if err != nil || hex.EncodeToString(nonce) != prep.BindingNonce {
		return nil, ErrPrivateStream
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	binding := tunnelv1.PrivateRunKeyBinding{
		TeamID: prep.TeamId, PrivateServiceID: prep.PrivateServiceId, PrivateRunID: prep.PrivateRunId,
		RunNumber: uint64(prep.RunNumber), PublisherIdentityID: prep.PublisherIdentityId,
		PublisherGrantID: prep.PublisherGrantId, PublisherKeyID: prep.PublisherKeyId,
		IdempotencyKey: prep.IdempotencyKey, BindingNonce: nonce, StreamPublicKey: public,
	}
	digest, err := tunnelv1.PrivateRunBindingDigest(binding)
	if err != nil {
		return nil, err
	}
	// the preparation nonce expires before a healthy heartbeat-maintained run.
	// leaf renewal keeps this per-run private key and control's public pin.
	p := &Prepared{Preparation: prep, target: selected, private: private, clock: time.Now,
		Request: controlv1.BindPrivateServiceRunKeyRequest{
			RunNumber: prep.RunNumber, StreamPublicKey: hex.EncodeToString(public),
			BindingSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signing, digest)),
		}}
	_, err = p.currentCertificate()
	if err != nil {
		return nil, err
	}
	return p, nil
}

// currentCertificate renews well before expiry and never rotates the per-run
// key. concurrent handshakes retain their own immutable certificate snapshot.
func (p *Prepared) currentCertificate() (*tls.Certificate, error) {
	if p == nil || p.clock == nil {
		return nil, ErrPrivateStream
	}
	p.certMu.Lock()
	defer p.certMu.Unlock()
	now := p.clock()
	if now.IsZero() {
		return nil, ErrPrivateStream
	}
	if !p.certValidTo.After(now.Add(certificateRenewBefore)) {
		public := p.private.Public().(ed25519.PublicKey)
		certificate, err := runCertificate(public, p.private, now)
		if err != nil {
			return nil, err
		}
		p.certificate, p.certValidTo = certificate, now.Add(certificateLifetime)
	}
	certificate := p.certificate
	if len(certificate.Certificate) == 0 || !p.certValidTo.After(now) {
		return nil, ErrPrivateStream
	}
	return &certificate, nil
}

func runCertificate(public ed25519.PublicKey, private ed25519.PrivateKey, now time.Time) (tls.Certificate, error) {
	if now.IsZero() || len(public) != ed25519.PublicKeySize || len(private) != ed25519.PrivateKeySize {
		return tls.Certificate{}, ErrPrivateStream
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(certificateLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, nil
}

// Bound is usable only with the exact control-approved key and two different
// assigned relay services. neither the run token nor TLS key enters any log.
type Bound struct {
	prepared    *Prepared
	assignments map[string]tunnelv1.PrivatePublisherConnectionRef
	connections [2]controlv1.ConnectionAssignment
	mu          sync.Mutex
	active      map[net.Conn]struct{}
	closed      bool
}

func (Bound) String() string   { return "private publisher run" }
func (Bound) GoString() string { return "private publisher run" }

func (p *Prepared) Bind(setup controlv1.PrivateServiceRunSetup) (*Bound, error) {
	if p == nil || setup.PrivateServiceId != p.Preparation.PrivateServiceId ||
		setup.PrivateRunId != p.Preparation.PrivateRunId || setup.RunNumber != p.Preparation.RunNumber ||
		setup.StreamPublicKey != p.Request.StreamPublicKey || setup.RunToken == "" ||
		!p.Preparation.ExpiresAt.After(time.Now()) ||
		len(setup.PublisherConnections) != 2 {
		return nil, ErrPrivateStream
	}
	if _, err := p.currentCertificate(); err != nil {
		return nil, err
	}
	assignments := make(map[string]tunnelv1.PrivatePublisherConnectionRef, 2)
	var connections [2]controlv1.ConnectionAssignment
	var slots [2]bool
	services := make(map[string]bool, 2)
	for _, assignment := range setup.PublisherConnections {
		if assignment.ConnectionSlot < 0 || assignment.ConnectionSlot > 1 || assignment.ConnectionAssignmentRevision < 1 ||
			assignment.PublisherConnectionCredential == "" || !assignment.PublisherConnectionCredentialExpiresAt.After(time.Now()) ||
			services[assignment.RelayServiceId] || slots[assignment.ConnectionSlot] || assignments[assignment.PublisherConnectionId].PublisherConnectionID != "" {
			return nil, ErrPrivateStream
		}
		ref := tunnelv1.PrivatePublisherConnectionRef{
			PrivateServiceID: setup.PrivateServiceId, PrivateRunID: setup.PrivateRunId, RunNumber: uint64(setup.RunNumber),
			PublisherConnectionID: assignment.PublisherConnectionId, ConnectionSlot: uint8(assignment.ConnectionSlot),
			ConnectionAssignmentRevision: uint64(assignment.ConnectionAssignmentRevision), RelayServiceID: assignment.RelayServiceId,
		}
		if err := ref.Validate(); err != nil {
			return nil, ErrPrivateStream
		}
		assignments[ref.PublisherConnectionID] = ref
		// connection slots are exactly 0 and 1; the credential stays local.
		connections[assignment.ConnectionSlot] = assignment
		slots[assignment.ConnectionSlot] = true
		services[ref.RelayServiceID] = true
	}
	if len(assignments) != 2 || len(services) != 2 {
		return nil, ErrPrivateStream
	}
	return &Bound{prepared: p, assignments: assignments, connections: connections, active: make(map[net.Conn]struct{})}, nil
}

// Hello selects one current relay assignment. callers must use a WebPKI-
// verified transport to that relay address and tunnel.Dial before accepting
// any private stream; a hello never selects a public URL.
func (b *Bound) Hello(slot uint8) (muxsession.Endpoint, tunnelv1.Message, error) {
	if b == nil || slot > 1 {
		return muxsession.Endpoint{}, tunnelv1.Message{}, ErrPrivateStream
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return muxsession.Endpoint{}, tunnelv1.Message{}, ErrPrivateStream
	}
	if _, err := b.prepared.currentCertificate(); err != nil {
		return muxsession.Endpoint{}, tunnelv1.Message{}, err
	}
	assignment := b.connections[slot]
	ref, ok := b.assignments[assignment.PublisherConnectionId]
	if !ok || ref.ConnectionSlot != slot || assignment.PublisherConnectionCredential == "" ||
		!assignment.PublisherConnectionCredentialExpiresAt.After(time.Now()) || assignment.RelayAddress == "" || assignment.TlsServerName == "" {
		return muxsession.Endpoint{}, tunnelv1.Message{}, ErrPrivateStream
	}
	hello := tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher,
		Credential: assignment.PublisherConnectionCredential, PrivateConnection: &ref}
	if err := hello.Validate(); err != nil {
		return muxsession.Endpoint{}, tunnelv1.Message{}, ErrPrivateStream
	}
	return muxsession.Endpoint{Address: assignment.RelayAddress, ServerName: assignment.TlsServerName}, hello, nil
}

// MatchesHeartbeat rejects a changed run pin or relay assignment. the caller
// must replace the affected slot under a new claimed connection before
// accepting streams on that revision; old visitor streams are never replayed.
func (b *Bound) MatchesHeartbeat(state controlv1.PrivateServiceRunState) bool {
	if b == nil || state.PrivateServiceId != b.prepared.Preparation.PrivateServiceId ||
		state.PrivateRunId != b.prepared.Preparation.PrivateRunId ||
		state.RunNumber != b.prepared.Preparation.RunNumber ||
		(state.State != controlv1.PrivateServiceRunStateState("starting") && state.State != controlv1.PrivateServiceRunStateState("ready")) ||
		state.StreamPublicKey != b.prepared.Request.StreamPublicKey ||
		!state.PublisherExpiresAt.After(time.Now()) || len(state.PublisherConnections) != 2 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	var seen [2]bool
	for _, current := range state.PublisherConnections {
		if current.ConnectionSlot < 0 || current.ConnectionSlot > 1 || seen[current.ConnectionSlot] {
			return false
		}
		seen[current.ConnectionSlot] = true
		original := b.connections[current.ConnectionSlot]
		if current.PublisherConnectionId != original.PublisherConnectionId ||
			current.ConnectionAssignmentRevision != original.ConnectionAssignmentRevision ||
			current.RelayServiceId != original.RelayServiceId ||
			current.RelayAddress != original.RelayAddress || current.TlsServerName != original.TlsServerName {
			return false
		}
	}
	_, err := b.prepared.currentCertificate()
	return err == nil
}

// ConnectSlot uses server-authenticated WebPKI on both transport candidates.
// tunnel.Race returns only after the relay accepts this exact private claim.
// no target CA or private TLS key is used for relay authentication.
func (b *Bound) ConnectSlot(ctx context.Context, slot uint8) (*Claimed, error) {
	endpoint, hello, err := b.Hello(slot)
	if err != nil {
		return nil, err
	}
	roots := &tls.Config{MinVersion: tls.VersionTLS13}
	session, _, err := tunnel.Race(ctx,
		tunnel.Candidate{Connector: muxsession.QUICConnector{TLSConfig: roots}, Endpoint: endpoint, Transport: tunnel.TransportQUIC},
		tunnel.Candidate{Connector: muxsession.TLSYamuxConnector{TLSConfig: roots}, Endpoint: endpoint, Transport: tunnel.TransportTLSTCP},
		250*time.Millisecond, hello)
	if err != nil {
		return nil, err
	}
	return &Claimed{bound: b, ref: *hello.PrivateConnection, session: session}, nil
}

// Claimed can only be constructed after a relay accepted the private tunnel
// hello over verified transport. visitor headers are still checked per stream.
type Claimed struct {
	bound   *Bound
	ref     tunnelv1.PrivatePublisherConnectionRef
	session *tunnel.Session
}

func (c *Claimed) Close() error {
	if c == nil || c.session == nil {
		return nil
	}
	return c.session.Close()
}

func (c *Claimed) Serve(ctx context.Context) error {
	if c == nil || c.bound == nil || c.session == nil {
		return ErrPrivateStream
	}
	stop := context.AfterFunc(ctx, func() { _ = c.session.Close() })
	var workers sync.WaitGroup
	defer func() { _ = c.session.Close(); workers.Wait(); stop() }()
	capacity := make(chan struct{}, 64)
	for {
		incoming, err := c.session.AcceptPrivateForwardingStream(ctx)
		if err != nil {
			var invalid *tunnel.StreamHeaderError
			if errors.As(err, &invalid) {
				continue
			}
			if ctx.Err() != nil || errors.Is(err, muxsession.ErrClosed) {
				return nil
			}
			return err
		}
		if !headerMatches(c.ref, incoming.Header, time.Now()) {
			_ = incoming.Reject(tunnelv1.StaleConnectionAssignment)
			continue
		}
		select {
		case capacity <- struct{}{}:
		default:
			_ = incoming.Reject(tunnelv1.CapacityExceeded)
			continue
		}
		if err := incoming.Accept(); err != nil {
			<-capacity
			return err
		}
		workers.Go(func() {
			defer func() { <-capacity }()
			defer incoming.Stream.Close()
			_ = c.bound.serveBody(ctx, c.ref, incoming.Stream, incoming.Header)
		})
	}
}

// Invalidate is called when control closes or replaces this run. it stops all
// current opaque streams and prevents another hello or visitor admission.
func (b *Bound) Invalidate() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.closed = true
	streams := make([]net.Conn, 0, len(b.active))
	for stream := range b.active {
		streams = append(streams, stream)
	}
	b.mu.Unlock()
	for _, stream := range streams {
		_ = stream.Close()
	}
}

// ServeOpaque accepts one stream from a relay connection already authenticated
// and claimed for ref. the caller must not pass an arbitrary visitor socket.
// header and PROXY v2 are checked before TLS or a target dial; only the
// publisher-held key signs the stream challenge inside TLS.
func (b *Bound) serveOpaque(ctx context.Context, ref tunnelv1.PrivatePublisherConnectionRef, stream net.Conn) error {
	if stream != nil {
		defer stream.Close()
	}
	if b == nil || stream == nil || b.assignments[ref.PublisherConnectionID] != ref || ref.Validate() != nil {
		return ErrPrivateStream
	}
	deadline := time.Now().Add(10 * time.Second)
	if err := stream.SetDeadline(deadline); err != nil {
		return err
	}
	header, err := tunnelv1.ReadPrivateForwardingHeader(stream)
	if err != nil || !headerMatches(ref, header, time.Now()) {
		_ = tunnelv1.WriteStreamResponse(stream, tunnelv1.StreamResponse{Type: tunnelv1.StreamRejected, Code: tunnelv1.StaleConnectionAssignment})
		return ErrPrivateStream
	}
	if err := tunnelv1.WriteStreamResponse(stream, tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted}); err != nil {
		return err
	}
	return b.serveBody(ctx, ref, stream, header)
}

func (b *Bound) serveBody(ctx context.Context, ref tunnelv1.PrivatePublisherConnectionRef, stream net.Conn, header tunnelv1.PrivateForwardingHeader) error {
	if b == nil || stream == nil || b.assignments[ref.PublisherConnectionID] != ref ||
		!headerMatches(ref, header, time.Now()) {
		return ErrPrivateStream
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrPrivateStream
	}
	b.active[stream] = struct{}{}
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.active, stream); b.mu.Unlock() }()
	deadline := time.Now().Add(10 * time.Second)
	if err := stream.SetDeadline(deadline); err != nil {
		return err
	}
	metadata, replay, err := proxyproto.Decode(stream)
	if err != nil || metadata.Source.Addr().String() != header.SourceIP {
		return ErrPrivateStream
	}
	if _, err := b.prepared.currentCertificate(); err != nil {
		return err
	}
	secure := tls.Server(&replayConn{Conn: stream, reader: replay}, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return b.prepared.currentCertificate() },
	})
	if err := secure.HandshakeContext(ctx); err != nil {
		return err
	}
	// the forwarding kind is relay-only; normalize the already validated
	// stream identity to the visitor kind before signing the shared challenge.
	visitorHeader := header.PrivateStreamHeader
	visitorHeader.Kind = tunnelv1.PrivateVisitorStream
	challenge, err := tunnelv1.PrivateChallengeFromHeader(visitorHeader)
	if err != nil {
		return ErrPrivateStream
	}
	if err := tunnelv1.WritePrivateStreamProof(secure, tunnelv1.PrivateStreamProof{
		Signature: ed25519.Sign(b.prepared.private, challenge),
	}); err != nil {
		return err
	}
	target, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", b.prepared.target)
	if err != nil {
		return err
	}
	defer target.Close()
	stop := context.AfterFunc(ctx, func() { _ = secure.Close(); _ = target.Close() })
	defer stop()
	if err := stream.SetDeadline(time.Time{}); err != nil {
		return err
	}
	_, err = streamcopy.Copy(secure, target)
	return err
}

func headerMatches(ref tunnelv1.PrivatePublisherConnectionRef, h tunnelv1.PrivateForwardingHeader, now time.Time) bool {
	return h.Validate() == nil && h.PrivateServiceID == ref.PrivateServiceID && h.PrivateRunID == ref.PrivateRunID &&
		h.RunNumber == ref.RunNumber && h.PublisherConnectionID == ref.PublisherConnectionID &&
		h.ConnectionSlot == ref.ConnectionSlot && h.ConnectionAssignmentRevision == ref.ConnectionAssignmentRevision &&
		h.RelayServiceID == ref.RelayServiceID && h.LeaseExpiresAt.After(now) && h.ExpiresAt.After(now) &&
		opaqueid.Valid(h.RelayRunID, opaqueid.RelayRunPrefix)
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
