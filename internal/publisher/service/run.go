// package privatepublisher owns service runs, verified visitor TLS and
// authenticated publisher connections. certificate keys stay in CertificateCache.
package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrPrivateStream = errors.New("private publisher: stream is not bound to the current claimed connection")

// Prepared retains control's exact endpoint and certificate plan across retries.
type Prepared struct {
	Preparation controlv1.ServiceRunPreparation
	*preparedCertificate
	clock               func() time.Time
	target              string
	targetResolver      TargetResolver
	managedHostname     string
	managedProtocol     config.ProtocolName
	managedTargetTLS    *tls.Config
	managedVisitor      func(tunnelv1.ServiceForwardingHeader) publisher.ServiceVisitorAuthentication
	servicePort         uint16
	managedPublic       bool
	serviceHTTPRequests *publisher.ServiceHTTPRequestLimits
	policy              *visitorlease.Lease
	metadataRevision    int64
}

// mutable certificate state stays behind a pointer so redacted value
// formatting cannot copy a lock or race with certificate renewal.
type preparedCertificate struct {
	certMu      sync.Mutex
	certificate tls.Certificate
	certValidTo time.Time
}

func (Prepared) String() string   { return "private publisher preparation" }
func (Prepared) GoString() string { return "private publisher preparation" }

// currentCertificate returns only a live installed certificate from the shared
// cache lifecycle. no serving path generates a certificate or a fallback key.
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
	certificate := p.certificate
	if len(certificate.Certificate) == 0 || !p.certValidTo.After(now) {
		return nil, ErrPrivateStream
	}
	return &certificate, nil
}

// Bound accepts only the exact control-approved run and two different assigned
// relay services. neither the run token nor cached TLS key enters any log.
type Bound struct {
	prepared *Prepared
	*boundState
	streamCapacity int
	audit          serviceaudit.Sink
}

type boundState struct {
	assignments      map[string]tunnelv1.ServicePublisherConnectionRef
	connections      [2]controlv1.ConnectionAssignment
	mu               sync.Mutex
	active           map[net.Conn]struct{}
	closed           bool
	reservedStreams  int
	connectorPending int
	connectorPeers   map[string]*PeerSession
	packetSlots      [2]*Claimed
	closePolicy      func()
}

func (Bound) String() string   { return "private publisher run" }
func (Bound) GoString() string { return "private publisher run" }

func (p *Prepared) Activate(setup controlv1.ServiceRunSetup) (*Bound, error) {
	if p == nil || setup.ServiceId != p.Preparation.ServiceId ||
		setup.ServiceRunId != p.Preparation.ServiceRunId || setup.RunNumber != p.Preparation.RunNumber ||
		setup.RunToken == "" ||
		!p.Preparation.ExpiresAt.After(time.Now()) ||
		len(setup.PublisherConnections) != 2 {
		return nil, ErrPrivateStream
	}
	assignments := make(map[string]tunnelv1.ServicePublisherConnectionRef, 2)
	var connections [2]controlv1.ConnectionAssignment
	var slots [2]bool
	services := make(map[string]bool, 2)
	for _, assignment := range setup.PublisherConnections {
		if assignment.ConnectionSlot < 0 || assignment.ConnectionSlot > 1 || assignment.ConnectionAssignmentRevision < 1 ||
			assignment.PublisherConnectionCredential == "" || !assignment.PublisherConnectionCredentialExpiresAt.After(time.Now()) ||
			services[assignment.RelayServiceId] || slots[assignment.ConnectionSlot] || assignments[assignment.PublisherConnectionId].PublisherConnectionID != "" {
			return nil, ErrPrivateStream
		}
		ref := tunnelv1.ServicePublisherConnectionRef{
			ServiceID: setup.ServiceId, ServiceRunID: setup.ServiceRunId, RunNumber: uint64(setup.RunNumber),
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
	return &Bound{prepared: p, boundState: &boundState{assignments: assignments, connections: connections, active: make(map[net.Conn]struct{})}}, nil
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
	assignment := b.connections[slot]
	ref, ok := b.assignments[assignment.PublisherConnectionId]
	if !ok || ref.ConnectionSlot != slot || assignment.PublisherConnectionCredential == "" ||
		!assignment.PublisherConnectionCredentialExpiresAt.After(time.Now()) || assignment.RelayAddress == "" || assignment.TlsServerName == "" {
		return muxsession.Endpoint{}, tunnelv1.Message{}, ErrPrivateStream
	}
	hello := tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher,
		Credential: assignment.PublisherConnectionCredential, ServiceConnection: &ref}
	if err := hello.Validate(); err != nil {
		return muxsession.Endpoint{}, tunnelv1.Message{}, ErrPrivateStream
	}
	return muxsession.Endpoint{Address: assignment.RelayAddress, ServerName: assignment.TlsServerName}, hello, nil
}

// ApplyHeartbeat validates the exact run and atomically installs current slots.
func (b *Bound) ApplyHeartbeat(state controlv1.ServiceRunState) error {
	if b == nil || state.ServiceId != b.prepared.Preparation.ServiceId ||
		state.ServiceRunId != b.prepared.Preparation.ServiceRunId ||
		state.RunNumber != b.prepared.Preparation.RunNumber ||
		(state.State != controlv1.ServiceRunStateState("starting") && state.State != controlv1.ServiceRunStateState("ready")) ||
		!state.PublisherExpiresAt.After(time.Now()) || len(state.PublisherConnections) != 2 {
		return ErrPrivateStream
	}
	b.mu.Lock()
	var obsolete []*PeerSession
	defer func() {
		b.mu.Unlock()
		for _, p := range obsolete {
			p.Close()
		}
	}()
	if b.closed {
		return ErrPrivateStream
	}
	var seen [2]bool
	var next [2]controlv1.ConnectionAssignment
	refs := make(map[string]tunnelv1.ServicePublisherConnectionRef, 2)
	services := make(map[string]bool, 2)
	for _, current := range state.PublisherConnections {
		if current.ConnectionSlot < 0 || current.ConnectionSlot > 1 || seen[current.ConnectionSlot] {
			return ErrPrivateStream
		}
		seen[current.ConnectionSlot] = true
		original := b.connections[current.ConnectionSlot]
		changed := current.PublisherConnectionId != original.PublisherConnectionId || current.ConnectionAssignmentRevision != original.ConnectionAssignmentRevision
		if current.ConnectionAssignmentRevision < original.ConnectionAssignmentRevision ||
			changed && (current.ConnectionAssignmentRevision <= original.ConnectionAssignmentRevision || current.PublisherConnectionId == original.PublisherConnectionId ||
				current.PublisherConnectionCredential == "" || !current.PublisherConnectionCredentialExpiresAt.After(time.Now())) ||
			!changed && (current.RelayServiceId != original.RelayServiceId || current.RelayAddress != original.RelayAddress || current.TlsServerName != original.TlsServerName) ||
			current.RelayAddress == "" || current.TlsServerName == "" || services[current.RelayServiceId] {
			return ErrPrivateStream
		}
		ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: state.ServiceId, ServiceRunID: state.ServiceRunId,
			RunNumber: uint64(state.RunNumber), PublisherConnectionID: current.PublisherConnectionId,
			ConnectionSlot: uint8(current.ConnectionSlot), ConnectionAssignmentRevision: uint64(current.ConnectionAssignmentRevision), RelayServiceID: current.RelayServiceId}
		if ref.Validate() != nil || refs[ref.PublisherConnectionID].PublisherConnectionID != "" {
			return ErrPrivateStream
		}
		refs[ref.PublisherConnectionID], services[ref.RelayServiceID] = ref, true
		next[current.ConnectionSlot] = current
	}
	b.connections, b.assignments = next, refs
	for _, p := range b.connectorPeers {
		if !b.peerRelaysCurrentLocked(p.binding) {
			obsolete = append(obsolete, p)
		}
	}
	return nil
}

func (b *Bound) MatchesHeartbeat(state controlv1.ServiceRunState) bool {
	return b.ApplyHeartbeat(state) == nil
}

func (b *Bound) assignmentKey(slot uint8) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	a := b.connections[slot]
	return fmt.Sprintf("%s/%d", a.PublisherConnectionId, a.ConnectionAssignmentRevision)
}

func (b *Bound) current(ref tunnelv1.ServicePublisherConnectionRef) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.closed && b.assignments[ref.PublisherConnectionID] == ref
}

// reserveStream is the run's shared final capacity, across both relay slots and
// connector peers. only joined physical cleanup returns this debit.
func (b *Bound) reserveStream(ref tunnelv1.ServicePublisherConnectionRef) (func(), bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.streamCapacity
	if limit == 0 {
		limit = 64
	}
	if b.closed || b.assignments[ref.PublisherConnectionID] != ref || b.reservedStreams >= limit {
		return nil, false
	}
	b.reservedStreams++
	return sync.OnceFunc(func() { b.mu.Lock(); b.reservedStreams--; b.mu.Unlock() }), true
}

// ConnectSlot uses server-authenticated WebPKI on both transport candidates.
// tunnel.Race returns only after the relay accepts this exact private claim.
// no target CA or private TLS key is used for relay authentication.
func (b *Bound) ConnectSlot(ctx context.Context, slot uint8) (*Claimed, error) {
	return b.ConnectSlotWithPreference(ctx, slot, false, nil)
}

func (b *Bound) ConnectSlotWithPreference(ctx context.Context, slot uint8, preferTCP bool, roots *tls.Config) (*Claimed, error) {
	if roots == nil {
		roots = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	if roots.InsecureSkipVerify {
		return nil, ErrPrivateStream
	}
	return b.ConnectSlotWithTransports(ctx, slot, preferTCP, muxsession.QUICConnector{TLSConfig: roots, Config: muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}}}, muxsession.TLSYamuxConnector{TLSConfig: roots})
}

// ConnectSlotWithTransports retains the production claim and stale-assignment
// checks when a caller supplies address-aware, certificate-verified connectors.
func (b *Bound) ConnectSlotWithTransports(ctx context.Context, slot uint8, preferTCP bool, quic, tcp muxsession.Connector) (*Claimed, error) {
	endpoint, hello, err := b.Hello(slot)
	if err != nil {
		return nil, err
	}
	primary := tunnel.Candidate{Connector: requirePeerDatagrams(quic), Endpoint: endpoint, Transport: tunnel.TransportQUIC}
	fallback := tunnel.Candidate{Connector: tcp, Endpoint: endpoint, Transport: tunnel.TransportTLSTCP}
	if preferTCP {
		primary, fallback = fallback, primary
	}
	connectCtx, finish := observability.PublisherOperation(ctx, "private_connect")
	session, transport, err := tunnel.Race(connectCtx, primary, fallback, 250*time.Millisecond, hello)
	finish(err)
	observability.PublisherConnection(ctx, string(transport), preferTCP, err)
	if err != nil {
		return nil, err
	}
	if !b.current(*hello.ServiceConnection) {
		_ = session.Close()
		return nil, ErrPrivateStream
	}
	outer, err := session.BorrowServicePublisherTransport()
	if err != nil {
		return nil, errors.Join(err, session.Close())
	}
	packets, err := peer.NewDispatchedSharedSession(ctx, outer)
	if err != nil {
		return nil, errors.Join(err, session.Close())
	}
	dispatcher, err := tunnel.NewServiceStreamDispatcher(ctx, session, packets)
	if err != nil {
		return nil, errors.Join(err, packets.Close(), session.Close())
	}
	claimed := &Claimed{bound: b, ref: *hello.ServiceConnection, session: session, transport: transport,
		packets: packets, dispatcher: dispatcher,
		endObservation: observability.PublisherConnectionLifetime(ctx, string(transport), int(slot))}
	b.mu.Lock()
	current := !b.closed && b.assignments[claimed.ref.PublisherConnectionID] == claimed.ref
	if current {
		b.packetSlots[slot] = claimed
	}
	b.mu.Unlock()
	if !current {
		return nil, errors.Join(ErrPrivateStream, claimed.Close())
	}
	return claimed, nil
}

// Claimed can only be constructed after a relay accepted the private tunnel
// hello over verified transport. visitor headers are still checked per stream.
type Claimed struct {
	bound          *Bound
	ref            tunnelv1.ServicePublisherConnectionRef
	session        *tunnel.Session
	transport      tunnel.Transport
	endObservation func(error, bool)
	packets        *peer.SharedSession
	dispatcher     *tunnel.ServiceStreamDispatcher
	closeOnce      sync.Once
	closeErr       error
}

func (c *Claimed) Transport() tunnel.Transport { return c.transport }

func (c *Claimed) Drain(ctx context.Context) error {
	id, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return err
	}
	return c.session.RequestPublisherDrain(ctx, id)
}

func (c *Claimed) Close() error {
	if c == nil || c.session == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.bound.mu.Lock()
		if c.bound.packetSlots[c.ref.ConnectionSlot] == c {
			c.bound.packetSlots[c.ref.ConnectionSlot] = nil
		}
		c.bound.mu.Unlock()
		if c.endObservation != nil {
			c.endObservation(nil, true)
		}
		if c.dispatcher != nil {
			c.closeErr = errors.Join(c.closeErr, c.dispatcher.Close())
		}
		if c.packets != nil {
			c.closeErr = errors.Join(c.closeErr, c.packets.Close())
		}
		c.closeErr = errors.Join(c.closeErr, c.session.Close())
	})
	return c.closeErr
}

func (c *Claimed) Serve(ctx context.Context) (result error) {
	if c == nil || c.bound == nil || c.session == nil {
		return ErrPrivateStream
	}
	owner := ctx
	defer func() {
		if c.endObservation != nil {
			observationError := result
			if observationError == nil && owner.Err() == nil {
				observationError = io.EOF
			}
			c.endObservation(observationError, owner.Err() != nil)
		}
	}()
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { _ = c.session.Close() })
	var workers sync.WaitGroup
	defer func() { cancel(); _ = c.session.Close(); workers.Wait(); stop() }()
	for {
		incoming, err := c.session.AcceptDispatchedServiceForwardingStream(ctx, c.dispatcher)
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
		if !c.bound.current(c.ref) || !headerMatches(c.ref, incoming.Header, time.Now()) {
			_ = incoming.Reject(tunnelv1.StaleConnectionAssignment)
			continue
		}
		release, available := c.bound.reserveStream(c.ref)
		if !available {
			_ = incoming.Reject(tunnelv1.CapacityExceeded)
			continue
		}
		if err := incoming.Accept(); err != nil {
			release()
			continue
		}
		workers.Go(func() {
			defer release()
			defer incoming.Stream().Close()
			_ = c.bound.serveBody(incoming.Context(), c.ref, incoming.Stream(), incoming.Header, incoming.CloseWrite)
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
	peers := make([]*PeerSession, 0, len(b.connectorPeers))
	for _, p := range b.connectorPeers {
		peers = append(peers, p)
	}
	streams := make([]net.Conn, 0, len(b.active))
	for stream := range b.active {
		streams = append(streams, stream)
	}
	b.mu.Unlock()
	for _, stream := range streams {
		_ = stream.Close()
	}
	for _, p := range peers {
		p.Close()
	}
	if b.closePolicy != nil {
		b.closePolicy()
	}
}

func (b *Bound) serveBody(ctx context.Context, ref tunnelv1.ServicePublisherConnectionRef, stream net.Conn, header tunnelv1.ServiceForwardingHeader, endStream func(context.Context) error) error {
	ctx = observability.ExtractWireTrace(ctx, header.TraceContext)
	ctx = observability.WithVisitor(ctx, header.VisitorConnectionID)
	if b == nil || stream == nil || !b.current(ref) ||
		!headerMatches(ref, header, time.Now()) {
		return ErrPrivateStream
	}
	b.mu.Lock()
	if b.closed || b.assignments[ref.PublisherConnectionID] != ref {
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
	if header.PublicService != nil && (metadata.Destination.Port() != header.PublicService.DestinationPort || header.PublicService.DestinationPort != b.prepared.servicePort) {
		return ErrPrivateStream
	}
	authority := ""
	// direct visitors use the exact managed origin. admitted connector clients
	// can use a loopback authority, including an owned kubeconfig's local server.
	if b.prepared.managedPublic && header.PublicService != nil {
		authority = net.JoinHostPort(b.prepared.managedHostname, strconv.Itoa(int(b.prepared.servicePort)))
	}
	connection := &replayConn{Conn: stream, reader: replay}
	if endStream != nil {
		connection.endStream = func() error { return endStream(ctx) }
	}
	return b.forwardManaged(ctx, connection, b.prepared.managedVisitor(header), authority)
}

func (b *Bound) forwardManaged(ctx context.Context, stream net.Conn, visitor publisher.ServiceVisitorAuthentication, authority string) error {
	check := func() error {
		if native, ok := visitor.(publisher.ConnectorVisitor); ok {
			_, err := native.Admission.CheckUse(ctx)
			return err
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	target, targetTLS := b.prepared.target, b.prepared.managedTargetTLS
	if b.prepared.targetResolver != nil {
		resolve := ctx
		cancel := func() {}
		if native, ok := visitor.(publisher.ConnectorVisitor); ok {
			resolve, cancel = context.WithDeadline(ctx, native.Admission.SetupDeadline())
		}
		var err error
		target, targetTLS, err = b.prepared.targetResolver.ResolveTarget(resolve)
		if err == nil {
			err = context.Cause(resolve)
		}
		cancel()
		if err != nil {
			return err
		}
		if targetTLS == nil {
			return ErrPrivateStream
		}
	}
	if err := check(); err != nil {
		return err
	}
	managed := publisher.ServiceStream{Protocol: b.prepared.managedProtocol, Public: b.prepared.managedPublic, Hostname: b.prepared.managedHostname, Target: target, HTTPRequests: b.prepared.serviceHTTPRequests,
		Authority: authority,
		TLS:       &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return b.prepared.currentCertificate() }}, TargetTLS: targetTLS, Visitor: visitor}
	return managed.Forward(ctx, stream)
}

func headerMatches(ref tunnelv1.ServicePublisherConnectionRef, h tunnelv1.ServiceForwardingHeader, now time.Time) bool {
	return h.Validate() == nil && h.ServiceID == ref.ServiceID && h.ServiceRunID == ref.ServiceRunID &&
		h.RunNumber == ref.RunNumber && h.PublisherConnectionID == ref.PublisherConnectionID &&
		h.ConnectionSlot == ref.ConnectionSlot && h.ConnectionAssignmentRevision == ref.ConnectionAssignmentRevision &&
		h.RelayServiceID == ref.RelayServiceID && h.LeaseExpiresAt.After(now) && h.ExpiresAt.After(now) &&
		opaqueid.Valid(h.RelayRunID, opaqueid.RelayRunPrefix)
}

type replayConn struct {
	net.Conn
	reader    io.Reader
	endStream func() error
	closeOnce sync.Once
	closeErr  error
}

func (c *replayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *replayConn) Close() error {
	c.closeOnce.Do(func() {
		var err error
		if c.endStream != nil {
			err = c.endStream()
		}
		c.closeErr = errors.Join(err, c.Conn.Close())
	})
	return c.closeErr
}
