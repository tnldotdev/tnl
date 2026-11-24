package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/relayslots"

	"github.com/jackc/pgx/v5"
	yamux "github.com/libp2p/go-yamux/v5"
	controlrelay "github.com/tnldotdev/tnl/internal/control/api/private/relay"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/transporttest"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// separate live relay processes in one assigned service let both real
// transports reach postgres; a shared registry would reject one locally.
func TestIntegrationPrivateClaimCompetingTransports(t *testing.T) {
	for _, first := range []tunnel.Transport{tunnel.TransportQUIC, tunnel.TransportWSS} {
		t.Run(string(first)+"-first", func(t *testing.T) {
			testPrivateClaimCompetingTransports(t, first)
		})
	}
}

func testPrivateClaimCompetingTransports(t *testing.T, firstTransport tunnel.Transport) {
	t.Helper()
	fixture := newPrivateClaimFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	slot := fixture.run.Connections[0]
	first := fixture.leases[slot.RelayServiceID]
	otherRun, err := opaqueid.New(opaqueid.RelayRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.database.RegisterRelay(ctx, controlstate.RelayRegistration{
		RelayID: first.RelayID + "-other", RelayServiceID: first.RelayServiceID, RelayRunID: otherRun,
		RelayAddress: first.RelayAddress, TLSServerName: first.TLSServerName, InternalRelayAddress: "127.0.0.1:9449",
		ProtocolVersion: 1, ConnectionCapacity: 1, StreamCapacity: 8,
	}, fixture.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := controlrelay.NewHandler(controlrelay.Config{Store: fixture.database, Slots: claimTestSlots(t, first, second, fixture.leases[fixture.run.Connections[1].RelayServiceID]), LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	type decision struct {
		body     []byte
		path     string
		status   int
		response []byte
		claim    relayv1.ServicePublisherConnectionClaim
	}
	decisions := make(chan decision, 2)
	release := make(chan struct{})
	releaseResponse := sync.OnceFunc(func() { close(release) })
	defer releaseResponse()
	var claims atomic.Int32
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
		var claim relayv1.ServicePublisherConnectionClaim
		if err := json.Unmarshal(body, &claim); err != nil {
			t.Error(err)
			return
		}
		attempt := claims.Add(1)
		r.Body = io.NopCloser(bytes.NewReader(body))
		committed := httptest.NewRecorder()
		handler.ServeHTTP(committed, r)
		if attempt <= 2 {
			decisions <- decision{body, r.URL.Path, committed.Code, bytes.Clone(committed.Body.Bytes()), claim}
			if committed.Code == http.StatusOK {
				// only the response is held: the real claim already committed.
				// keep it connected for replay before normal readiness begins.
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
		}
		for key, values := range committed.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(committed.Code)
		_, _ = w.Write(committed.Body.Bytes())
	}))
	t.Cleanup(server.Close)

	// lock the actual admission row, not an http callback. both claim
	// transactions must be observed behind this lock before either can win.
	blocker, err := pgx.Connect(ctx, fixture.url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := blocker.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	lock, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lock.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	}()
	if _, err := lock.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, fixture.service.ID); err != nil {
		t.Fatal(err)
	}
	ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: fixture.service.ID, ServiceRunID: fixture.run.RunID,
		RunNumber: uint64(fixture.run.RunNumber), PublisherConnectionID: slot.PublisherConnectionID, ConnectionSlot: uint8(slot.ConnectionSlot),
		ConnectionAssignmentRevision: uint64(slot.Revision), RelayServiceID: slot.RelayServiceID}
	hello := tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: 1, Role: tunnelv1.Publisher, Credential: slot.Credential, ServiceConnection: &ref}
	ca, certificate := testutil.TLSCertificate(t, []string{"relay.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("relay test CA is invalid")
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	secondTransport := tunnel.TransportQUIC
	if firstTransport == tunnel.TransportQUIC {
		secondTransport = tunnel.TransportWSS
	}
	candidates := []*privateClaimCandidate{
		startPrivateClaimCandidate(t, ctx, firstTransport, first, claimClient(t, server, first.RelayID), hello, serverTLS, clientTLS),
	}
	if err := relayAwait(t, candidates[0].peer); err != nil {
		t.Fatal(err)
	}
	// postgres's real lock queue, not transport timing, selects the winner in
	// each ordering. both transactions still overlap before the lock is released.
	waitForPrivateClaimTransactions(t, ctx, fixture.inspect, int32(blocker.PgConn().PID()), decisions, candidates)
	candidates = append(candidates, startPrivateClaimCandidate(t, ctx, secondTransport, second, claimClient(t, server, second.RelayID), hello, serverTLS, clientTLS))
	if err := relayAwait(t, candidates[1].peer); err != nil {
		t.Fatal(err)
	}
	waitForPrivateClaimTransactions(t, ctx, fixture.inspect, int32(blocker.PgConn().PID()), decisions, candidates)
	for _, candidate := range candidates {
		candidate.assertLocalOwnership(t, 1, 0)
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	a, b := relayAwait(t, decisions), relayAwait(t, decisions)
	if a.status != http.StatusOK {
		a, b = b, a
	}
	if a.status != http.StatusOK || b.status != http.StatusConflict {
		t.Fatalf("competing durable claims = %d/%d; want exactly one success and one conflict", a.status, b.status)
	}
	winner, loser := candidates[0], candidates[1]
	if a.claim.RelayId != first.RelayID {
		winner, loser = loser, winner
	}
	if winner.transport != firstTransport {
		t.Fatalf("lock queue did not exercise the %s winner", firstTransport)
	}
	for _, result := range []decision{a, b} {
		if result.path != a.path || result.claim.ServiceId != ref.ServiceID || result.claim.ServiceRunId != ref.ServiceRunID ||
			result.claim.RunNumber != int64(ref.RunNumber) || result.claim.ConnectionAssignmentRevision != slot.Revision ||
			result.claim.Credential != slot.Credential || result.claim.ObservedSourceIp != "127.0.0.1" {
			t.Fatal("transport candidates did not claim the same exact assignment and accepted source")
		}
	}
	if a.claim.RelayId != winner.lease.RelayID || a.claim.RelayRunId != winner.lease.RelayRunID ||
		a.claim.RelayLeaseRevision != int64(winner.lease.RelayLeaseRevision) ||
		b.claim.RelayId != loser.lease.RelayID || b.claim.RelayRunId != loser.lease.RelayRunID ||
		b.claim.RelayLeaseRevision != int64(loser.lease.RelayLeaseRevision) {
		t.Fatal("transport claims did not retain their distinct live process leases")
	}
	t.Logf("durable race resolved: winner=%s loser=%s", winner.transport, loser.transport)
	losingDial := relayAwait(t, loser.dial)
	// closing a rejected quic/yamux session can overtake its buffered reply.
	// require the actual control conflict and relay rejection, but do not
	// promise the peer a protocol frame rather than transport reset/eof.
	if losingDial.err == nil || !privateClaimRejectionOnly(losingDial.err, true) {
		t.Fatal("losing publisher hid an independent handshake or cleanup failure", losingDial.err)
	}
	if losingDial.session != nil {
		t.Fatal("losing publisher received an accepted tunnel")
	}
	assertPrivateClaimRejection(t, relayAwait(t, loser.served))
	loser.assertLocalOwnership(t, 0, 0)
	winner.assertLocalOwnership(t, 1, 0)
	snapshot := fixture.assertClaimOwner(t, slot, winner.lease, "connected")

	// replay the exact captured http bytes, including credential and lease.
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+a.path, bytes.NewReader(a.body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+relayslots.Token(winner.lease.RelayID))
	replayed, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	replayBody, readErr := io.ReadAll(replayed.Body)
	closeErr := replayed.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if replayed.StatusCode != http.StatusOK || !bytes.Equal(replayBody, a.response) {
		t.Fatal("exact connected claim replay changed the committed assignment", replayed.StatusCode)
	}
	fixture.assertClaimUnchanged(t, slot, snapshot)

	wrongCredential, _, err := credentials.NewPublisherConnectionCredential()
	if err != nil {
		t.Fatal(err)
	}
	wrongRun, err := opaqueid.New(opaqueid.ServiceRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	wrongRelayRun, err := opaqueid.New(opaqueid.RelayRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	wrongService, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*relayv1.ServicePublisherConnectionClaim)
	}{
		{"credential", func(c *relayv1.ServicePublisherConnectionClaim) { c.Credential = wrongCredential.String() }},
		{"service", func(c *relayv1.ServicePublisherConnectionClaim) { c.ServiceId = wrongService }},
		{"service-run", func(c *relayv1.ServicePublisherConnectionClaim) { c.ServiceRunId = wrongRun }},
		{"run-number", func(c *relayv1.ServicePublisherConnectionClaim) { c.RunNumber++ }},
		{"assignment", func(c *relayv1.ServicePublisherConnectionClaim) { c.ConnectionAssignmentRevision++ }},
		{"relay-process", func(c *relayv1.ServicePublisherConnectionClaim) {
			c.RelayId, c.RelayRunId, c.RelayLeaseRevision = loser.lease.RelayID, loser.lease.RelayRunID, int64(loser.lease.RelayLeaseRevision)
		}},
		{"relay-service", func(c *relayv1.ServicePublisherConnectionClaim) {
			other := fixture.leases[fixture.run.Connections[1].RelayServiceID]
			c.RelayId, c.RelayRunId, c.RelayLeaseRevision = other.RelayID, other.RelayRunID, int64(other.RelayLeaseRevision)
		}},
		{"relay-run", func(c *relayv1.ServicePublisherConnectionClaim) { c.RelayRunId = wrongRelayRun }},
		{"relay-lease", func(c *relayv1.ServicePublisherConnectionClaim) { c.RelayLeaseRevision++ }},
	} {
		claim := a.claim
		test.change(&claim)
		response, err := claimWire(t, server, claim.RelayId).ClaimServicePublisherConnectionWithResponse(ctx, slot.PublisherConnectionID, claim)
		if err != nil || response.StatusCode() != http.StatusConflict || response.ApplicationproblemJSONDefault == nil ||
			response.ApplicationproblemJSONDefault.Code != relayv1.StaleConnectionAssignment {
			t.Fatalf("%s did not reject a non-exact replay: %v, %v", test.name, response, err)
		}
		fixture.assertClaimUnchanged(t, slot, snapshot)
	}
	releaseResponse()
	winningDial := relayAwait(t, winner.dial)
	if winningDial.err != nil || winningDial.session == nil {
		t.Fatal("winning transport did not complete the real publisher handshake", winningDial.err)
	}
	relayAwait(t, winner.ready)
	snapshot = fixture.assertClaimOwner(t, slot, winner.lease, "ready")
	winner.assertLocalOwnership(t, 1, 1)
	loser.assertLocalOwnership(t, 0, 0)
	reclaim, err := claimWire(t, server, winner.lease.RelayID).ClaimServicePublisherConnectionWithResponse(ctx, slot.PublisherConnectionID, a.claim)
	if err != nil || reclaim.StatusCode() != http.StatusConflict || reclaim.ApplicationproblemJSONDefault == nil ||
		reclaim.ApplicationproblemJSONDefault.Code != relayv1.StaleConnectionAssignment {
		t.Fatal("ready claim was not rejected as a stale assignment", err)
	}
	transition := relayv1.ServicePublisherConnectionTransition{ServiceRunId: fixture.run.RunID, RunNumber: fixture.run.RunNumber,
		ConnectionAssignmentRevision: slot.Revision, RelayId: loser.lease.RelayID, RelayRunId: loser.lease.RelayRunID,
		RelayLeaseRevision: int64(loser.lease.RelayLeaseRevision), Unexpected: new(false)}
	response, err := claimWire(t, server, loser.lease.RelayID).DisconnectServicePublisherConnectionWithResponse(ctx, slot.PublisherConnectionID, transition)
	if err != nil || response.StatusCode() != http.StatusConflict {
		t.Fatal("losing process could disconnect the winner", err)
	}
	fixture.assertClaimUnchanged(t, slot, snapshot)
	select {
	case <-winningDial.session.Done():
		t.Fatal("losing candidate or stale transition closed the winning tunnel", winningDial.session.Err())
	default:
	}
	// a real drain exchange proves the winner still carries control messages.
	drain, finishDrain := context.WithTimeout(ctx, 5*time.Second)
	err = winningDial.session.RequestPublisherDrain(drain, "claim-race")
	finishDrain()
	if err != nil {
		t.Fatal("winning publisher stopped responding after the rejected claims", err)
	}
	winner.cancel()
	if err := winningDial.session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := relayAwait(t, winner.served); err != nil {
		t.Fatal("winning relay lost an operation or cleanup failure", err)
	}
	winner.assertLocalOwnership(t, 0, 0)
	t.Logf("one durable claim: winner=%s loser=%s; exact connected replay and current-identity checks retained the owner", winner.transport, loser.transport)
}

type privateClaimDial struct {
	session *tunnel.Session
	err     error
}

type privateClaimCandidate struct {
	transport tunnel.Transport
	lease     controlstate.RelayLease
	registry  *ServiceRegistry
	cancel    context.CancelFunc
	peer      chan error
	dial      chan privateClaimDial
	served    chan error
	ready     chan struct{}
}

func newPrivateClaimCandidateController(client ControlClient, lease controlstate.RelayLease) *Controller {
	return &Controller{client: client, now: time.Now, lease: relayv1.RelayLease{
		RelayServiceId: lease.RelayServiceID, RelayId: lease.RelayID, RelayRunId: lease.RelayRunID,
		RelayLeaseRevision: int64(lease.RelayLeaseRevision), LeaseExpiresAt: lease.LeaseExpiresAt,
		ServingUntil: lease.ServingUntil, ConnectionCapacity: 1}}
}

func TestPrivateClaimCandidateServingAuthority(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		live    time.Time
		serving time.Time
		want    bool
	}{
		{"distinct deadlines", now.Add(time.Minute), now.Add(5 * time.Minute), true},
		{"expired liveness", now, now.Add(time.Minute), true},
		{"missing serving authority", now.Add(time.Minute), time.Time{}, false},
		{"expired serving authority", now.Add(time.Minute), now, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := controlstate.RelayLease{
				RelayLeaseIdentity: controlstate.RelayLeaseIdentity{RelayServiceID: "relay-a", RelayID: "relay-a-1", RelayRunID: "process", RelayLeaseRevision: 7},
				LeaseExpiresAt:     test.live, ServingUntil: test.serving,
			}
			client := &privateClaimControlStub{}
			controller := newPrivateClaimCandidateController(client, lease)
			controller.now = func() time.Time { return now }
			candidate := &privateClaimCandidate{transport: tunnel.TransportQUIC, registry: NewServiceRegistry()}
			acceptor := &PublisherAcceptor{selectTarget: func(string) (ServicePublisherTarget, bool) {
				return ServicePublisherTarget{Control: controller, Registry: candidate.registry}, true
			}}
			ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: privateRelayID(opaqueid.ServicePrefix),
				ServiceRunID: privateRelayID(opaqueid.ServiceRunPrefix), RunNumber: 1,
				PublisherConnectionID:        privateRelayID(opaqueid.PublisherConnectionPrefix),
				ConnectionAssignmentRevision: 1, RelayServiceID: lease.RelayServiceID}
			claim, err := acceptor.claim(t.Context(), tunnelv1.Message{Role: tunnelv1.Publisher, ServiceConnection: &ref, Credential: "credential"}, netip.MustParseAddr("127.0.0.1"))
			if !test.want {
				if claim != nil || err == nil || err.Error() != "relay: control lease is unavailable\ntunnel: internal" || client.claims.Load() != 0 {
					t.Fatalf("invalid serving authority reached control or changed its local rejection: claim=%v err=%v calls=%d", claim != nil, err, client.claims.Load())
				}
				candidate.assertLocalOwnership(t, 0, 0)
				return
			}
			if err != nil || claim == nil || client.claims.Load() != 1 {
				t.Fatalf("control-issued serving authority did not reach the claim: err=%v calls=%d", err, client.claims.Load())
			}
			if claim.lease.RelayServiceId != lease.RelayServiceID || claim.lease.RelayId != lease.RelayID ||
				claim.lease.RelayRunId != lease.RelayRunID || claim.lease.RelayLeaseRevision != int64(lease.RelayLeaseRevision) ||
				!claim.lease.LeaseExpiresAt.Equal(test.live) || !claim.lease.ServingUntil.Equal(test.serving) ||
				claim.lease.ConnectionCapacity != 1 {
				t.Fatal("candidate changed its control-issued lease identity, deadlines, or capacity")
			}
			candidate.assertLocalOwnership(t, 1, 0)
			candidate.registry.release(claim)
			candidate.assertLocalOwnership(t, 0, 0)
		})
	}
}

func startPrivateClaimCandidate(t *testing.T, parent context.Context, transport tunnel.Transport, lease controlstate.RelayLease, client *HTTPControlClient, hello tunnelv1.Message, serverTLS, clientTLS *tls.Config) *privateClaimCandidate {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	c := &privateClaimCandidate{transport: transport, lease: lease, registry: NewServiceRegistry(), cancel: cancel,
		peer: make(chan error, 1), dial: make(chan privateClaimDial, 1), served: make(chan error, 1), ready: make(chan struct{}, 1)}
	controller := newPrivateClaimCandidateController(client, lease)
	acceptor, err := NewPublisherAcceptor(PublisherAcceptorConfig{
		Select: func(id string) (ServicePublisherTarget, bool) {
			return ServicePublisherTarget{Control: controller, Registry: c.registry}, id == lease.RelayServiceID
		},
		ReadyConnectionsDelta: func(delta int) {
			if delta == 1 {
				c.ready <- struct{}{}
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	address := traceMuxServer(t, ctx, transport, serverTLS, func(owner context.Context, mux muxsession.Session) error {
		peer, ok := mux.(muxsession.AcceptedPeer)
		var peerErr error
		// net/http's forced HTTP/1 upgrade clears client ALPN. the accepted
		// WSS session still requires the exact HTTP upgrade and subprotocol.
		network, alpn := "tcp", ""
		if transport == tunnel.TransportQUIC {
			network, alpn = "udp", muxsession.ALPN
		}
		if !ok {
			peerErr = fmt.Errorf("%s candidate has no accepted transport facts", transport)
		} else if state := peer.TLSConnectionState(); peer.RemoteAddr().Network() != network || peer.LocalAddr().Network() != network ||
			!state.HandshakeComplete || state.NegotiatedProtocol != alpn ||
			state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 {
			peerErr = fmt.Errorf("%s candidate did not use its real authenticated %s transport: local=%s remote=%s handshake=%t alpn=%q", transport, network,
				peer.LocalAddr().Network(), peer.RemoteAddr().Network(), state.HandshakeComplete, state.NegotiatedProtocol)
		}
		if transport == tunnel.TransportQUIC {
			bound, ok := mux.(muxsession.IPBoundPeer)
			if !ok || !bound.RemoteIPBound() {
				peerErr = errors.Join(peerErr, errors.New("QUIC candidate has no transport-layer source pin"))
			}
		}
		c.peer <- peerErr
		err := peerErr
		if err == nil {
			err = acceptor.Accept(owner, mux)
		}
		err = errors.Join(err, mux.Close())
		c.served <- err
		return err
	})
	var connector muxsession.Connector = muxsession.WebSocketConnector{TLSConfig: clientTLS}
	if transport == tunnel.TransportQUIC {
		connector = muxsession.QUICConnector{TLSConfig: clientTLS, Dialer: transporttest.QUICTransport(t)}
	}
	var result privateClaimDial
	done := make(chan struct{})
	go func() {
		defer close(done)
		mux, err := connector.Connect(ctx, muxsession.Endpoint{Address: address, ServerName: "relay.test"})
		if err != nil {
			result.err = err
		} else {
			result.session, result.err = tunnel.Dial(ctx, mux, hello)
		}
		c.dial <- result
	}()
	t.Cleanup(func() {
		cancel()
		relayAwait(t, done)
		if result.session != nil {
			if err := result.session.Close(); err != nil {
				t.Error(err)
			}
		}
		if err := c.registry.Close(); err != nil {
			t.Error(err)
		}
	})
	return c
}

func (c *privateClaimCandidate) assertLocalOwnership(t *testing.T, claims, connections int) {
	t.Helper()
	c.registry.mu.Lock()
	defer c.registry.mu.Unlock()
	if len(c.registry.claims) != claims || len(c.registry.connections) != connections {
		t.Fatalf("%s local ownership = %d claims/%d connections; want %d/%d", c.transport, len(c.registry.claims), len(c.registry.connections), claims, connections)
	}
}

func (f privateClaimFixture) assertClaimOwner(t *testing.T, slot controlstate.ServiceRunAssignment, lease controlstate.RelayLease, want string) string {
	t.Helper()
	var state, relay, run, snapshot string
	var revision int64
	err := f.inspect.QueryRow(t.Context(), `
		SELECT state,relay_id,relay_run_id,relay_lease_revision,to_jsonb(slot)::text
		FROM control.service_connection_slots slot WHERE publisher_connection_id=$1
	`, slot.PublisherConnectionID).Scan(&state, &relay, &run, &revision, &snapshot)
	if err != nil || state != want || relay != lease.RelayID || run != lease.RelayRunID || revision != int64(lease.RelayLeaseRevision) {
		t.Fatalf("durable claim lost its exact %s owner: state=%s relay=%s run=%s lease=%d err=%v", want, state, relay, run, revision, err)
	}
	return snapshot
}

func (f privateClaimFixture) assertClaimUnchanged(t *testing.T, slot controlstate.ServiceRunAssignment, snapshot string) {
	t.Helper()
	var unchanged bool
	if err := f.inspect.QueryRow(t.Context(), `
		SELECT to_jsonb(slot)=$2::jsonb FROM control.service_connection_slots slot WHERE publisher_connection_id=$1
	`, slot.PublisherConnectionID, snapshot).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("replay or rejected identity mutated the durable claim", err)
	}
}

// check every joined cause, so an expected rejection cannot hide failed cleanup.
func assertPrivateClaimRejection(t *testing.T, err error) {
	t.Helper()
	var protocol *tunnel.ProtocolError
	var control *ControlProblemError
	if !errors.As(err, &protocol) || protocol.Code != tunnelv1.StaleConnectionAssignment ||
		!errors.As(err, &control) || !privateClaimRejectionOnly(err, false) {
		t.Fatal("relay did not retain the exact control/protocol rejection and cleanup result", err)
	}
}

func privateClaimRejectionOnly(err error, peerClose bool) bool {
	switch err := err.(type) {
	case *tunnel.ProtocolError:
		return err.Code == tunnelv1.StaleConnectionAssignment
	case *ControlProblemError:
		return err.Status == http.StatusConflict && err.Problem != nil && err.Problem.Code == relayv1.StaleConnectionAssignment
	case *muxsession.QUICTransportCloseError:
		return false
	case interface{ Unwrap() []error }:
		if len(err.Unwrap()) == 0 {
			return false
		}
		for _, cause := range err.Unwrap() {
			if !privateClaimRejectionOnly(cause, peerClose) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return privateClaimRejectionOnly(err.Unwrap(), peerClose)
	default:
		return muxsession.NormalSessionCloseOnly(err) || peerClose && (err == io.EOF || err == yamux.ErrStreamReset)
	}
}

func TestPrivateClaimRejectionPreservesIndependentFailures(t *testing.T) {
	protocol := &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	for _, expected := range []error{protocol, muxsession.ErrClosed, io.EOF, fmt.Errorf("%w: connection closed: %w", yamux.ErrStreamReset, io.EOF)} {
		if !privateClaimRejectionOnly(expected, true) {
			t.Fatal("rejected peer close was not recognized", expected)
		}
		for _, independent := range []error{context.Canceled, context.DeadlineExceeded,
			&muxsession.QUICTransportCloseError{Err: muxsession.ErrClosed}, errors.New("independent transport cleanup failure")} {
			if privateClaimRejectionOnly(errors.Join(expected, independent), true) {
				t.Fatal("rejection hid an independent operation or cleanup failure", independent)
			}
		}
	}
	for _, peerOnly := range []error{io.EOF, yamux.ErrStreamReset} {
		if privateClaimRejectionOnly(errors.Join(protocol, peerOnly), false) {
			t.Fatal("relay rejection accepted a peer-only reset/EOF", peerOnly)
		}
	}
}

func waitForPrivateClaimTransactions[T any](t *testing.T, parent context.Context, inspect *pgx.Conn, blocker int32, decisions <-chan T, candidates []*privateClaimCandidate) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	var secondDone <-chan error
	if len(candidates) == 2 {
		secondDone = candidates[1].served
	}
	for {
		var pids []int32
		// follow the lock chain: one transaction may wait on the other claim
		// rather than directly on the fixture's service-row lock.
		err := inspect.QueryRow(ctx, `
			WITH RECURSIVE blocked(pid) AS (
				SELECT pid FROM pg_stat_activity
				WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))
				UNION
				SELECT activity.pid FROM pg_stat_activity activity JOIN blocked
					ON blocked.pid=ANY(pg_blocking_pids(activity.pid))
				WHERE activity.datname=current_database()
			)
			SELECT coalesce(array_agg(pid ORDER BY pid),'{}'::integer[])
			FROM pg_stat_activity WHERE pid IN (SELECT pid FROM blocked)
				AND state='active' AND xact_start IS NOT NULL AND wait_event_type='Lock'
		`, blocker).Scan(&pids)
		if err != nil {
			t.Fatal("observe actual claim transactions", err)
		}
		if len(pids) == len(candidates) {
			t.Logf("%d real transport claim transactions blocked in PostgreSQL: backends=%v blocker=%d", len(candidates), pids, blocker)
			return
		}
		select {
		case <-decisions:
			t.Fatal("a claim finished before the durable transactions reached the lock")
		case err := <-candidates[0].served:
			t.Fatalf("%s candidate exited before the claims reached the durable lock: %v", candidates[0].transport, err)
		case err := <-secondDone:
			t.Fatalf("%s candidate exited before both claims reached the durable lock: %v", candidates[1].transport, err)
		case <-ctx.Done():
			t.Fatal("real transport claims did not reach the durable lock", ctx.Err())
		case <-tick.C:
		}
	}
}
