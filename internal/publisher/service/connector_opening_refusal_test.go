package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// all network work, gates and assertions share the caller's original five
// seconds. the only synthetic operations below are faults on real stream i/o.
func openingRefusalAwait[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-ctx.Done():
		t.Fatal("opening refusal worker exceeded its original budget", context.Cause(ctx))
		var zero T
		return zero
	}
}

type openingRefusalTarget struct {
	address string
	trust   *tls.Config
	dials   atomic.Int64
}

func newOpeningRefusalTarget(t *testing.T, ctx context.Context, protocol config.ProtocolName) *openingRefusalTarget {
	t.Helper()
	certificate, trust := managedTestCertificate(t, "opening.target.example.test")
	target := &openingRefusalTarget{trust: trust}
	if protocol == config.ProtocolHTTP {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "opening HTTP")
		}))
		server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				target.dials.Add(1)
			}
		}
		server.StartTLS()
		t.Cleanup(server.Close)
		target.address = server.Listener.Addr().String()
		return target
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target.address = listener.Addr().String()
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	stopped := false
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if stopped {
				mu.Unlock()
				_ = raw.Close()
				return
			}
			connections[raw] = struct{}{}
			mu.Unlock()
			target.dials.Add(1)
			workers.Go(func() {
				defer func() {
					_ = raw.Close()
					mu.Lock()
					delete(connections, raw)
					mu.Unlock()
				}()
				deadline, _ := ctx.Deadline()
				_ = raw.SetDeadline(deadline)
				if protocol == config.ProtocolPostgres {
					var request [8]byte
					if _, err := io.ReadFull(raw, request[:]); err != nil || request != targettransport.PostgresSSLRequest {
						return
					}
					if _, err := raw.Write([]byte{'S'}); err != nil {
						return
					}
				}
				secured := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if err := secured.HandshakeContext(ctx); err != nil {
					return
				}
				if protocol == config.ProtocolPostgres {
					var startup [8]byte
					if _, err := io.ReadFull(secured, startup[:]); err != nil || startup != [8]byte{0, 0, 0, 8, 0, 3, 0, 0} {
						return
					}
					if _, err := secured.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}); err != nil {
						return
					}
				}
				_, _ = io.Copy(secured, secured)
			})
		}
	})
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		stopped = true
		for connection := range connections {
			_ = connection.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return target
}

type openingRefusalSubject struct {
	id  string
	key ed25519.PrivateKey
}

type openingRefusalFixture struct {
	bound       *Bound
	trust       *tls.Config
	control     *connectorDeliveryFixture
	target      *openingRefusalTarget
	protocol    config.ProtocolName
	resolutions atomic.Int64
	until       time.Time
	subjects    [3]openingRefusalSubject
}

func newOpeningRefusalFixture(t *testing.T, ctx context.Context, protocol config.ProtocolName) *openingRefusalFixture {
	t.Helper()
	target := newOpeningRefusalTarget(t, ctx, protocol)
	bound, _, trust, _, control := connectorPeerFixture(t, target.address)
	fixture := &openingRefusalFixture{bound: bound, trust: trust, control: control, target: target,
		protocol: protocol, until: control.delivery.ExpiresAt}
	bound.prepared.managedProtocol = protocol
	bound.prepared.targetResolver = connectorResolverFunc(func(context.Context) (string, *tls.Config, error) {
		fixture.resolutions.Add(1)
		return target.address, target.trust.Clone(), nil
	})
	if protocol == config.ProtocolHTTP {
		var err error
		bound.prepared.serviceHTTPRequests, err = requestlimit.NewHTTP(nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range fixture.subjects {
		fixture.subjects[i] = openingRefusalSubject{
			id:  "wls_" + strings.Repeat(string(rune('A'+i)), 22),
			key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(12 + i)}, 32)),
		}
	}
	fixture.install(t, 2, 0, 1)
	return fixture
}

func (f *openingRefusalFixture) install(t *testing.T, revision int64, subjects ...int) {
	t.Helper()
	policy := f.control.policy
	policy.VisitorPolicyRevision = revision
	policy.ObservedAt = time.Now()
	policy.ValidUntil = policy.ObservedAt.Add(visitortoken.PolicyLifetime)
	policy.WorkloadLeases = nil
	for _, index := range subjects {
		subject := f.subjects[index]
		digest, err := visitortoken.KeyDigest(subject.key.Public())
		if err != nil {
			t.Fatal(err)
		}
		policy.WorkloadLeases = append(policy.WorkloadLeases,
			controlv1.VisitorWorkloadLease{SessionId: subject.id, KeySha256: digest, ExpiresAt: f.until})
	}
	// keep the original fixture's background response immutable. its older
	// revision cannot overwrite this installed snapshot during a five-second case.
	request := f.bound.prepared.policy.Begin()
	update, err := visitorlease.Decode(controlv1.VisitorPolicyUpdate{Policy: policy, SnapshotRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.bound.prepared.policy.Apply(request, update); err != nil {
		t.Fatal(err)
	}
}

func (f *openingRefusalFixture) peer(t *testing.T, ctx context.Context, index int, label string) *PeerSession {
	t.Helper()
	delivery := f.control.delivery
	delivery.PairId = "cpp_" + strings.Repeat(label, 22)
	delivery.DeliveryId = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{label[0]}, 16))
	delivery.Key = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{label[0]}, 32))
	delivery.SessionKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{label[0] + 1}, 32))
	delivery.Subject = controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &f.subjects[index].id}
	control := &connectorDeliveryFixture{delivery: delivery}
	binding, err := PreparePeerBinding(ctx, control, delivery.ServiceId, delivery.ServiceRunId,
		delivery.PairId, delivery.DeliveryGeneration, "run-token")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := f.bound.BindPeer(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Close)
	return peer
}

func openingRefusalSign(t *testing.T, entry *tunnelv1.ConnectorPeerVisitorEntry, key ed25519.PrivateKey) {
	t.Helper()
	message, err := tunnelv1.ConnectorPeerProofMessage(*entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
}

func (f *openingRefusalFixture) entry(t *testing.T, peer *PeerSession, index int, label string) tunnelv1.ConnectorPeerVisitorEntry {
	t.Helper()
	subject, binding := f.subjects[index], peer.bindingSnapshot()
	view, enabled, _ := f.bound.prepared.policy.Current()
	if !enabled {
		t.Fatal("opening fixture lost current policy")
	}
	digest, err := visitortoken.KeyDigest(subject.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	token, err := visitortoken.Sign(view.Issuer, "fixture", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)),
		visitortoken.Permission{Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: binding.serviceID},
			Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision,
			Subject: visitortoken.Workload{SessionID: subject.id, KeySHA256: digest}, ExpiresAt: f.until}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	entry := tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream,
		PairID: binding.pairID, DeliveryID: base64.RawURLEncoding.EncodeToString(binding.delivery[:]),
		DeliveryGeneration: binding.generation, ServiceID: binding.serviceID, ServiceRunID: binding.runID,
		RunNumber: binding.number, Subject: binding.subject, SourceIP: binding.source.String(),
		VisitorConnectionID: "vc_" + strings.Repeat(label, 22), MetadataRevision: uint64(f.bound.prepared.metadataRevision),
		Permission: tunnelv1.ConnectorVisitorPermission{Token: token.Reveal(),
			PublicKey: base64.RawURLEncoding.EncodeToString(subject.key.Public().(ed25519.PublicKey)),
			Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}}
	openingRefusalSign(t, &entry, subject.key)
	if _, err := visitortoken.VerifyConnectorPeerSession(entry, nil, binding.expected(), view, time.Now()); err != nil {
		t.Fatal("fixture did not produce an actual valid signed opening", err)
	}
	return entry
}

// the stream observer delegates every real operation except an explicitly armed
// write fault. it observes acceptance/control writes; it never manufactures one.
type openingRefusalWriteStream struct {
	muxsession.Stream
	ctx              context.Context
	writes           atomic.Int64
	armed            atomic.Bool
	err              error
	entered, release chan struct{}
	once             sync.Once
}

func (s *openingRefusalWriteStream) Write(p []byte) (int, error) {
	s.writes.Add(1)
	if s.armed.Load() {
		s.once.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-s.ctx.Done():
		}
		return 0, s.err
	}
	return s.Stream.Write(p)
}

type openingRefusalWriteSession struct {
	muxsession.Session
	accepted, selected int
	stream             *openingRefusalWriteStream
}

func (s *openingRefusalWriteSession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	s.accepted++
	if s.accepted == s.selected {
		s.stream.Stream = stream
		return s.stream, nil
	}
	return stream, nil
}

type openingRefusalServing struct {
	peer   *PeerSession
	client muxsession.Session
	done   chan struct{}
	err    error
}

func (f *openingRefusalFixture) serve(t *testing.T, ctx context.Context, peer *PeerSession,
	wrap func(muxsession.Session) muxsession.Session, unblock func(),
) *openingRefusalServing {
	t.Helper()
	client, server := connectorInnerPair(t, ctx, f.trust)
	serving := &openingRefusalServing{peer: peer, client: client, done: make(chan struct{})}
	selected := muxsession.Session(server)
	if wrap != nil {
		selected = wrap(server)
	}
	go func() {
		serving.err = serveConnectorInner(ctx, peer, selected)
		close(serving.done)
	}()
	t.Cleanup(func() {
		if unblock != nil {
			unblock()
		}
		peer.Close()
		_ = client.Close()
		_ = server.Close()
		<-serving.done
	})
	return serving
}

func (s *openingRefusalServing) alive(t *testing.T) {
	t.Helper()
	s.peer.bound.mu.Lock()
	current, closed, err := s.peer.currentLocked(), s.peer.bound.closed, s.peer.err
	s.peer.bound.mu.Unlock()
	if !current || closed || err != nil {
		t.Fatal("initial opening refusal escaped its visitor and retired a live peer/run", current, closed, err)
	}
	select {
	case <-s.done:
		t.Fatal("initial opening refusal ended the retained peer", s.err)
	default:
	}
}

func openingRefusalJoinWorkers(t *testing.T, ctx context.Context, peer *PeerSession) {
	t.Helper()
	done := make(chan struct{})
	go func() { peer.workers.Wait(); close(done) }()
	openingRefusalAwait(t, ctx, done)
}

func openingRefusalPending(t *testing.T, peer *PeerSession) *connectorAdmission {
	t.Helper()
	peer.bound.mu.Lock()
	defer peer.bound.mu.Unlock()
	if len(peer.streams) != 1 {
		t.Fatal("held opening did not own exactly one real reservation", len(peer.streams))
	}
	for admission := range peer.streams {
		if admission.guard != nil || admission.admittedLocked() || admission.chargedLocked() {
			t.Fatal("unverified opening acquired a guard or ordinary capacity")
		}
		return admission
	}
	return nil
}

func openingRefusalRaw(t *testing.T, ctx context.Context, serving *openingRefusalServing, entry tunnelv1.ConnectorPeerVisitorEntry) muxsession.Stream {
	t.Helper()
	stream, err := serving.client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	deadline, _ := ctx.Deadline()
	if err := stream.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := tunnelv1.WriteConnectorPeerVisitorOpening(stream, entry, nil); err != nil {
		t.Fatal(err)
	}
	return stream
}

func openingRefusalNoAcceptance(t *testing.T, stream net.Conn) {
	t.Helper()
	var first [1]byte
	n, err := stream.Read(first[:])
	var timeout net.Error
	if n != 0 || err == nil || errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatal("initial refusal wrote acceptance/target bytes or merely timed out", n, err)
	}
}

func (f *openingRefusalFixture) connect(t *testing.T, ctx context.Context, serving *openingRefusalServing,
	entry tunnelv1.ConnectorPeerVisitorEntry,
) net.Conn {
	t.Helper()
	raw := openingRefusalRaw(t, ctx, serving, entry)
	if err := tunnelv1.ReadConnectorPeerVisitorAccepted(raw, entry.VisitorConnectionID); err != nil {
		t.Fatal("valid opening following a refusal lost its actual acceptance", err)
	}
	if f.protocol == config.ProtocolPostgres {
		if _, err := raw.Write(targettransport.PostgresSSLRequest[:]); err != nil {
			t.Fatal(err)
		}
		var accepted [1]byte
		if _, err := io.ReadFull(raw, accepted[:]); err != nil || accepted[0] != 'S' {
			t.Fatal("visitor postgres negotiation changed", accepted, err)
		}
	}
	secured := tls.Client(raw, f.trust.Clone())
	if err := secured.HandshakeContext(ctx); err != nil {
		t.Fatal("valid visitor TLS failed", err)
	}
	if f.protocol == config.ProtocolPostgres {
		if _, err := secured.Write([]byte{0, 0, 0, 8, 0, 3, 0, 0}); err != nil {
			t.Fatal(err)
		}
		var authenticated [9]byte
		if _, err := io.ReadFull(secured, authenticated[:]); err != nil ||
			authenticated != [9]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0} {
			t.Fatal("native postgres startup transcript changed", authenticated, err)
		}
	}
	return secured
}

func (f *openingRefusalFixture) roundTrip(t *testing.T, conn net.Conn) {
	t.Helper()
	if f.protocol == config.ProtocolHTTP {
		request, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:15432/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := request.Write(conn); err != nil {
			t.Fatal("healthy HTTP visitor write failed", err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), request)
		if err != nil {
			t.Fatal("healthy HTTP visitor response failed", err)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || string(body) != "opening HTTP" {
			t.Fatal("healthy HTTP transcript changed", response.StatusCode, string(body), readErr, closeErr)
		}
		return
	}
	payload := []byte("opening\x00transcript\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal("healthy native visitor write failed", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("healthy native transcript changed", got, err)
	}
}

func TestConnectorOpeningRefusalKeepsPeerAndSameRun(t *testing.T) {
	for _, protocol := range []config.ProtocolName{config.ProtocolTCP, config.ProtocolHTTP, config.ProtocolPostgres} {
		for _, refusal := range []string{"bad-token", "bad-proof", "wrong-source", "wrong-run", "stale", "revoked"} {
			t.Run(string(protocol)+"/"+refusal, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				f := newOpeningRefusalFixture(t, ctx, protocol)
				run := f.bound.prepared.Preparation
				healthyPeer := f.peer(t, ctx, 1, "H")
				healthy := f.serve(t, ctx, healthyPeer, nil, nil)
				rawConnectorControl(t, ctx, healthy.client)
				healthyConn := f.connect(t, ctx, healthy, f.entry(t, healthyPeer, 1, "H"))
				f.roundTrip(t, healthyConn)
				peer := f.peer(t, ctx, 0, "J")
				gate := &permissionOpeningGate{entered: make(chan struct{}), release: make(chan struct{})}
				held := &permissionHeldClose{entered: make(chan struct{}), release: make(chan struct{})}
				release := sync.OnceFunc(func() { close(held.release) })
				observer := &openingRefusalWriteStream{}
				serving := f.serve(t, ctx, peer, func(server muxsession.Session) muxsession.Session {
					writes := &openingRefusalWriteSession{Session: server, selected: 2, stream: observer}
					closes := &permissionHeldSession{Session: writes, held: held}
					return &permissionOpeningSession{Session: closes, ctx: ctx, gate: gate, hold: 2}
				}, func() { gate.open(); release() })
				rawConnectorControl(t, ctx, serving.client)
				entry := f.entry(t, peer, 0, "J")
				want := visitortoken.ErrBinding
				switch refusal {
				case "bad-token":
					entry.Permission.Token += "x"
					openingRefusalSign(t, &entry, f.subjects[0].key)
					want = visitortoken.ErrToken
				case "bad-proof":
					entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				case "wrong-source":
					entry.SourceIP = "192.0.2.99"
					openingRefusalSign(t, &entry, f.subjects[0].key)
				case "wrong-run":
					entry.ServiceRunID = "srun_" + strings.Repeat("Q", 22)
					openingRefusalSign(t, &entry, f.subjects[0].key)
				case "stale":
					want = visitortoken.ErrToken
				}
				resolutions, dials := f.resolutions.Load(), f.target.dials.Load()
				stream := openingRefusalRaw(t, ctx, serving, entry)
				openingRefusalAwait(t, ctx, gate.entered)
				admission := openingRefusalPending(t, peer)
				setupUntil := admission.setupUntil
				if refusal == "stale" {
					f.install(t, 3, 0, 1)
				} else if refusal == "revoked" {
					// keep the signed revision current so removal of the old
					// workload lease, rather than staleness, causes refusal.
					f.install(t, 2, 1, 2)
				}
				view, _, _ := f.bound.prepared.policy.Current()
				if refusal == "revoked" {
					proof, err := visitortoken.VerifyConnectorPeerRenewalProof(entry, nil, peer.bindingSnapshot().expected(), view, time.Now())
					if err != nil || proof.Facts().VisitorPolicyRevision != view.VisitorPolicyRevision {
						t.Fatal("revoked opening lost its valid signature, possession proof or current revision", err)
					}
				}
				if _, err := visitortoken.VerifyConnectorPeerSession(entry, nil, peer.bindingSnapshot().expected(), view, time.Now()); err != want {
					t.Fatal("fixture did not reach its intended initial verifier refusal", err, want)
				}
				gate.open()
				openingRefusalAwait(t, ctx, held.entered)
				openingRefusalNoAcceptance(t, stream)
				f.bound.mu.Lock()
				pending, active := f.bound.connectorPending, f.bound.reservedStreams
				guard, renewals, terminal := admission.guard, admission.renewDone, admission.terminal
				history := len(peer.seen)
				f.bound.mu.Unlock()
				if pending != 1 || active != 1 || guard != nil || renewals != nil || terminal != nil || history != 0 ||
					observer.writes.Load() != 0 || f.resolutions.Load() != resolutions || f.target.dials.Load() != dials {
					t.Fatal("refusal acknowledged, acquired authority, entered target work or released unjoined pending capacity",
						pending, active, history, observer.writes.Load(), f.resolutions.Load(), f.target.dials.Load())
				}
				select {
				case <-admission.joined:
					t.Fatal("refused opening published a join before physical close returned")
				default:
				}
				f.roundTrip(t, healthyConn)
				release()
				openingRefusalAwait(t, ctx, admission.joined)
				// this peer has only the refused opening. joining its actual
				// caller also covers the escalation after forwardPeer returns.
				openingRefusalJoinWorkers(t, ctx, peer)
				f.bound.mu.Lock()
				pending, active = f.bound.connectorPending, f.bound.reservedStreams
				result := admission.joinedOutcome.err
				unchanged := admission.setupUntil.Equal(setupUntil) &&
					f.bound.prepared.Preparation.ServiceId == run.ServiceId &&
					f.bound.prepared.Preparation.ServiceRunId == run.ServiceRunId &&
					f.bound.prepared.Preparation.RunNumber == run.RunNumber
				f.bound.mu.Unlock()
				if !errors.Is(result, want) || pending != 0 || active != 1 || !unchanged {
					t.Fatal("joined refusal lost its cause, exact charges or original run/deadline", result, pending, active, unchanged)
				}
				serving.alive(t)
				healthy.alive(t)
				f.roundTrip(t, healthyConn)
				nextPeer, next := peer, serving
				index := 0
				if refusal == "revoked" {
					index = 2
					nextPeer = f.peer(t, ctx, index, "K")
					next = f.serve(t, ctx, nextPeer, nil, nil)
					rawConnectorControl(t, ctx, next.client)
				}
				nextConn := f.connect(t, ctx, next, f.entry(t, nextPeer, index, "K"))
				f.roundTrip(t, nextConn)
				next.alive(t)
				healthy.alive(t)
			})
		}
	}
}

func TestConnectorOpeningRefusalPhysicalCloseKeepsIndependentFailures(t *testing.T) {
	for _, boundary := range []string{"clean", "independent", "canceled-mixed", "typed-physical", "raw-token"} {
		t.Run(boundary, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			f := newOpeningRefusalFixture(t, ctx, config.ProtocolTCP)
			peer := f.peer(t, ctx, 0, "L")
			independent := errors.New("independent initial opening physical close failure")
			var closeErr error
			var physical *muxsession.QUICTransportCloseError
			switch boundary {
			case "independent":
				closeErr = independent
			case "canceled-mixed":
				closeErr = errors.Join(context.Canceled, independent)
			case "typed-physical":
				physical = &muxsession.QUICTransportCloseError{Err: errors.Join(context.Canceled, independent)}
				closeErr = physical
			case "raw-token":
				closeErr = visitortoken.ErrToken
			}
			gate := &permissionOpeningGate{entered: make(chan struct{}), release: make(chan struct{})}
			held := &permissionHeldClose{entered: make(chan struct{}), release: make(chan struct{}), closeErr: closeErr}
			release := sync.OnceFunc(func() { close(held.release) })
			serving := f.serve(t, ctx, peer, func(server muxsession.Session) muxsession.Session {
				return &permissionOpeningSession{Session: &permissionHeldSession{Session: server, held: held},
					ctx: ctx, gate: gate, hold: 2}
			}, func() { gate.open(); release() })
			rawConnectorControl(t, ctx, serving.client)
			entry := f.entry(t, peer, 0, "L")
			entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			stream := openingRefusalRaw(t, ctx, serving, entry)
			openingRefusalAwait(t, ctx, gate.entered)
			admission := openingRefusalPending(t, peer)
			gate.open()
			openingRefusalAwait(t, ctx, held.entered)
			openingRefusalNoAcceptance(t, stream)
			f.bound.mu.Lock()
			pending, active := f.bound.connectorPending, f.bound.reservedStreams
			f.bound.mu.Unlock()
			if pending != 1 || active != 0 || f.resolutions.Load() != 0 || f.target.dials.Load() != 0 {
				t.Fatal("refusal released pending capacity or touched a target before physical join", pending, active)
			}
			select {
			case <-admission.joined:
				t.Fatal("refusal abandoned its entered physical close")
			default:
			}
			release()
			openingRefusalAwait(t, ctx, admission.joined)
			openingRefusalJoinWorkers(t, ctx, peer)
			if boundary == "clean" {
				serving.alive(t)
				return
			}
			openingRefusalAwait(t, ctx, serving.done)
			if !errors.Is(serving.err, visitortoken.ErrBinding) || !errors.Is(serving.err, closeErr) {
				t.Fatal("initial proof refusal hid an independent physical cause", serving.err)
			}
			if boundary == "canceled-mixed" || boundary == "typed-physical" {
				if !errors.Is(serving.err, context.Canceled) || !errors.Is(serving.err, independent) {
					t.Fatal("physical join lost cancellation or its independent failure", serving.err)
				}
			}
			if physical != nil {
				var retained *muxsession.QUICTransportCloseError
				if !errors.As(serving.err, &retained) || retained != physical {
					t.Fatal("physical close lost its exact typed provenance", serving.err)
				}
			}
			f.bound.mu.Lock()
			pending, active = f.bound.connectorPending, f.bound.reservedStreams
			f.bound.mu.Unlock()
			if pending != 0 || active != 0 || admission.guard != nil {
				t.Fatal("fatal refused opening returned before releasing joined pending capacity", pending, active)
			}
		})
	}
}

func TestConnectorOpeningPositiveAcceptanceWriteFailureRemainsFatal(t *testing.T) {
	for _, protocol := range []config.ProtocolName{config.ProtocolTCP, config.ProtocolHTTP, config.ProtocolPostgres} {
		for _, boundary := range []string{"independent", "raw-token", "canceled-mixed"} {
			t.Run(string(protocol)+"/"+boundary, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				f := newOpeningRefusalFixture(t, ctx, protocol)
				peer := f.peer(t, ctx, 0, "M")
				independent := errors.New("independent positive acceptance write failure")
				writeErr := independent
				if boundary == "raw-token" {
					writeErr = visitortoken.ErrToken
				} else if boundary == "canceled-mixed" {
					writeErr = errors.Join(context.Canceled, independent)
				}
				fault := &openingRefusalWriteStream{ctx: ctx, err: writeErr,
					entered: make(chan struct{}), release: make(chan struct{})}
				fault.armed.Store(true)
				release := sync.OnceFunc(func() { close(fault.release) })
				serving := f.serve(t, ctx, peer, func(server muxsession.Session) muxsession.Session {
					return &openingRefusalWriteSession{Session: server, selected: 2, stream: fault}
				}, release)
				rawConnectorControl(t, ctx, serving.client)
				entry := f.entry(t, peer, 0, "M")
				stream := openingRefusalRaw(t, ctx, serving, entry)
				openingRefusalAwait(t, ctx, fault.entered)
				f.bound.mu.Lock()
				var admission *connectorAdmission
				for candidate := range peer.streams {
					admission = candidate
				}
				valid := admission != nil && admission.guard != nil && admission.admittedLocked() &&
					admission.entry.VisitorConnectionID == entry.VisitorConnectionID &&
					f.bound.connectorPending == 0 && f.bound.reservedStreams == 1 && len(peer.seen) == 1
				f.bound.mu.Unlock()
				if !valid || f.resolutions.Load() != 0 || f.target.dials.Load() != 0 {
					t.Fatal("acceptance fault did not reach the actual post-verification/pre-target write")
				}
				release()
				openingRefusalNoAcceptance(t, stream)
				openingRefusalAwait(t, ctx, admission.joined)
				openingRefusalAwait(t, ctx, serving.done)
				if !errors.Is(serving.err, writeErr) || fault.writes.Load() == 0 {
					t.Fatal("positive acceptance failure became a routine opening refusal", serving.err, fault.writes.Load())
				}
				if boundary == "canceled-mixed" &&
					(!errors.Is(serving.err, context.Canceled) || !errors.Is(serving.err, independent)) {
					t.Fatal("acceptance failure lost a mixed independent cause", serving.err)
				}
				select {
				case <-admission.renewDone:
				default:
					t.Fatal("failed acceptance did not join its already-started renewal worker")
				}
				f.bound.mu.Lock()
				pending, active := f.bound.connectorPending, f.bound.reservedStreams
				f.bound.mu.Unlock()
				if pending != 0 || active != 0 || f.resolutions.Load() != 0 || f.target.dials.Load() != 0 {
					t.Fatal("failed acceptance touched the target or leaked joined charges", pending, active)
				}
			})
		}
	}
}

func TestConnectorOpeningControlWriteFailureRemainsFatal(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	f := newOpeningRefusalFixture(t, ctx, config.ProtocolTCP)
	peer := f.peer(t, ctx, 0, "N")
	independent := errors.New("independent permission control acceptance write failure")
	fault := &openingRefusalWriteStream{ctx: ctx, err: errors.Join(context.Canceled, independent),
		entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(fault.release) })
	serving := f.serve(t, ctx, peer, func(server muxsession.Session) muxsession.Session {
		return &openingRefusalWriteSession{Session: server, selected: 1, stream: fault}
	}, release)
	control := rawConnectorControl(t, ctx, serving.client)
	entry := f.entry(t, peer, 0, "N")
	connection := f.connect(t, ctx, serving, entry)
	f.roundTrip(t, connection)
	admission := permissionAdmission(t, f.bound, peer, entry.VisitorConnectionID)
	next := f.entry(t, peer, 0, "N")
	update := tunnelv1.ConnectorPermissionUpdate{VisitorConnectionID: entry.VisitorConnectionID,
		DeliveryGeneration: entry.DeliveryGeneration, UpdateNumber: 1, Permission: next.Permission}
	fault.armed.Store(true)
	if err := tunnelv1.WriteConnectorPermissionUpdate(control, update); err != nil {
		t.Fatal(err)
	}
	openingRefusalAwait(t, ctx, fault.entered)
	release()
	openingRefusalAwait(t, ctx, serving.done)
	if !errors.Is(serving.err, independent) || !errors.Is(serving.err, context.Canceled) {
		t.Fatal("actual control acceptance write failure lost its independent cause", serving.err)
	}
	var failure *tunnel.ConnectorControlFailure
	if !errors.As(serving.err, &failure) || failure.Origin != tunnel.ConnectorControlWriterFailure {
		t.Fatal("control failure lost its writer origin", serving.err)
	}
	openingRefusalAwait(t, ctx, admission.joined)
	f.bound.mu.Lock()
	pending, active := f.bound.connectorPending, f.bound.reservedStreams
	f.bound.mu.Unlock()
	if pending != 0 || active != 0 {
		t.Fatal("control failure returned before application cleanup joined", pending, active)
	}
}

func TestConnectorOpeningProofRefusalClassificationKeepsIndependentFailures(t *testing.T) {
	for _, sentinel := range []struct {
		name string
		err  error
	}{
		{name: "token", err: visitortoken.ErrToken},
		{name: "binding", err: visitortoken.ErrBinding},
	} {
		t.Run(sentinel.name, func(t *testing.T) {
			independent := errors.New("independent opening cleanup failure")
			refusal := &connectorOpeningProofRefusal{err: sentinel.err}
			physical := &muxsession.QUICTransportCloseError{Err: errors.Join(context.Canceled, independent)}
			physicalCancellation := &muxsession.QUICTransportCloseError{Err: context.Canceled}
			ack := &tunnel.ConnectorControlFailure{Origin: tunnel.ConnectorControlWriterFailure,
				Err: errors.Join(context.Canceled, independent)}
			malformed := &connectorOpeningProofRefusal{err: context.Canceled}
			for _, test := range []struct {
				name    string
				err     error
				routine bool
			}{
				{name: "raw proof", err: sentinel.err},
				{name: "wrapped raw proof", err: fmt.Errorf("other operation: %w", sentinel.err)},
				{name: "raw proof and cancellation", err: errors.Join(sentinel.err, context.Canceled)},
				{name: "exact opening proof", err: refusal, routine: true},
				{name: "wrapped opening proof", err: fmt.Errorf("opening: %w", refusal), routine: true},
				{name: "joined opening proof", err: errors.Join(refusal), routine: true},
				{name: "opening proof and owned cancellation", err: errors.Join(refusal, context.Canceled), routine: true},
				{name: "nested routine causes", err: errors.Join(fmt.Errorf("opening: %w", refusal),
					errors.Join(context.Canceled, io.EOF)), routine: true},
				{name: "opening proof and raw token close", err: errors.Join(refusal, visitortoken.ErrToken)},
				{name: "opening proof and raw binding close", err: errors.Join(refusal, visitortoken.ErrBinding)},
				{name: "opening proof and independent close", err: errors.Join(refusal, independent)},
				{name: "opening proof and mixed cancellation", err: errors.Join(refusal, context.Canceled, independent)},
				{name: "nested independent close", err: errors.Join(refusal,
					fmt.Errorf("close: %w", errors.Join(context.Canceled, independent)))},
				{name: "opening proof and control write failure", err: errors.Join(refusal, ack)},
				{name: "opening proof and raw control token", err: errors.Join(refusal,
					&tunnel.ConnectorControlFailure{Origin: tunnel.ConnectorControlWriterFailure, Err: visitortoken.ErrToken})},
				{name: "opening proof and typed physical failure", err: errors.Join(refusal, physical)},
				{name: "typed physical cancellation", err: physicalCancellation},
				{name: "opening proof and typed physical cancellation", err: errors.Join(refusal, physicalCancellation)},
				{name: "wrapped typed physical failure", err: fmt.Errorf("close: %w", errors.Join(refusal, physical))},
				{name: "physical marker around opening proof", err: &muxsession.QUICTransportCloseError{Err: refusal}},
				{name: "wrapped cause is not exact refusal", err: &connectorOpeningProofRefusal{err: fmt.Errorf("proof: %w", sentinel.err)}},
				{name: "single joined cause is not exact refusal", err: &connectorOpeningProofRefusal{err: errors.Join(sentinel.err)}},
				{name: "joined cancellation is not exact refusal", err: &connectorOpeningProofRefusal{err: errors.Join(sentinel.err, context.Canceled)}},
				{name: "joined independent cause is not exact refusal", err: &connectorOpeningProofRefusal{err: errors.Join(sentinel.err, independent)}},
				{name: "nested marker is not exact refusal", err: &connectorOpeningProofRefusal{err: refusal}},
				{name: "cancellation is not a proof refusal", err: malformed},
				{name: "wrapped malformed marker", err: fmt.Errorf("opening: %w", malformed)},
				{name: "joined malformed marker", err: errors.Join(io.EOF, malformed)},
				{name: "nil cause is not a proof refusal", err: &connectorOpeningProofRefusal{}},
				{name: "policy failure remains raw", err: errors.Join(refusal, visitortoken.ErrPolicy)},
				{name: "key failure remains raw", err: errors.Join(refusal, visitortoken.ErrKey)},
				{name: "tagged policy failure is not a proof refusal", err: &connectorOpeningProofRefusal{err: visitortoken.ErrPolicy}},
				{name: "tagged key failure is not a proof refusal", err: &connectorOpeningProofRefusal{err: visitortoken.ErrKey}},
			} {
				t.Run(test.name, func(t *testing.T) {
					if got := connectorAdmissionRoutineError(test.err); got != test.routine {
						t.Fatal("opening provenance changed independent failure classification", got, test.err)
					}
				})
			}
			if refusal.Unwrap() != sentinel.err || refusal.Error() != sentinel.err.Error() {
				t.Fatal("opening refusal changed its exact original cause or message")
			}
			joined := errors.Join(refusal, ack, physical)
			var retained *connectorOpeningProofRefusal
			var retainedPhysical *muxsession.QUICTransportCloseError
			var retainedACK *tunnel.ConnectorControlFailure
			if !errors.Is(joined, sentinel.err) || !errors.Is(joined, independent) || !errors.Is(joined, context.Canceled) ||
				!errors.As(joined, &retained) || retained != refusal ||
				!errors.As(joined, &retainedPhysical) || retainedPhysical != physical ||
				!errors.As(joined, &retainedACK) || retainedACK != ack {
				t.Fatal("opening refusal lost its proof, control, cancellation or typed physical cause", joined)
			}
		})
	}
}
