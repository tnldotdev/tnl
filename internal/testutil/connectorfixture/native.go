package connectorfixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var errNativeFixture = errors.New("native connector fixture rejected preparation")

// Native supplies local relay acceptance and an inner QUIC publisher for SDK
// consumers. the target still owns application TLS and authentication. real
// authority, policy and process claims remain covered by the daemon/state tiers.
type Native struct {
	Ready                          controlv1.NativePeerPairReady
	service, run, workload, target string
	ctx                            context.Context
	tls                            *tls.Config
	mu                             sync.Mutex
	pairs                          map[string]*nativePair
	workers                        sync.WaitGroup
}

type nativePair struct {
	response controlv1.NativePeerPair
	public   ed25519.PublicKey
	key      [32]byte
	paths    [2]chan peer.Carrier
	mu       sync.Mutex
	nonces   [2][]byte
	seen     map[string]bool
}

func NewNative(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, service, run, workload, hostname, target string) *Native {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(100), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost", hostname}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	n := &Native{ctx: ctx, service: service, run: run, workload: workload, target: target, pairs: make(map[string]*nativePair), tls: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	n.Ready.PublisherIdentityId, err = opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	var listeners []net.Listener
	t.Cleanup(func() {
		cancel()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		n.workers.Wait()
	})
	for slot := range 2 {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		id, err := opaqueid.New(opaqueid.PublisherConnectionPrefix)
		if err != nil {
			t.Fatal(err)
		}
		runID, err := opaqueid.New(opaqueid.RelayRunPrefix)
		if err != nil {
			t.Fatal(err)
		}
		name := []string{"relay-a", "relay-b"}[slot]
		n.Ready.Relays = append(n.Ready.Relays, controlv1.NativePeerPairRelay{PublisherConnectionId: id, AssignmentRevision: 1, RelayAddress: listener.Addr().String(), TlsServerName: "localhost", RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: name, RelayId: name, RelayRunId: runID, RelayLeaseRevision: 1}})
		n.workers.Go(func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				n.workers.Go(func() { n.accept(connection, slot) })
			}
		})
	}
	return n
}

// Prepare checks the exchanged workload's actual key and exact signed snapshot.
// it does not replace the real control authority assertions in the state tier.
func (n *Native) Prepare(ctx context.Context, body controlv1.NativePeerPairRequest, public ed25519.PublicKey) (controlv1.NativePeerPair, error) {
	message, err := controlv1.NativePeerPairProofMessage(n.service, body)
	signature, decodeErr := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	subject, subjectErr := visitorsubject.Parse(body.Subject)
	if err != nil || decodeErr != nil || subjectErr != nil || subject.Kind != tunnelv1.VisitorWorkloadSession || subject.WorkloadSessionID != n.workload || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, message, signature) || body.ServiceRunId != n.run || body.RunNumber != 1 || body.PublisherIdentityId != n.Ready.PublisherIdentityId || !slices.Equal(body.ExpectedRelays, n.Ready.Relays) {
		return controlv1.NativePeerPair{}, errNativeFixture
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ctx.Err() != nil || ctx.Err() != nil {
		return controlv1.NativePeerPair{}, context.Canceled
	}
	if p := n.pairs[body.IdempotencyKey]; p != nil {
		if !bytes.Equal(p.public, public) || body.Action == "renew" && (body.PreviousPairId == nil || *body.PreviousPairId != p.response.PairId || body.PreviousGeneration == nil || *body.PreviousGeneration != 1) {
			return controlv1.NativePeerPair{}, errNativeFixture
		}
		result := p.response
		result.ObservedAt, result.ExpiresAt = time.Now(), time.Now().Add(time.Minute)
		return result, nil
	}
	if body.Action != "create" {
		return controlv1.NativePeerPair{}, errNativeFixture
	}
	p := &nativePair{public: bytes.Clone(public), seen: make(map[string]bool)}
	var delivery [16]byte
	if _, err := rand.Read(delivery[:]); err != nil {
		return controlv1.NativePeerPair{}, err
	}
	if _, err := rand.Read(p.key[:]); err != nil {
		return controlv1.NativePeerPair{}, err
	}
	id, err := opaqueid.New("npp_")
	if err != nil {
		return controlv1.NativePeerPair{}, err
	}
	p.response = controlv1.NativePeerPair{PairId: id, DeliveryId: base64.RawURLEncoding.EncodeToString(delivery[:]), DeliveryGeneration: 1, Key: base64.RawURLEncoding.EncodeToString(p.key[:]), ServiceId: n.service, ServiceRunId: n.run, RunNumber: 1, PublisherIdentityId: n.Ready.PublisherIdentityId, Subject: body.Subject, Relays: n.Ready.Relays, ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	for slot := range p.paths {
		p.paths[slot] = make(chan peer.Carrier, 1)
	}
	n.pairs[body.IdempotencyKey] = p
	ready := make(chan error, 1)
	n.workers.Go(func() { n.serve(p, ready) })
	select {
	case err := <-ready:
		if err == nil {
			p.response.PublisherPreparedUntil = new(p.response.ExpiresAt)
		}
		return p.response, err
	case <-ctx.Done():
		return controlv1.NativePeerPair{}, context.Cause(ctx)
	}
}

func (n *Native) accept(connection net.Conn, slot int) {
	defer connection.Close()
	stop := context.AfterFunc(n.ctx, func() { _ = connection.Close() })
	defer stop()
	transport, err := muxsession.AcceptTLSYamux(n.ctx, connection, n.tls, muxsession.TLSYamuxConfig{})
	if err != nil {
		return
	}
	defer transport.Close()
	var pair *nativePair
	receipt := func() tunnelv1.NativePairLegAccepted {
		return tunnelv1.NativePairLegAccepted{PairID: pair.response.PairId, DeliveryID: pair.response.DeliveryId, DeliveryGeneration: 1, ConnectionSlot: slot, SourceIP: "127.0.0.1", ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	}
	session, hello, err := tunnel.AcceptWithResult(n.ctx, transport, func(_ context.Context, hello tunnelv1.Message) (*tunnelv1.NativePairLegAccepted, error) {
		n.mu.Lock()
		defer n.mu.Unlock()
		proof := hello.NativePairLegProof
		if proof == nil {
			return nil, errNativeFixture
		}
		for _, p := range n.pairs {
			if p.response.PairId == proof.PairID {
				pair = p
				break
			}
		}
		message, err := proof.Message()
		if pair == nil || err != nil || proof.ConnectionSlot != slot || !ed25519.Verify(pair.public, message, proof.Signature) {
			return nil, errNativeFixture
		}
		r := receipt()
		return &r, nil
	})
	if err != nil {
		return
	}
	packets, err := peer.NewSharedSession(n.ctx, transport)
	if err != nil {
		return
	}
	defer packets.Close()
	id, _ := tunnelv1.ParsePeerDeliveryIdentifier(pair.response.DeliveryId)
	carrier, err := packets.Register(peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: 1}, Key: pair.key, Role: 1, Path: uint8(slot)}, false)
	if err != nil {
		return
	}
	defer carrier.Close()
	_ = session.HandleNativeLegControl(n.ctx, func(_ context.Context, selection tunnelv1.NativeLegBinding) error {
		pair.mu.Lock()
		defer pair.mu.Unlock()
		if len(pair.nonces[slot]) != 0 || !selection.Matches(*hello.NativePairLegProof) {
			return errNativeFixture
		}
		pair.nonces[slot] = bytes.Clone(hello.NativePairLegProof.Nonce)
		pair.paths[slot] <- carrier
		return nil
	}, func(context.Context, tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error) {
		return receipt(), nil
	})
}

func (n *Native) serve(p *nativePair, ready chan<- error) {
	ready <- nil
	var paths [2]peer.Carrier
	for slot, incoming := range p.paths {
		select {
		case paths[slot] = <-incoming:
			defer paths[slot].Close()
		case <-n.ctx.Done():
			return
		}
	}
	packets, err := peer.New(n.ctx, peer.Config{Key: p.key, Role: 1, Paths: paths})
	if err != nil {
		return
	}
	defer packets.Close()
	transport := &quic.Transport{Conn: packets}
	defer transport.Close()
	tlsConfig := n.tls.Clone()
	tlsConfig.NextProtos = []string{muxsession.ALPN}
	listener, err := transport.Listen(tlsConfig, &quic.Config{InitialPacketSize: tunnelv1.MaxPeerPacketBytes, DisablePathMTUDiscovery: true, MaxIncomingStreams: 64})
	if err != nil {
		return
	}
	defer listener.Close()
	connection, err := listener.Accept(n.ctx)
	if err != nil {
		return
	}
	session, err := muxsession.AdoptQUIC(connection)
	if err != nil {
		return
	}
	defer session.Close()
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		stream, err := session.AcceptStream(n.ctx)
		if err != nil {
			return
		}
		workers.Go(func() {
			defer stream.Close()
			stop := context.AfterFunc(n.ctx, func() { _ = stream.Close() })
			defer stop()
			entry, initial, err := tunnelv1.ReadNativePeerVisitorOpening(stream)
			if err != nil {
				return
			}
			public, _ := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.PublicKey)
			signature, _ := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.Signature)
			message, err := tunnelv1.NativePeerProofMessage(entry, initial)
			if err != nil || !bytes.Equal(public, p.public) || !ed25519.Verify(public, message, signature) || !visitorsubject.Equal(p.response.Subject, entry.Subject) || entry.PairID != p.response.PairId || entry.ServiceID != n.service || entry.ServiceRunID != n.run || entry.SourceIP != "127.0.0.1" {
				return
			}
			p.mu.Lock()
			replay := p.seen[entry.VisitorConnectionID]
			p.seen[entry.VisitorConnectionID] = true
			p.mu.Unlock()
			if replay {
				return
			}
			reader := tunnel.NewNativeRequestReader(stream, initial, func(tunnelv1.NativeVisitorPermission) error { return nil })
			defer reader.Finish()
			target, err := (&net.Dialer{Timeout: time.Second}).DialContext(n.ctx, "tcp", n.target)
			if err != nil {
				return
			}
			defer target.Close()
			stopTarget := context.AfterFunc(n.ctx, func() { _ = target.Close() })
			defer stopTarget()
			_, _ = streamcopy.Copy(reader, target)
		})
	}
}
