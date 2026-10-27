package service

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func peerAdmissionFixture(t *testing.T, b *Bound) PeerBinding {
	t.Helper()
	binding := PeerBinding{pairID: "npp_" + strings.Repeat("a", 22), serviceID: b.prepared.Preparation.ServiceId,
		serviceRunID: b.prepared.Preparation.ServiceRunId, publisherIdentityID: b.prepared.Preparation.PublisherIdentityId,
		runNumber: b.prepared.Preparation.RunNumber, generation: 1, subject: visitorsubject.Wire(nativeFixtureSubject()),
		deliveryID: [16]byte{1}, key: [32]byte{2}, sourceIP: netip.MustParseAddr("192.0.2.10"), expiresAt: time.Now().Add(time.Minute)}
	for slot, a := range b.connections {
		binding.relays[slot] = controlv1.NativePeerPairRelay{PublisherConnectionId: a.PublisherConnectionId,
			AssignmentRevision: a.ConnectionAssignmentRevision, RelayAddress: a.RelayAddress, TlsServerName: a.TlsServerName,
			RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: a.RelayServiceId, RelayId: a.RelayServiceId + "-process", RelayRunId: "run", RelayLeaseRevision: 1}}
	}
	return binding
}

func peerVisitorOpening(t *testing.T, b *Bound, binding PeerBinding, visitor string, initial []byte) tunnelv1.NativePeerVisitorEntry {
	t.Helper()
	ref := b.assignments[b.connections[0].PublisherConnectionId]
	native := nativeFixtureOpening(t, privateHeader(t, ref))
	entry := tunnelv1.NativePeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.NativePeerVisitorStream,
		PairID: binding.pairID, DeliveryID: base64.RawURLEncoding.EncodeToString(binding.deliveryID[:]), DeliveryGeneration: binding.generation,
		ServiceID: binding.serviceID, ServiceRunID: binding.serviceRunID, RunNumber: uint64(binding.runNumber),
		Subject: nativeFixtureSubject(), SourceIP: binding.sourceIP.String(), VisitorConnectionID: visitor, MetadataRevision: uint64(b.prepared.metadataRevision), Permission: native.Permission}
	message, err := tunnelv1.NativePeerProofMessage(entry, initial)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(nativeFixtureKey(), message))
	return entry
}

func TestPeerAdmissionRejectsSubstitutionBeforeTargetDial(t *testing.T) {
	for _, field := range []string{"pair", "source", "token", "signature", "run", "metadata", "first bytes", "policy"} {
		t.Run(field, func(t *testing.T) {
			target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			_, b, _, _ := privateFixture(t, target.Addr().String())
			binding := peerAdmissionFixture(t, b)
			owner, err := b.BindPeer(t.Context(), binding)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			entry := peerVisitorOpening(t, b, binding, "vc_"+strings.Repeat("v", 22), nil)
			var initial []byte
			switch field {
			case "pair":
				entry.PairID = "npp_" + strings.Repeat("z", 22)
			case "source":
				entry.SourceIP = "192.0.2.11"
			case "token":
				entry.Permission.Token = "pair-key-only"
			case "signature":
				entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
			case "run":
				entry.RunNumber++
			case "metadata":
				entry.MetadataRevision++
			case "first bytes":
				initial = []byte("unsigned first bytes")
			case "policy":
				b.prepared.policy.Close()
			}
			client, server := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() { done <- owner.ServeStream(t.Context(), server) }()
			_, _ = tunnelv1.WriteNativePeerVisitorOpening(client, entry, initial)
			if err := <-done; err == nil {
				t.Fatal("substitution admitted a peer visitor")
			}
			b.mu.Lock()
			retained := b.reservedStreams != 0 || len(owner.streams) != 0 || len(owner.seen) != 0
			b.mu.Unlock()
			if retained {
				t.Fatal("denied opening retained capacity or consumed a visitor ID")
			}
			_ = target.SetDeadline(time.Now().Add(10 * time.Millisecond))
			if conn, err := target.Accept(); err == nil {
				_ = conn.Close()
				t.Fatal("unverified opening dialed target")
			}
		})
	}
}

func TestPeerAdmissionSharesRunCapacityAndRetainsReplayFence(t *testing.T) {
	target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	_, b, ref, verification := privateFixture(t, target.Addr().String())
	b.streamCapacity = 1
	binding := peerAdmissionFixture(t, b)
	owner, err := b.BindPeer(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if duplicate, err := b.BindPeer(t.Context(), binding); err == nil {
		duplicate.Close()
		t.Fatal("second relay created an independent replay/capacity owner")
	}
	client, server := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 1)
	go func() { done <- owner.ServeStream(t.Context(), server) }()
	entry := peerVisitorOpening(t, b, binding, "vc_"+strings.Repeat("v", 22), nil)
	if _, err := tunnelv1.WriteNativePeerVisitorOpening(client, entry, nil); err != nil {
		t.Fatal(err)
	}
	secure := tls.Client(tunnel.NewNativeRequestWriter(client), verification)
	if err := secure.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := target.Accept(); accepted <- conn }()
	var backend net.Conn
	select {
	case backend = <-accepted:
		if backend == nil {
			t.Fatal("target accept failed")
		}
	case <-time.After(3 * time.Second):
		_ = target.Close()
		t.Fatal("verified peer did not reach target")
	}
	defer backend.Close()
	if release, ok := b.reserveStream(ref); ok {
		release()
		t.Fatal("ingress and peer paths spent separate run capacity")
	}
	// make capacity available so this duplicate must fail on the shared replay
	// ledger, rather than accidentally passing because the run was full.
	b.mu.Lock()
	b.streamCapacity = 2
	b.mu.Unlock()
	duplicate, duplicateServer := net.Pipe()
	_ = duplicate.SetDeadline(time.Now().Add(time.Second))
	duplicateDone := make(chan error, 1)
	go func() { duplicateDone <- owner.ServeStream(t.Context(), duplicateServer) }()
	_, _ = tunnelv1.WriteNativePeerVisitorOpening(duplicate, entry, nil)
	if err := <-duplicateDone; err == nil {
		t.Fatal("concurrent second carrier replayed an admitted visitor")
	}
	_ = duplicate.Close()
	select {
	case <-done:
		t.Fatal("rejected duplicate stopped the admitted stream")
	default:
	}
	exchange := make(chan error, 1)
	go func() {
		var buf [4]byte
		_, err := io.ReadFull(backend, buf[:])
		if err == nil && !bytes.Equal(buf[:], []byte("ping")) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = backend.Write(buf[:])
		}
		exchange <- err
	}()
	if _, err := secure.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(secure, reply[:]); err != nil || string(reply[:]) != "ping" {
		t.Fatal("verified peer lost application bytes", err)
	}
	if err := <-exchange; err != nil {
		t.Fatal(err)
	}
	_ = backend.Close()
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("peer stream cleanup did not join")
	}
	replayed, replayServer := net.Pipe()
	defer replayed.Close()
	_ = replayed.SetDeadline(time.Now().Add(time.Second))
	go func() { done <- owner.ServeStream(t.Context(), replayServer) }()
	_, _ = tunnelv1.WriteNativePeerVisitorOpening(replayed, entry, nil)
	if err := <-done; err == nil {
		t.Fatal("released peer visitor was replayed through another carrier")
	}
	if release, ok := b.reserveStream(ref); !ok {
		t.Fatal("closed peer retained live stream capacity")
	} else {
		release()
	}
	owner.Close()
	if replacement, err := b.BindPeer(t.Context(), binding); err == nil {
		replacement.Close()
		t.Fatal("reopening the same delivery discarded its replay fence")
	}
}

func TestPeerAdmissionRunReplacementFencesPeerOwner(t *testing.T) {
	_, b, _, _ := privateFixture(t, "127.0.0.1:1")
	binding := peerAdmissionFixture(t, b)
	owner, err := b.BindPeer(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	next := append([]controlv1.ConnectionAssignment(nil), b.connections[:]...)
	next[0].PublisherConnectionId = "pc_" + strings.Repeat("z", 22)
	next[0].ConnectionAssignmentRevision++
	state := controlv1.ServiceRunState{ServiceId: binding.serviceID, ServiceRunId: binding.serviceRunID,
		RunNumber: binding.runNumber, State: "ready", PublisherExpiresAt: time.Now().Add(time.Minute), PublisherConnections: next}
	if err := b.ApplyHeartbeat(state); err != nil {
		t.Fatal(err)
	}
	select {
	case <-owner.done:
	case <-time.After(time.Second):
		t.Fatal("assignment replacement left peer authority alive")
	}
	if err := owner.Renew(binding); err == nil {
		t.Fatal("old assignment revived a stopped peer")
	}
}

func TestPeerAdmissionFixedDeadlineCancelsAndJoinsPartialOpening(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, b, _, _ := privateFixture(t, "127.0.0.1:1")
		binding := peerAdmissionFixture(t, b)
		owner, err := b.BindPeer(t.Context(), binding)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Close()
		client, server := net.Pipe()
		defer client.Close()
		done := make(chan error, 1)
		go func() { done <- owner.ServeStream(t.Context(), server) }()
		synctest.Wait()
		binding.expiresAt = time.Now().Add(time.Second)
		if err := owner.Renew(binding); err != nil {
			t.Fatal("fresh authority could not shorten live pair", err)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if err := <-done; err == nil {
			t.Fatal("expired peer admitted a partial opening")
		}
		owner.Close()
		binding.expiresAt = time.Now().Add(time.Minute)
		if err := owner.Renew(binding); err == nil {
			t.Fatal("fresh binding revived an expired inner session")
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.reservedStreams != 0 || len(owner.streams) != 0 {
			t.Fatal("expired peer left work or capacity behind")
		}
	})
}
