package peer

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func testBinding(generation int64) BindingRevision {
	return BindingRevision{PairID: "cpp_session", Generation: generation, OperationID: "operation", Challenge: "control-challenge"}
}

func awaitBindingProofs(t *testing.T, ctx context.Context, e *Endpoint, binding BindingRevision) [pathCount]BindingPathProof {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if proofs, ok := e.BindingProofs(binding); ok {
			return proofs
		}
		select {
		case <-ctx.Done():
			t.Fatal("binding probes did not complete", ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestPeerBindingStagesBothPathsAndPreservesOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	initial, next := testBinding(17), testBinding(18)
	key := [32]byte{7}
	var slots [2][pathCount]*CarrierSlot
	for side := range slots {
		for index := range slots[side] {
			slots[side][index] = NewCarrierSlot()
		}
	}
	for index := range pathCount {
		a, b := memoryPair()
		if err := slots[0][index].Install(a); err != nil {
			t.Fatal(err)
		}
		if err := slots[1][index].Install(b); err != nil {
			t.Fatal(err)
		}
	}
	var endpoints [2]*Endpoint
	for side := range endpoints {
		e, err := New(ctx, Config{Key: key, Role: uint8(side), Binding: initial, Paths: [pathCount]Carrier{slots[side][0], slots[side][1]}, ProbeInterval: 5 * time.Millisecond, PathTimeout: 50 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		endpoints[side] = e
		defer e.Close()
	}
	left, right := endpoints[0], endpoints[1]
	awaitPath(t, ctx, left, right, RelayA)
	if _, err := left.WriteTo([]byte("before the cut"), left.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	var stale queuedPacket
	select {
	case stale = <-right.input:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	sequence, oldEpoch := left.seq.Load(), left.bindingEpoch
	for _, e := range endpoints {
		if err := e.StageBinding(next); err != nil {
			t.Fatal(err)
		}
		if e.ctx.Err() != nil || e.config.Key != key {
			t.Fatal("staging ended or rekeyed the peer owner")
		}
	}
	buffer := []byte("unchanged")
	if n, ok := stale.copyTo(buffer); n != 0 || ok || string(buffer) != "unchanged" {
		t.Fatal("dequeued old input committed after the session cut")
	}
	if err := left.ActivateBinding(next); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unproved binding resumed packet data", err)
	}
	for index := range pathCount {
		a, b := memoryPair()
		if err := left.InstallBindingCarrier(next, index, a); err != nil {
			t.Fatal(err)
		}
		if err := right.InstallBindingCarrier(next, index, b); err != nil {
			t.Fatal(err)
		}
	}
	proofs := awaitBindingProofs(t, ctx, left, next)
	awaitBindingProofs(t, ctx, right, next)
	for index, proof := range proofs {
		nonce, err := base64.RawURLEncoding.Strict().DecodeString(proof.ProbeNonce)
		if err != nil || len(nonce) != 16 || proof.ConnectionSlot != index {
			t.Fatal("noncanonical path nonce", err)
		}
		frame, err := base64.RawURLEncoding.Strict().DecodeString(proof.ReplyFrame)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := tunnelv1.VerifyPeerPacketFrame(frame, key)
		challenge, challengeErr := tunnelv1.ConnectorPeerBindingProbe(next.PairID, next.OperationID, next.Generation, next.Challenge, 0, uint8(index), nonce)
		if err != nil || challengeErr != nil || packet.Kind != tunnelv1.PeerProbeReply || packet.Sender != 1 || packet.Path != uint8(index) || packet.BindingGeneration != uint64(next.Generation) || !bytes.Equal(packet.Payload, challenge[:]) {
			t.Fatal("path proof did not bind the operation and initiating role", err, challengeErr)
		}
	}
	// duplicate discovery neither replaces carriers nor discards collected proof.
	if err := left.StageBinding(next); err != nil {
		t.Fatal(err)
	}
	if got, ok := left.BindingProofs(next); !ok || got != proofs {
		t.Fatal("duplicate stage discarded evidence")
	}
	if _, err := left.WriteTo([]byte("not active"), left.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	_ = right.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := right.ReadFrom(make([]byte, 32)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("staged binding carried data", err)
	}
	wrong := next
	wrong.Challenge = "another challenge"
	if err := left.ActivateBinding(wrong); !errors.Is(err, ErrConfiguration) {
		t.Fatal("mismatched control observation resumed data", err)
	}
	for _, e := range endpoints {
		if err := e.ActivateBinding(next); err != nil {
			t.Fatal(err)
		}
		if err := e.StageBinding(initial); !errors.Is(err, ErrConfiguration) {
			t.Fatal("older binding replaced active delivery", err)
		}
	}
	if left.seq.Load() < sequence {
		t.Fatal("staging reset the output sequence")
	}
	// even a frame dequeued after activation cannot inherit the new epoch.
	frame, err := tunnelv1.SignPeerPacketFrame(tunnelv1.PeerPacket{BindingGeneration: 18, Kind: tunnelv1.PeerData, Sequence: left.seq.Add(1), Total: 5, Payload: []byte("stale")}, key)
	if err != nil {
		t.Fatal(err)
	}
	left.paths[0].queue <- queuedFrame{revision: slots[0][0].Generation(), epoch: oldEpoch, data: frame}
	if _, err := left.WriteTo([]byte("same packet owner"), left.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	_ = right.SetReadDeadline(time.Now().Add(time.Second))
	var received [32]byte
	if n, _, err := right.ReadFrom(received[:]); err != nil || string(received[:n]) != "same packet owner" {
		t.Fatal("binding did not resume the original packet owner", n, err, string(received[:]))
	}
	left.SuspendBinding()
	if err := left.ActivateBinding(next); !errors.Is(err, ErrConfiguration) {
		t.Fatal("suspended old delivery resurrected without a newer operation", err)
	}
}

func TestPeerBindingProofRequiresBothCurrentPhysicalCarriers(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	key := [32]byte{7}
	var ends [2]*Endpoint
	for side := range ends {
		e, err := New(ctx, Config{Key: key, Role: uint8(side), Paths: [pathCount]Carrier{NewCarrierSlot(), NewCarrierSlot()}, ProbeInterval: 5 * time.Millisecond, PathTimeout: 50 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		ends[side] = e
		defer e.Close()
		if err := e.StageBinding(testBinding(2)); err != nil {
			t.Fatal(err)
		}
	}
	binding := testBinding(2)
	install := func(index int) {
		t.Helper()
		a, b := memoryPair()
		for side, c := range []Carrier{a, b} {
			if err := ends[side].InstallBindingCarrier(binding, index, c); err != nil {
				t.Fatal(err)
			}
		}
	}
	install(0)
	awaitPath(t, ctx, ends[0], ends[1], 0)
	if _, ok := ends[0].BindingProofs(binding); ok {
		t.Fatal("one healthy path proved both physical carriers")
	}
	install(1)
	before := awaitBindingProofs(t, ctx, ends[0], binding)
	if err := ends[0].InstallBindingCarrier(binding, 0, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := ends[0].BindingProofs(binding); ok {
		t.Fatal("retired carrier evidence remained usable")
	}
	install(0)
	after := awaitBindingProofs(t, ctx, ends[0], binding)
	if before[0].ProbeNonce == after[0].ProbeNonce {
		t.Fatal("replacement reused the physical predecessor's probe nonce")
	}
	older := testBinding(1)
	a, b := memoryPair()
	defer b.Close()
	if err := ends[0].InstallBindingCarrier(older, 0, a); !errors.Is(err, ErrConfiguration) {
		t.Fatal("delayed older carrier installed", err)
	}
	select {
	case <-a.stop:
	default:
		t.Fatal("rejected installation leaked its carrier")
	}
}

func TestPeerBindingActivationRequiresFreshProofs(t *testing.T) {
	binding := testBinding(2)
	endpoint := &Endpoint{ctx: t.Context(), config: Config{PathTimeout: time.Second}, binding: binding, bindingPending: true}
	for index := range pathCount {
		slot := NewCarrierSlot()
		defer slot.Close()
		frame, err := tunnelv1.SignPeerPacketFrame(tunnelv1.PeerPacket{BindingGeneration: 2, Kind: tunnelv1.PeerProbeReply,
			Sender: 1, Path: uint8(index), Sequence: uint64(index + 1), Total: 16, Payload: make([]byte, 16)}, [32]byte{7})
		if err != nil {
			t.Fatal(err)
		}
		endpoint.paths[index] = &path{carrier: slot, revision: slot.Generation(), alive: true, ack: time.Now(), proof: bindingProof(index, [16]byte{1}, frame)}
	}
	if _, ok := endpoint.BindingProofs(binding); !ok {
		t.Fatal("fresh physical-carrier proofs were not available")
	}
	endpoint.paths[1].ack = time.Now().Add(-2 * time.Second)
	if _, ok := endpoint.BindingProofs(binding); ok {
		t.Fatal("expired path proof remained usable")
	}
	if err := endpoint.ActivateBinding(binding); !errors.Is(err, ErrConfiguration) {
		t.Fatal("expired path proof activated delivery", err)
	}
	endpoint.paths[1].ack, endpoint.paths[1].alive = time.Now(), false
	if _, ok := endpoint.BindingProofs(binding); ok {
		t.Fatal("unhealthy path proof remained usable")
	}
}

func TestPeerBindingRetainsInnerQUICAndOpenStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	initial, next := testBinding(1), testBinding(2)
	var ends [2]*Endpoint
	for side := range ends {
		e, err := New(ctx, Config{Key: [32]byte{7}, Role: uint8(side), Binding: initial, Paths: [pathCount]Carrier{NewCarrierSlot(), NewCarrierSlot()}, ProbeInterval: 5 * time.Millisecond, PathTimeout: 50 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		ends[side] = e
		defer e.Close()
	}
	install := func(binding BindingRevision, staged bool) {
		t.Helper()
		for index := range pathCount {
			a, b := memoryPair()
			for side, carrier := range []Carrier{a, b} {
				var err error
				if staged {
					err = ends[side].InstallBindingCarrier(binding, index, carrier)
				} else {
					err = ends[side].paths[index].carrier.(*CarrierSlot).Install(carrier)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	install(initial, false)
	client, server := &quic.Transport{Conn: ends[0]}, &quic.Transport{Conn: ends[1]}
	defer client.Close()
	defer server.Close()
	serverTLS, clientTLS := peerTLS(t)
	config := &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, MaxIdleTimeout: 30 * time.Second}
	listener, err := server.Listen(serverTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connection, err := client.Dial(ctx, ends[0].RemoteAddr(), clientTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(0, "")
	publisher, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.CloseWithError(0, "")
	var streams [2]*quic.Stream
	var incomingStreams [2]*quic.Stream
	var workers sync.WaitGroup
	defer func() {
		for _, stream := range incomingStreams {
			if stream != nil {
				stream.CancelRead(0)
				stream.CancelWrite(0)
			}
		}
		workers.Wait()
	}()
	for index := range streams {
		stream, err := connection.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		streams[index] = stream
		_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := stream.Write([]byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
		incoming, err := publisher.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		incomingStreams[index] = incoming
		workers.Go(func() { _, _ = io.Copy(incoming, incoming) })
		var first [1]byte
		if _, err := io.ReadFull(stream, first[:]); err != nil || first[0] != byte(index) {
			t.Fatal("initial stream did not exchange bytes", err)
		}
	}
	for _, e := range ends {
		if err := e.StageBinding(next); err != nil {
			t.Fatal(err)
		}
	}
	// there is no keepalive substitute while both registrations are absent.
	if config.KeepAlivePeriod != 0 || connection.Context().Err() != nil || publisher.Context().Err() != nil {
		t.Fatal("binding cut closed QUIC or configured fake keepalives")
	}
	install(next, true)
	for _, e := range ends {
		awaitBindingProofs(t, ctx, e, next)
		if err := e.ActivateBinding(next); err != nil {
			t.Fatal(err)
		}
	}
	for index, stream := range streams {
		value := []byte{byte(index + 10)}
		if _, err := stream.Write(value); err != nil {
			t.Fatal("original stream did not survive the binding change", err)
		}
		var got [1]byte
		if _, err := io.ReadFull(stream, got[:]); err != nil || got[0] != value[0] {
			t.Fatal("original stream state changed", err)
		}
	}
}

func TestPeerSharedBindingRetirementKeepsGenerationHighWater(t *testing.T) {
	for _, datagrams := range []bool{false, true} {
		t.Run(map[bool]string{false: "TLS", true: "QUIC"}[datagrams], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			serverTLS, clientTLS := peerTLS(t)
			var outer muxsession.Session
			if datagrams {
				left, _ := sharedQUICPair(t, ctx, serverTLS, clientTLS)
				outer = left
			} else {
				outer, _ = sharedTLSPair(t, ctx, serverTLS, clientTLS)
			}
			owner, err := NewSharedSession(ctx, outer)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			binding, _ := sharedBinding(t, 1, 0)
			first, err := owner.Register(binding, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Register(binding, true); !errors.Is(err, ErrConfiguration) {
				t.Fatal("retired generation reopened", err)
			}
			binding.Delivery.Generation++
			binding.Key[0] ^= 1
			second, err := owner.Register(binding, true)
			if err != nil {
				t.Fatal("authorized newer binding could not reuse its stable delivery ID", err)
			}
			defer second.Close()
			if _, err := owner.Register(binding, true); !errors.Is(err, ErrConfiguration) {
				t.Fatal("equal live generation replaced its registration", err)
			}
		})
	}
}
