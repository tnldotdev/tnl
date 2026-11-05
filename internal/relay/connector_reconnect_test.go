package relay

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type reconnectCarrier struct {
	closed chan struct{}
	once   sync.Once
}

func newReconnectCarrier() *reconnectCarrier                         { return &reconnectCarrier{closed: make(chan struct{})} }
func (c *reconnectCarrier) Send(ctx context.Context, _ []byte) error { return ctx.Err() }
func (c *reconnectCarrier) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, net.ErrClosed
	}
}
func (c *reconnectCarrier) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

func reconnectBridgeFixture(t *testing.T) (*connectorBridge, func(byte) (*connectorDelivery, tunnelv1.ConnectorLegBinding)) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	nonce := bytes.Repeat([]byte{1}, 32)
	proof := tunnelv1.ConnectorPairLegProof{PairID: "pair", ServiceRunID: "run", RequestedAt: time.Now(), Nonce: nonce}
	claim := connectorClaim{key: [32]byte{1}, receipt: tunnelv1.ConnectorPairLegAccepted{SourceIP: "192.0.2.1"}}
	b := &connectorBridge{ctx: ctx, cancel: cancel, connector: peer.NewCarrierSlot(), publisher: newReconnectCarrier(), proof: proof, claim: claim, nonce: nonce, selectedAt: proof.RequestedAt, used: map[[32]byte]bool{[32]byte(nonce): true}, until: time.Now().Add(time.Minute)}
	t.Cleanup(func() { cancel(); _ = b.connector.Close(); _ = b.publisher.Close() })
	return b, func(n byte) (*connectorDelivery, tunnelv1.ConnectorLegBinding) {
		life, stop := context.WithCancel(ctx)
		t.Cleanup(stop)
		next := proof
		next.RequestedAt = proof.RequestedAt.Add(time.Duration(n) * time.Microsecond)
		next.Nonce = bytes.Repeat([]byte{n}, 32)
		d := &connectorDelivery{ctx: life, cancel: stop, proof: next, claim: claim, carrier: newReconnectCarrier(), until: b.until.Add(time.Minute)}
		t.Cleanup(func() { _ = d.carrier.Close() })
		return d, tunnelv1.ConnectorLegBinding{Nonce: next.Nonce, PreviousNonce: nonce, ReplacementNonce: bytes.Repeat([]byte{9}, 32)}
	}
}

func TestConnectorBridgeReconnectRecoversLostActivationReply(t *testing.T) {
	b, next := reconnectBridgeFixture(t)
	until, publisher := b.until, b.publisher
	d, selection := next(2)
	if _, err := b.replaceCarrier(t.Context(), d, selection); err != nil {
		t.Fatal(err)
	}
	// the activation committed but its response was lost. a fresh authenticated
	// hello resumes the same handoff, not an unrelated successor operation.
	d.cancel()
	b.detach(d)
	retry, binding := next(3)
	if _, err := b.replaceCarrier(t.Context(), retry, binding); err != nil {
		t.Fatal("lost reply stranded slot", err)
	}
	if b.publisher != publisher || b.until != until || retry.until != until || len(b.used) != 2 {
		t.Fatal("retry replaced publisher, extended authority or spent another handoff")
	}
	if _, err := b.replaceCarrier(t.Context(), d, selection); err == nil {
		t.Fatal("delayed activation replaced its successor")
	}
	newer, advance := next(4)
	advance.PreviousNonce, advance.ReplacementNonce = selection.ReplacementNonce, bytes.Repeat([]byte{10}, 32)
	if _, err := b.replaceCarrier(t.Context(), newer, advance); err != nil {
		t.Fatal(err)
	}
	late, stale := next(5)
	if _, err := b.replaceCarrier(t.Context(), late, stale); err == nil {
		t.Fatal("old handoff revived after a newer predecessor")
	}
	if b.active != newer || b.publisher != publisher || b.until != until {
		t.Fatal("stale retry mutated current bridge")
	}
}

func TestConnectorBridgeReconnectRejectsChangedAuthority(t *testing.T) {
	for _, boundary := range []string{"source", "pair", "run", "assignment", "key", "publisher", "predecessor", "expired", "revoked", "canceled", "stale hello", "budget"} {
		t.Run(boundary, func(t *testing.T) {
			b, next := reconnectBridgeFixture(t)
			d, selection := next(2)
			switch boundary {
			case "source":
				d.claim.receipt.SourceIP = "192.0.2.2"
			case "pair":
				d.proof.PairID = "other"
			case "run":
				d.proof.ServiceRunID = "other"
			case "assignment":
				d.proof.AssignmentRevision++
			case "key":
				d.claim.key[0]++
			case "publisher":
				d.claim.ref.PublisherConnectionID = "other"
			case "predecessor":
				selection.PreviousNonce = bytes.Repeat([]byte{8}, 32)
			case "expired":
				b.until = time.Now().Add(-time.Second)
			case "revoked":
				b.cancel()
			case "canceled":
				d.cancel()
			case "stale hello":
				d.proof.RequestedAt = b.selectedAt
			case "budget":
				for i := byte(0); i < 64; i++ {
					b.used[[32]byte{i}] = true
				}
			}
			generation := b.connector.Generation()
			_, err := b.replaceCarrier(t.Context(), d, selection)
			var rejected *tunnel.ProtocolError
			if !errors.As(err, &rejected) || rejected.Code != tunnelv1.Unauthenticated {
				t.Fatal("rejection lost authority classification", err)
			}
			if b.active != nil || b.connector.Generation() != generation {
				t.Fatal("rejected handoff changed delivery")
			}
		})
	}
}

func TestConnectorBridgeOldDetachCannotRemoveReplacement(t *testing.T) {
	b, next := reconnectBridgeFixture(t)
	old, selection := next(2)
	if _, err := b.replaceCarrier(t.Context(), old, selection); err != nil {
		t.Fatal(err)
	}
	newer, binding := next(3)
	if _, err := b.replaceCarrier(t.Context(), newer, binding); err != nil {
		t.Fatal(err)
	}
	generation := b.connector.Generation()
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() { b.detach(old) })
	}
	workers.Wait()
	if b.active != newer || b.connector.Generation() != generation || newer.ctx.Err() != nil {
		t.Fatal("old cleanup removed successor")
	}
}

type heldReconnectClose struct {
	*reconnectCarrier
	entered, release chan struct{}
}

func (c *heldReconnectClose) Close() error {
	close(c.entered)
	<-c.release
	return c.reconnectCarrier.Close()
}

func TestConnectorBridgeCanceledInstallRetainsHandoffForRetry(t *testing.T) {
	b, next := reconnectBridgeFixture(t)
	held := &heldReconnectClose{reconnectCarrier: newReconnectCarrier(), entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(held.release) })
	defer release()
	if err := b.connector.Install(held); err != nil {
		t.Fatal(err)
	}
	d, selection := next(2)
	done := make(chan error, 1)
	go func() { _, err := b.replaceCarrier(t.Context(), d, selection); done <- err }()
	select {
	case <-held.entered:
	case <-time.After(time.Second):
		t.Fatal("install did not retire old carrier")
	}
	d.cancel()
	release()
	select {
	case err := <-done:
		var unavailable *tunnel.ProtocolError
		if !errors.As(err, &unavailable) || unavailable.Code != tunnelv1.Unavailable {
			t.Fatal("lost candidate became authority rejection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("install failed to join")
	}
	if b.ctx.Err() != nil || b.active != nil {
		t.Fatal("canceled candidate retired bridge")
	}
	retry, binding := next(3)
	if _, err := b.replaceCarrier(t.Context(), retry, binding); err != nil {
		t.Fatal("canceled committed install stranded chain", err)
	}
}
