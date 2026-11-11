package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
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

func reconnectBridgeFixture(t *testing.T) (*connectorBridge, func(uint64) (*connectorDelivery, tunnelv1.ConnectorLegBinding)) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	nonce := bytes.Repeat([]byte{1}, 32)
	proof := tunnelv1.ConnectorPairLegProof{PairID: "pair", ServiceRunID: "run", RequestedAt: time.Now(), Nonce: nonce}
	claim := connectorClaim{key: [32]byte{1}, receipt: tunnelv1.ConnectorPairLegAccepted{BindingState: tunnelv1.ConnectorPeerLegBindingActive, SourceIP: "192.0.2.1"}}
	activation, err := (tunnelv1.ConnectorLegBinding{Nonce: nonce}).Activation()
	if err != nil {
		t.Fatal(err)
	}
	outer := newForwardingTestSession()
	packets, err := peer.NewDispatchedSharedSession(ctx, outer)
	if err != nil {
		t.Fatal(err)
	}
	connector := peer.NewCarrierSlot()
	publisher, err := packets.RegisterForwarding(peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: [16]byte{1}, Generation: 1}, Key: claim.key}, false, connector)
	if err != nil {
		t.Fatal(err)
	}
	b := &connectorBridge{ctx: ctx, cancel: cancel, connector: connector, publisher: publisher, proof: proof, claim: claim, handoff: initialHandoff(activation, proof.RequestedAt), until: time.Now().Add(time.Minute)}
	t.Cleanup(func() {
		cancel()
		_ = b.connector.Close()
		_ = b.publisher.Close()
		_ = packets.Close()
		_ = outer.Close()
	})
	return b, func(n uint64) (*connectorDelivery, tunnelv1.ConnectorLegBinding) {
		life, stop := context.WithCancel(ctx)
		t.Cleanup(stop)
		next := proof
		next.RequestedAt = proof.RequestedAt.Add(time.Duration(n) * time.Microsecond)
		next.Nonce = make([]byte, 32)
		binary.BigEndian.PutUint64(next.Nonce[24:], n)
		d := &connectorDelivery{ctx: life, cancel: stop, proof: next, claim: claim, carrier: newReconnectCarrier(), until: b.until.Add(time.Minute)}
		t.Cleanup(func() { _ = d.carrier.Close() })
		return d, tunnelv1.ConnectorLegBinding{Nonce: next.Nonce, PreviousNonce: nonce, ReplacementNonce: bytes.Repeat([]byte{9}, 32), HandoffRevision: 1}
	}
}

func replaceBridgeBinding(ctx context.Context, b *connectorBridge, d *connectorDelivery, binding tunnelv1.ConnectorLegBinding) (*connectorBridge, error) {
	activation, err := binding.Activation()
	if err != nil {
		return nil, err
	}
	return b.replaceCarrier(ctx, d, activation)
}

func TestConnectorBridgeReconnectRecoversLostActivationReply(t *testing.T) {
	b, next := reconnectBridgeFixture(t)
	until, publisher := b.until, b.publisher
	d, selection := next(2)
	if _, err := replaceBridgeBinding(t.Context(), b, d, selection); err != nil {
		t.Fatal(err)
	}
	// the activation committed but its response was lost. a fresh authenticated
	// hello resumes the same handoff, not an unrelated successor operation.
	d.cancel()
	b.detach(d)
	retry, binding := next(3)
	if _, err := replaceBridgeBinding(t.Context(), b, retry, binding); err != nil {
		t.Fatal("lost reply stranded slot", err)
	}
	if b.publisher != publisher || b.until != until || retry.until != until || b.handoff.operation.Revision() != 1 {
		t.Fatal("retry replaced publisher, extended authority or spent another handoff")
	}
	if _, err := replaceBridgeBinding(t.Context(), b, d, selection); err == nil {
		t.Fatal("delayed activation replaced its successor")
	}
	newer, advance := next(4)
	advance.PreviousNonce, advance.ReplacementNonce = selection.ReplacementNonce, bytes.Repeat([]byte{10}, 32)
	advance.HandoffRevision = 2
	if _, err := replaceBridgeBinding(t.Context(), b, newer, advance); err != nil {
		t.Fatal(err)
	}
	late, stale := next(5)
	if _, err := replaceBridgeBinding(t.Context(), b, late, stale); err == nil {
		t.Fatal("old handoff revived after a newer predecessor")
	}
	if b.active != newer || b.publisher != publisher || b.until != until {
		t.Fatal("stale retry mutated current bridge")
	}
}

func TestConnectorBridgeReconnectRejectsChangedAuthority(t *testing.T) {
	for _, boundary := range []string{"source", "pair", "run", "assignment", "key", "publisher", "predecessor", "expired", "revoked", "canceled", "stale hello", "reused hello", "skipped revision"} {
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
				d.proof.RequestedAt = b.handoff.selectedAt
			case "reused hello":
				d.proof.Nonce = b.proof.Nonce
				selection.Nonce = d.proof.Nonce
			case "skipped revision":
				selection.HandoffRevision = 2
			}
			generation := b.connector.Generation()
			_, err := replaceBridgeBinding(t.Context(), b, d, selection)
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

func TestConnectorBridgeMoreThan64HandoffsRetainsExactRetryAndAuthority(t *testing.T) {
	b, next := reconnectBridgeFixture(t)
	publisher, until := b.publisher, b.until
	hello := uint64(2)
	for revision := tunnelv1.ConnectorHandoffRevision(1); revision <= 96; revision++ {
		// a lost hello does not spend an operation. the next socket authenticates
		// with a fresh signed hello and repeats the same planned operation.
		before := b.handoff
		lost, _ := next(hello)
		hello++
		lost.cancel()
		if b.handoff != before {
			t.Fatal("lost hello changed selected handoff")
		}
		d, binding := next(hello)
		hello++
		previous := b.handoff.selected
		binding.PreviousNonce = append([]byte(nil), previous[:]...)
		binding.ReplacementNonce = make([]byte, 32)
		binary.BigEndian.PutUint64(binding.ReplacementNonce[24:], uint64(revision))
		binding.HandoffRevision = revision
		if _, err := replaceBridgeBinding(t.Context(), b, d, binding); err != nil {
			t.Fatal("handoff failed", revision, err)
		}
		// lose the committed activation reply and retry its exact operation ID
		// on another hello, not a new successor and not a new publisher stream.
		d.cancel()
		b.detach(d)
		retry, _ := next(hello)
		hello++
		binding.Nonce = retry.proof.Nonce
		if _, err := replaceBridgeBinding(t.Context(), b, retry, binding); err != nil {
			t.Fatal("lost activation stranded chain", revision, err)
		}
		if b.publisher != publisher || b.until != until || retry.until != until || b.handoff.operation.Revision() != revision || b.active != retry {
			t.Fatal("handoff changed registration, revision or authority", revision)
		}
	}
}

func TestConnectorBridgeRevisionExhaustionIsNotAuthenticationDenial(t *testing.T) {
	b, next := reconnectBridgeFixture(t)
	op, err := tunnelv1.NewConnectorHandoff(tunnelv1.ConnectorHandoffID{8}, b.handoff.selected, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	b.handoff.operation = op
	d, binding := next(2)
	before := b.handoff
	_, err = replaceBridgeBinding(t.Context(), b, d, binding)
	var exhausted *tunnel.ProtocolError
	if !errors.As(err, &exhausted) || exhausted.Code != tunnelv1.HandoffRevisionExhausted || b.handoff != before || b.active != nil {
		t.Fatal("exhaustion changed state or became an authentication denial", err)
	}
	// exhausting the successor space must not prevent a fresh hello from
	// recovering the final committed operation after a lost response.
	retry, _ := next(3)
	hello, err := tunnelv1.ParseConnectorHelloNonce(retry.proof.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.replaceCarrier(t.Context(), retry, tunnelv1.InitialConnectorActivation(hello).Replacing(op)); err != nil {
		t.Fatal("final operation could not be retried", err)
	}
}

func TestConnectorBridgeRetryCannotRestoreNarrowedOrExpiredAuthority(t *testing.T) {
	b, next := reconnectBridgeFixture(t)
	d, binding := next(2)
	d.until = b.until.Add(-10 * time.Second)
	narrowed := d.until
	if _, err := replaceBridgeBinding(t.Context(), b, d, binding); err != nil {
		t.Fatal(err)
	}
	d.cancel()
	b.detach(d)
	retry, same := next(3)
	if _, err := replaceBridgeBinding(t.Context(), b, retry, same); err != nil {
		t.Fatal(err)
	}
	if b.until != narrowed || retry.until != narrowed {
		t.Fatal("fresh socket claim restored authority lost before its reply")
	}
	b.until = time.Now().Add(-time.Second)
	fresh, same := next(4)
	before, generation := b.handoff, b.connector.Generation()
	if _, err := replaceBridgeBinding(t.Context(), b, fresh, same); err == nil {
		t.Fatal("exact retry resurrected an expired bridge")
	}
	if b.handoff != before || b.active != retry || b.connector.Generation() != generation {
		t.Fatal("expired retry changed selected operation")
	}
}

func TestConnectorBridgeRejectsStaleOrReusedRevisionOnFreshHello(t *testing.T) {
	for _, boundary := range []string{"old operation", "reused revision", "skipped revision", "fresh operation stale hello", "fresh operation reused hello"} {
		t.Run(boundary, func(t *testing.T) {
			b, next := reconnectBridgeFixture(t)
			first, initial := next(2)
			if _, err := replaceBridgeBinding(t.Context(), b, first, initial); err != nil {
				t.Fatal(err)
			}
			current, selected := next(3)
			selected.PreviousNonce, selected.ReplacementNonce = initial.ReplacementNonce, bytes.Repeat([]byte{10}, 32)
			selected.HandoffRevision = 2
			if _, err := replaceBridgeBinding(t.Context(), b, current, selected); err != nil {
				t.Fatal(err)
			}
			candidate, binding := next(4)
			binding.PreviousNonce, binding.ReplacementNonce = selected.ReplacementNonce, bytes.Repeat([]byte{11}, 32)
			binding.HandoffRevision = 3
			switch boundary {
			case "old operation":
				binding.PreviousNonce, binding.ReplacementNonce, binding.HandoffRevision = initial.PreviousNonce, initial.ReplacementNonce, 1
			case "reused revision":
				binding.HandoffRevision = 2
			case "skipped revision":
				binding.HandoffRevision = 4
			case "fresh operation stale hello":
				candidate.proof.RequestedAt = current.proof.RequestedAt
			case "fresh operation reused hello":
				candidate.proof.Nonce = current.proof.Nonce
				binding.Nonce = candidate.proof.Nonce
			}
			before, until, generation := b.handoff, b.until, b.connector.Generation()
			if _, err := replaceBridgeBinding(t.Context(), b, candidate, binding); err == nil {
				t.Fatal("invalid attempt replaced current carrier")
			}
			if b.handoff != before || b.until != until || b.connector.Generation() != generation || b.active != current || current.ctx.Err() != nil {
				t.Fatal("rejected attempt mutated current operation or authority")
			}
		})
	}
}

func TestConnectorBridgeOldDetachCannotRemoveReplacement(t *testing.T) {
	b, next := reconnectBridgeFixture(t)
	old, selection := next(2)
	if _, err := replaceBridgeBinding(t.Context(), b, old, selection); err != nil {
		t.Fatal(err)
	}
	newer, binding := next(3)
	if _, err := replaceBridgeBinding(t.Context(), b, newer, binding); err != nil {
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
	go func() { _, err := replaceBridgeBinding(t.Context(), b, d, selection); done <- err }()
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
	if _, err := replaceBridgeBinding(t.Context(), b, retry, binding); err != nil {
		t.Fatal("canceled committed install stranded chain", err)
	}
}
