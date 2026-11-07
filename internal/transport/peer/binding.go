package peer

import (
	"encoding/base64"
	"net"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// BindingRevision identifies one authenticated control operation, not a new
// peer session. the role owner keeps identity, authority, and expiry separately.
type BindingRevision struct {
	PairID      string
	Generation  int64
	OperationID string
	Challenge   string
}

func (b BindingRevision) valid() bool {
	_, err := tunnelv1.ConnectorPeerBindingProbe(b.PairID, b.OperationID, b.Generation, b.Challenge, 0, 0, make([]byte, 16))
	return err == nil
}

// BindingPathProof carries the exact role-initiated reply observed on a physical
// carrier. strings use canonical unpadded base64url for the control API.
type BindingPathProof = tunnelv1.ConnectorPeerPairPathProof

// SuspendBinding cuts packet input and output without closing inner QUIC or
// changing the revision high-water mark. only a newer staged revision can resume.
func (e *Endpoint) SuspendBinding() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bindingActive = false
	e.bindingPending = false
	e.bindingEpoch++
}

// StageBinding fences both paths before retiring their registrations. duplicates
// do not reset evidence or extend any deadline. callers register new carriers
// only after this returns, then install them through InstallBindingCarrier.
func (e *Endpoint) StageBinding(binding BindingRevision) error {
	e.bindingMu.Lock()
	defer e.bindingMu.Unlock()
	e.mu.Lock()
	if e.ctx.Err() != nil {
		e.mu.Unlock()
		return net.ErrClosed
	}
	if !binding.valid() || e.binding.PairID != "" && binding.PairID != e.binding.PairID || binding.Generation <= e.binding.Generation {
		same := binding == e.binding && e.bindingPending
		e.mu.Unlock()
		if same {
			return nil
		}
		return ErrConfiguration
	}
	for _, p := range e.paths {
		if _, ok := p.carrier.(*CarrierSlot); !ok {
			e.mu.Unlock()
			return ErrConfiguration
		}
	}
	e.binding, e.bindingActive = binding, false
	e.bindingPending = true
	e.bindingEpoch++
	for _, p := range e.paths {
		p.alive, p.challenge, p.proof = false, [16]byte{}, BindingPathProof{}
	}
	e.mu.Unlock()
	for _, p := range e.paths {
		if err := p.carrier.(*CarrierSlot).Install(nil); err != nil {
			return err
		}
	}
	return nil
}

// InstallBindingCarrier transfers ownership even when the revision is stale.
// one serialization lock prevents an older installation from following a newer
// stage. replacing either path invalidates only that path's proof.
func (e *Endpoint) InstallBindingCarrier(binding BindingRevision, index int, carrier Carrier) error {
	e.bindingMu.Lock()
	defer e.bindingMu.Unlock()
	e.mu.Lock()
	if e.ctx.Err() != nil || binding != e.binding || !e.bindingPending || index < 0 || index >= pathCount {
		e.mu.Unlock()
		if carrier != nil {
			_ = carrier.Close()
		}
		return ErrConfiguration
	}
	slot, ok := e.paths[index].carrier.(*CarrierSlot)
	e.mu.Unlock()
	if !ok {
		if carrier != nil {
			_ = carrier.Close()
		}
		return ErrConfiguration
	}
	return slot.Install(carrier)
}

// BindingProofs returns evidence only for the exact staged operation and current
// physical carriers. PathHealthy alone is never sufficient for activation.
func (e *Endpoint) BindingProofs(binding BindingRevision) ([pathCount]BindingPathProof, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.bindingProofsLocked(binding)
}

func (e *Endpoint) bindingProofsLocked(binding BindingRevision) ([pathCount]BindingPathProof, bool) {
	var proofs [pathCount]BindingPathProof
	if e.ctx.Err() != nil || binding != e.binding || !binding.valid() || !e.bindingActive && !e.bindingPending {
		return proofs, false
	}
	now := time.Now()
	for index, p := range e.paths {
		p.refreshRevisionLocked()
		if p.failed || !p.alive || now.Sub(p.ack) > e.config.PathTimeout || p.proof.ReplyFrame == "" {
			return [pathCount]BindingPathProof{}, false
		}
		proofs[index] = p.proof
	}
	return proofs, true
}

// ActivateBinding must be called only after an authenticated control observation
// says this exact operation is active, and after role-specific revalidation.
// local proof success never grants permission to resume packet data by itself.
func (e *Endpoint) ActivateBinding(binding BindingRevision) error {
	e.bindingMu.Lock()
	defer e.bindingMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.bindingPending && !e.bindingActive {
		return ErrConfiguration
	}
	if _, ok := e.bindingProofsLocked(binding); !ok {
		return ErrConfiguration
	}
	e.bindingActive = true
	e.bindingPending = false
	return nil
}

func bindingProof(index int, nonce [16]byte, frame []byte) BindingPathProof {
	return BindingPathProof{ConnectionSlot: index, ProbeNonce: base64.RawURLEncoding.EncodeToString(nonce[:]), ReplyFrame: base64.RawURLEncoding.EncodeToString(frame)}
}
