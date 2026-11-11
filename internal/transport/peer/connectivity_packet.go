package peer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// each ICE attempt gets a separate envelope key. a delayed frame from an old
// nomination cannot pass a new agent's dispatch filter, even on the same address.
// the retained endpoint's independent replay history is never reset.
func connectivityPacketKey(sessionKey [32]byte, binding ConnectivityBinding, offer, answer tunnelv1.ConnectorPeerConnectivity) [32]byte {
	mac := hmac.New(sha256.New, sessionKey[:])
	_, _ = mac.Write([]byte("tnl connector direct attempt v1\x00"))
	transcript, _ := json.Marshal([]any{binding.Revision, offer, answer})
	_, _ = mac.Write(transcript)
	var key [32]byte
	copy(key[:], mac.Sum(nil))
	return key
}

type connectivityPacketBinding struct {
	key                 [32]byte
	generation, attempt uint64
	role                uint8
}

func (b connectivityPacketBinding) seal(frame []byte) ([]byte, error) {
	return (tunnelv1.ConnectorPeerDirect{Generation: b.generation, Attempt: b.attempt}).Seal(frame, b.key)
}

func (b connectivityPacketBinding) open(packet []byte) ([]byte, bool) {
	bound, frame, err := tunnelv1.OpenConnectorPeerDirect(packet, b.key)
	if err != nil || bound.Generation != b.generation || bound.Attempt != b.attempt {
		return nil, false
	}
	inner, err := tunnelv1.ParsePeerPacket(frame)
	if err != nil || inner.Path != Direct || inner.Sender == b.role || inner.BindingGeneration != b.generation {
		return nil, false
	}
	return frame, true
}

type connectivityCarrier struct {
	Carrier
	binding   connectivityPacketBinding
	admit     func([]byte) bool
	sendAdmit func([]byte) bool
	consent   *connectivityConsent
}

func (c connectivityCarrier) DirectConsent() bool { return c.consent == nil || c.consent.valid() }

func (c connectivityCarrier) Send(ctx context.Context, frame []byte) error {
	if !c.DirectConsent() || c.sendAdmit != nil && !c.sendAdmit(frame) {
		return nil
	}
	packet, err := c.binding.seal(frame)
	if err != nil {
		return err
	}
	return c.Carrier.Send(ctx, packet)
}

func (c connectivityCarrier) Receive(ctx context.Context) ([]byte, error) {
	for {
		packet, err := c.Carrier.Receive(ctx)
		if err != nil {
			return nil, err
		}
		if frame, ok := c.binding.open(packet); ok && c.DirectConsent() && (c.admit == nil || c.admit(frame)) {
			return frame, nil
		}
	}
}
