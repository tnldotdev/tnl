package tunnelv1

import (
	"errors"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrNativePairLegAccepted = errors.New("tunnelv1: invalid native pair leg receipt")

// NativePairLegAccepted reports control's exact claim and the source observed
// by the accepting relay socket. it carries no pair key or stream permission.
type NativePairLegAccepted struct {
	PairID             string    `json:"pair_id"`
	DeliveryID         string    `json:"delivery_id"`
	DeliveryGeneration int64     `json:"delivery_generation"`
	ConnectionSlot     int       `json:"connection_slot"`
	SourceIP           string    `json:"source_ip"`
	ExpiresAt          time.Time `json:"expires_at"`
}

func (r NativePairLegAccepted) Validate() error {
	address, err := netip.ParseAddr(r.SourceIP)
	if err != nil || !address.IsValid() || address.IsUnspecified() || address.Zone() != "" || address.Unmap().String() != r.SourceIP ||
		!opaqueid.Valid(r.PairID, "npp_") || r.DeliveryGeneration < 1 || (r.ConnectionSlot != 0 && r.ConnectionSlot != 1) || r.ExpiresAt.IsZero() {
		return ErrNativePairLegAccepted
	}
	if _, err := ParsePeerDeliveryIdentifier(r.DeliveryID); err != nil {
		return ErrNativePairLegAccepted
	}
	return nil
}

// Match checks the receipt against a signed leg and the delivery ID obtained
// from the separately prepared pair. the leg proof's signed bytes stay intact.
func (r NativePairLegAccepted) Match(proof NativePairLegProof, expectedDeliveryID string, now time.Time) error {
	want, err := ParsePeerDeliveryIdentifier(expectedDeliveryID)
	if err != nil || proof.Validate() != nil || r.Validate() != nil || !r.ExpiresAt.After(now) ||
		r.PairID != proof.PairID || r.DeliveryGeneration != proof.DeliveryGeneration || r.ConnectionSlot != proof.ConnectionSlot {
		return ErrNativePairLegAccepted
	}
	got, _ := ParsePeerDeliveryIdentifier(r.DeliveryID)
	if got != want {
		return ErrNativePairLegAccepted
	}
	return nil
}
