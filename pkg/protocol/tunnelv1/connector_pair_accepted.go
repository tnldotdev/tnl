package tunnelv1

import (
	"errors"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrConnectorPairLegAccepted = errors.New("tunnelv1: invalid connector pair leg receipt")

// ConnectorPairLegAccepted reports control's exact claim and the source observed
// by the accepting relay socket. it carries no pair key or stream permission.
type ConnectorPairLegAccepted struct {
	PairID             string    `json:"pair_id"`
	DeliveryID         string    `json:"delivery_id"`
	DeliveryGeneration int64     `json:"delivery_generation"`
	ConnectionSlot     int       `json:"connection_slot"`
	SourceIP           string    `json:"source_ip"`
	ObservedAt         time.Time `json:"observed_at"`
	ExpiresAt          time.Time `json:"expires_at"`
}

func (r ConnectorPairLegAccepted) Validate() error {
	address, err := netip.ParseAddr(r.SourceIP)
	if err != nil || !address.IsValid() || address.IsUnspecified() || address.Zone() != "" || address.Unmap().String() != r.SourceIP ||
		!opaqueid.Valid(r.PairID, "cpp_") || r.DeliveryGeneration < 1 || (r.ConnectionSlot != 0 && r.ConnectionSlot != 1) ||
		r.ObservedAt.IsZero() || r.ExpiresAt.Sub(r.ObservedAt) <= 0 || r.ExpiresAt.Sub(r.ObservedAt) > 5*time.Minute {
		return ErrConnectorPairLegAccepted
	}
	if _, err := ParsePeerDeliveryIdentifier(r.DeliveryID); err != nil {
		return ErrConnectorPairLegAccepted
	}
	return nil
}

// Match checks the receipt against a signed leg and the delivery ID obtained
// from the separately prepared pair. the leg proof's signed bytes stay intact.
func (r ConnectorPairLegAccepted) Match(proof ConnectorPairLegProof, expectedDeliveryID string, started, now time.Time) error {
	want, err := ParsePeerDeliveryIdentifier(expectedDeliveryID)
	if err != nil || proof.Validate() != nil || r.Validate() != nil || started.IsZero() || started.After(now) || !started.Add(r.ExpiresAt.Sub(r.ObservedAt)).After(now) ||
		r.PairID != proof.PairID || r.DeliveryGeneration != proof.DeliveryGeneration || r.ConnectionSlot != proof.ConnectionSlot {
		return ErrConnectorPairLegAccepted
	}
	got, _ := ParsePeerDeliveryIdentifier(r.DeliveryID)
	if got != want {
		return ErrConnectorPairLegAccepted
	}
	return nil
}
