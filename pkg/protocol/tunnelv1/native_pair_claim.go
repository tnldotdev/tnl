package tunnelv1

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// NativePairLegProof identifies one delivered pair and one exact relay-owned
// publisher slot. source IP is deliberately absent: only the relay socket can
// supply it to the authority. this proof does not admit application streams.
type NativePairLegProof struct {
	PairID                string    `json:"pair_id"`
	DeliveryGeneration    int64     `json:"delivery_generation"`
	ServiceID             string    `json:"service_id"`
	ServiceRunID          string    `json:"service_run_id"`
	RunNumber             int64     `json:"run_number"`
	PublisherIdentityID   string    `json:"publisher_identity_id"`
	ConnectionSlot        int       `json:"connection_slot"`
	PublisherConnectionID string    `json:"publisher_connection_id"`
	AssignmentRevision    int64     `json:"assignment_revision"`
	RelayServiceID        string    `json:"relay_service_id"`
	RelayID               string    `json:"relay_id"`
	RelayRunID            string    `json:"relay_run_id"`
	RelayLeaseRevision    uint64    `json:"relay_lease_revision"`
	RequestedAt           time.Time `json:"requested_at"`
	Nonce                 []byte    `json:"nonce"`
	Signature             []byte    `json:"signature"`
}

var ErrNativePairLegProof = errors.New("tunnelv1: invalid native pair leg proof")

const MaxNativePairLegProofBytes = 4 << 10

// Message is signed with the enrolled connector key, independent of pair
// preparation and visitor opening proofs. the signature is never part of it.
func (p NativePairLegProof) Message() ([]byte, error) {
	if !opaqueid.Valid(p.PairID, "npp_") || p.DeliveryGeneration < 1 ||
		!opaqueid.Valid(p.ServiceID, opaqueid.ServicePrefix) || !opaqueid.Valid(p.ServiceRunID, opaqueid.ServiceRunPrefix) ||
		!opaqueid.Valid(p.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || p.RunNumber < 1 ||
		(p.ConnectionSlot != 0 && p.ConnectionSlot != 1) ||
		!opaqueid.Valid(p.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) || p.AssignmentRevision < 1 ||
		p.RelayServiceID == "" || len(p.RelayServiceID) > 256 || p.RelayID == "" || len(p.RelayID) > 256 ||
		p.RelayRunID == "" || len(p.RelayRunID) > 256 || p.RelayLeaseRevision == 0 || p.RelayLeaseRevision > 1<<63-1 ||
		p.RequestedAt.IsZero() || len(p.Nonce) != 32 {
		return nil, ErrNativePairLegProof
	}
	body, err := json.Marshal([]any{p.PairID, p.DeliveryGeneration, p.ServiceID, p.ServiceRunID, p.RunNumber,
		p.PublisherIdentityID, p.ConnectionSlot, p.PublisherConnectionID, p.AssignmentRevision,
		p.RelayServiceID, p.RelayID, p.RelayRunID, p.RelayLeaseRevision, p.RequestedAt.UTC().Truncate(time.Microsecond), p.Nonce})
	if err != nil {
		return nil, err
	}
	return append([]byte("tnl native pair leg claim v1\x00"), body...), nil
}

func (p NativePairLegProof) Validate() error {
	if _, err := p.Message(); err != nil || len(p.Signature) != ed25519.SignatureSize {
		return ErrNativePairLegProof
	}
	return nil
}

func WriteNativePairLegProof(w io.Writer, p NativePairLegProof) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, p, MaxNativePairLegProofBytes)
}

func ReadNativePairLegProof(r io.Reader) (NativePairLegProof, error) {
	var p NativePairLegProof
	if err := readJSONFrame(r, &p, MaxNativePairLegProofBytes); err != nil {
		return NativePairLegProof{}, err
	}
	if err := p.Validate(); err != nil {
		return NativePairLegProof{}, err
	}
	return p, nil
}
