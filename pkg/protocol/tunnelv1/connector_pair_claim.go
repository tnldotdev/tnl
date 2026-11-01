package tunnelv1

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// ConnectorPairLegProof identifies one delivered pair and one exact relay-owned
// publisher slot. source IP is deliberately absent: only the relay socket can
// supply it to the authority. this proof does not admit application streams.
type ConnectorPairLegProof struct {
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

var ErrConnectorPairLegProof = errors.New("tunnelv1: invalid connector pair leg proof")

const MaxConnectorPairLegProofBytes = 4 << 10

// SameLeg compares the immutable binding, not freshness or authorization.
// renewal still requires a fresh signed proof checked by control.
func (p ConnectorPairLegProof) SameLeg(other ConnectorPairLegProof) bool {
	return p.PairID == other.PairID && p.DeliveryGeneration == other.DeliveryGeneration && p.ServiceID == other.ServiceID &&
		p.ServiceRunID == other.ServiceRunID && p.RunNumber == other.RunNumber && p.PublisherIdentityID == other.PublisherIdentityID &&
		p.ConnectionSlot == other.ConnectionSlot && p.PublisherConnectionID == other.PublisherConnectionID && p.AssignmentRevision == other.AssignmentRevision &&
		p.RelayServiceID == other.RelayServiceID && p.RelayID == other.RelayID && p.RelayRunID == other.RelayRunID && p.RelayLeaseRevision == other.RelayLeaseRevision
}

// Message is signed with the enrolled connector key, independent of pair
// preparation and visitor opening proofs. the signature is never part of it.
func (p ConnectorPairLegProof) Message() ([]byte, error) {
	if !opaqueid.Valid(p.PairID, "cpp_") || p.DeliveryGeneration < 1 ||
		!opaqueid.Valid(p.ServiceID, opaqueid.ServicePrefix) || !opaqueid.Valid(p.ServiceRunID, opaqueid.ServiceRunPrefix) ||
		!opaqueid.Valid(p.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || p.RunNumber < 1 ||
		(p.ConnectionSlot != 0 && p.ConnectionSlot != 1) ||
		!opaqueid.Valid(p.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) || p.AssignmentRevision < 1 ||
		p.RelayServiceID == "" || len(p.RelayServiceID) > 256 || p.RelayID == "" || len(p.RelayID) > 256 ||
		p.RelayRunID == "" || len(p.RelayRunID) > 256 || p.RelayLeaseRevision == 0 || p.RelayLeaseRevision > 1<<63-1 ||
		p.RequestedAt.IsZero() || len(p.Nonce) != 32 {
		return nil, ErrConnectorPairLegProof
	}
	body, err := json.Marshal([]any{p.PairID, p.DeliveryGeneration, p.ServiceID, p.ServiceRunID, p.RunNumber,
		p.PublisherIdentityID, p.ConnectionSlot, p.PublisherConnectionID, p.AssignmentRevision,
		p.RelayServiceID, p.RelayID, p.RelayRunID, p.RelayLeaseRevision, p.RequestedAt.UTC().Truncate(time.Microsecond), p.Nonce})
	if err != nil {
		return nil, err
	}
	return append([]byte("tnl connector pair leg claim v1\x00"), body...), nil
}

// RelayClaimMessage binds the connector's signed proof to the source observed
// by the relay socket. control verifies a separate relay-process signature over
// this message before releasing a pair key.
func (p ConnectorPairLegProof) RelayClaimMessage(observedSource netip.Addr) ([]byte, error) {
	message, err := p.Message()
	if err != nil || len(p.Signature) != ed25519.SignatureSize || !observedSource.IsValid() || observedSource.Zone() != "" {
		return nil, ErrConnectorPairLegProof
	}
	address := observedSource.Unmap().AsSlice()
	result := make([]byte, 0, len(message)+len(p.Signature)+len(address)+40)
	result = append(result, "tnl relay connector pair leg claim v1\x00"...)
	result = append(result, message...)
	result = append(result, p.Signature...)
	return append(result, address...), nil
}

func (p ConnectorPairLegProof) Validate() error {
	if _, err := p.Message(); err != nil || len(p.Signature) != ed25519.SignatureSize {
		return ErrConnectorPairLegProof
	}
	return nil
}

func WriteConnectorPairLegProof(w io.Writer, p ConnectorPairLegProof) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, p, MaxConnectorPairLegProofBytes)
}

func ReadConnectorPairLegProof(r io.Reader) (ConnectorPairLegProof, error) {
	var p ConnectorPairLegProof
	if err := readJSONFrame(r, &p, MaxConnectorPairLegProofBytes); err != nil {
		return ConnectorPairLegProof{}, err
	}
	if err := p.Validate(); err != nil {
		return ConnectorPairLegProof{}, err
	}
	return p, nil
}
