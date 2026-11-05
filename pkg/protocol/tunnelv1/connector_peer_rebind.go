package tunnelv1

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrConnectorPeerPairRebindProof = errors.New("tunnelv1: invalid connector peer rebind proof")

const MaxConnectorPeerPairReplyFrameBytes = 256

// ConnectorPeerPairPathProof carries an opposite endpoint's authenticated reply.
// shape validation does not verify its MAC, challenge, freshness, or carrier.
type ConnectorPeerPairPathProof struct {
	ConnectionSlot int    `json:"connection_slot"`
	ProbeNonce     string `json:"probe_nonce"`
	ReplyFrame     string `json:"reply_frame"`
}

func (p ConnectorPeerPairPathProof) Validate() error {
	if p.ConnectionSlot < 0 || p.ConnectionSlot > 1 {
		return ErrConnectorPeerPairRebindProof
	}
	if _, err := rebindBase64(p.ProbeNonce, 16, 16); err != nil {
		return err
	}
	frame, err := rebindBase64(p.ReplyFrame, 1, MaxConnectorPeerPairReplyFrameBytes)
	if err != nil {
		return err
	}
	packet, err := ParsePeerPacket(frame)
	if err != nil || packet.Kind != PeerProbeReply || int(packet.Path) != p.ConnectionSlot {
		return ErrConnectorPeerPairRebindProof
	}
	return nil
}

// ConnectorPeerPairRebindProof names one retained owner and one lifecycle phase.
// source credentials and signatures are deliberately outside the signing value.
type ConnectorPeerPairRebindProof struct {
	Phase, ServiceID, PairID, IdempotencyKey, OperationID string
	ExpectedGeneration                                    int64
	RequestedAt                                           time.Time
	ServiceRunID, PublisherIdentityID                     string
	RunNumber, TrustRevision                              int64
	Subject                                               VisitorSubject
	ExpectedRelays                                        []ConnectorPeerPairRelay
	BindingChallenge                                      string
	PathProofs                                            []ConnectorPeerPairPathProof
}

// Message is the only canonical rebind signing input. empty arrays are always
// encoded as [], and each uncertain phase retry retains its original timestamp.
// this domain and format do not change the original pair preparation proof.
func (p ConnectorPeerPairRebindProof) Message() ([]byte, error) {
	if !opaqueid.Valid(p.ServiceID, opaqueid.ServicePrefix) || !opaqueid.Valid(p.PairID, "cpp_") ||
		!opaqueid.Valid(p.ServiceRunID, opaqueid.ServiceRunPrefix) || !opaqueid.Valid(p.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) ||
		p.RunNumber < 1 || p.TrustRevision < 1 || p.ExpectedGeneration < 1 || p.RequestedAt.IsZero() ||
		!rebindText(p.IdempotencyKey, 128) || p.Subject.Validate() != nil ||
		len(p.ExpectedRelays) > 2 || len(p.PathProofs) > 2 {
		return nil, ErrConnectorPeerPairRebindProof
	}
	if p.Phase != "inspect" && !opaqueid.Valid(p.OperationID, opaqueid.IdempotencyPrefix) {
		return nil, ErrConnectorPeerPairRebindProof
	}
	switch p.Phase {
	case "inspect":
		if p.OperationID != "" || len(p.ExpectedRelays) != 0 || p.BindingChallenge != "" || len(p.PathProofs) != 0 {
			return nil, ErrConnectorPeerPairRebindProof
		}
	case "prepare":
		if p.ExpectedGeneration == math.MaxInt64 || len(p.ExpectedRelays) != 2 || p.BindingChallenge != "" || len(p.PathProofs) != 0 {
			return nil, ErrConnectorPeerPairRebindProof
		}
		for slot, relay := range p.ExpectedRelays {
			ref := ServicePublisherConnectionRef{ServiceID: p.ServiceID, ServiceRunID: p.ServiceRunID, RunNumber: uint64(p.RunNumber),
				PublisherConnectionID: relay.PublisherConnectionID, ConnectionSlot: uint8(slot), ConnectionAssignmentRevision: uint64(relay.AssignmentRevision), RelayServiceID: relay.RelayLease.RelayServiceID}
			if ref.Validate() != nil || relay.AssignmentRevision < 1 || !rebindText(relay.RelayLease.RelayServiceID, 256) ||
				!rebindText(relay.RelayLease.RelayID, 256) || !opaqueid.Valid(relay.RelayLease.RelayRunID, opaqueid.RelayRunPrefix) ||
				relay.RelayLease.RelayLeaseRevision < 1 || relay.RelayLease.RelayLeaseRevision > math.MaxInt64 ||
				!rebindText(relay.RelayAddress, 256) || !rebindText(relay.TLSServerName, 256) {
				return nil, ErrConnectorPeerPairRebindProof
			}
		}
		if p.ExpectedRelays[0].PublisherConnectionID == p.ExpectedRelays[1].PublisherConnectionID ||
			p.ExpectedRelays[0].RelayLease.RelayServiceID == p.ExpectedRelays[1].RelayLease.RelayServiceID {
			return nil, ErrConnectorPeerPairRebindProof
		}
	case "activate":
		if len(p.ExpectedRelays) != 0 || len(p.PathProofs) != 2 {
			return nil, ErrConnectorPeerPairRebindProof
		}
		if _, err := rebindBase64(p.BindingChallenge, 32, 32); err != nil {
			return nil, err
		}
		for slot, proof := range p.PathProofs {
			if proof.ConnectionSlot != slot || proof.Validate() != nil {
				return nil, ErrConnectorPeerPairRebindProof
			}
			frame, _ := base64.RawURLEncoding.DecodeString(proof.ReplyFrame)
			packet, _ := ParsePeerPacket(frame)
			if packet.Sender != 1 {
				return nil, ErrConnectorPeerPairRebindProof
			}
		}
	case "abort":
		if len(p.ExpectedRelays) != 0 || p.BindingChallenge != "" || len(p.PathProofs) != 0 {
			return nil, ErrConnectorPeerPairRebindProof
		}
	default:
		return nil, ErrConnectorPeerPairRebindProof
	}
	relays := append([]ConnectorPeerPairRelay{}, p.ExpectedRelays...)
	proofs := append([]ConnectorPeerPairPathProof{}, p.PathProofs...)
	body, err := json.Marshal([]any{p.Phase, p.ServiceID, p.PairID, p.IdempotencyKey, p.OperationID,
		p.ExpectedGeneration, p.RequestedAt.UTC().Truncate(time.Microsecond), p.ServiceRunID, p.RunNumber,
		p.PublisherIdentityID, p.TrustRevision, p.Subject, relays, p.BindingChallenge, proofs})
	if err != nil {
		return nil, err
	}
	return append([]byte("tnl connector peer rebind v1\x00"), body...), nil
}

func rebindText(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func rebindBase64(value string, minimum, maximum int) ([]byte, error) {
	if len(value) < base64.RawURLEncoding.EncodedLen(minimum) || len(value) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, ErrConnectorPeerPairRebindProof
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(b) < minimum || len(b) > maximum || base64.RawURLEncoding.EncodeToString(b) != value {
		return nil, ErrConnectorPeerPairRebindProof
	}
	return b, nil
}
