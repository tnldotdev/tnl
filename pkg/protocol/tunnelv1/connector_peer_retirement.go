package tunnelv1

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrConnectorPeerPairRetireProof = errors.New("tunnelv1: invalid connector peer pair retirement proof")

const (
	connectorPeerRetireMACDomain = "tnl connector peer pair retire mac v1\x00"
	connectorPeerRetireDomain    = "tnl connector peer pair retire v1\x00"
)

// ConnectorPeerPairRetireProof binds negative-only retirement to one stable pair.
// it reuses the original enrolled signing key and existing endpoint session key.
// current permission, retention, and transaction ownership remain control's job.
type ConnectorPeerPairRetireProof struct {
	ServiceID, ServiceRunID, PublisherIdentityID string
	RunNumber                                    int64
	PairID, DeliveryID, IdempotencyKey           string
	RequestedAt                                  time.Time
}

func (ConnectorPeerPairRetireProof) String() string   { return "connector peer pair retirement proof" }
func (ConnectorPeerPairRetireProof) GoString() string { return "connector peer pair retirement proof" }

func (p ConnectorPeerPairRetireProof) body() ([]byte, error) {
	if !opaqueid.Valid(p.ServiceID, opaqueid.ServicePrefix) || !opaqueid.Valid(p.ServiceRunID, opaqueid.ServiceRunPrefix) ||
		!opaqueid.Valid(p.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(p.PairID, "cpp_") ||
		p.RunNumber < 1 || p.RequestedAt.UTC().Truncate(time.Microsecond).IsZero() ||
		p.IdempotencyKey == "" || len(p.IdempotencyKey) > 128 || !utf8.ValidString(p.IdempotencyKey) ||
		strings.TrimSpace(p.IdempotencyKey) != p.IdempotencyKey || strings.ContainsFunc(p.IdempotencyKey, unicode.IsControl) {
		return nil, ErrConnectorPeerPairRetireProof
	}
	if _, err := ParsePeerDeliveryIdentifier(p.DeliveryID); err != nil {
		return nil, ErrConnectorPeerPairRetireProof
	}
	body, err := json.Marshal([]any{p.ServiceID, p.ServiceRunID, p.RunNumber, p.PublisherIdentityID,
		p.PairID, p.DeliveryID, p.IdempotencyKey, p.RequestedAt.UTC().Truncate(time.Microsecond)})
	if err != nil {
		return nil, ErrConnectorPeerPairRetireProof
	}
	return body, nil
}

// SessionProof authenticates the immutable scope with the stable endpoint key.
// it issues no credential and must never use a relay's per-binding delivery key.
func (p ConnectorPeerPairRetireProof) SessionProof(sessionKey []byte) ([]byte, error) {
	if len(sessionKey) != sha256.Size {
		return nil, ErrConnectorPeerPairRetireProof
	}
	body, err := p.body()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, sessionKey)
	_, _ = mac.Write([]byte(connectorPeerRetireMACDomain))
	_, _ = mac.Write(body)
	return mac.Sum(nil), nil
}

// Message is the sole canonical retirement signature input, including the raw
// session MAC. its scope intentionally excludes mutable network generations.
func (p ConnectorPeerPairRetireProof) Message(sessionProof []byte) ([]byte, error) {
	if len(sessionProof) != sha256.Size {
		return nil, ErrConnectorPeerPairRetireProof
	}
	body, err := p.body()
	if err != nil {
		return nil, err
	}
	message := append([]byte(connectorPeerRetireDomain), body...)
	return append(message, sessionProof...), nil
}

// VerifySignature checks the original stored public-key snapshot, not a current
// parent or a caller-supplied key. verify this before opening the stored secret.
func (p ConnectorPeerPairRetireProof) VerifySignature(publicKey ed25519.PublicKey, sessionProof, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return ErrConnectorPeerPairRetireProof
	}
	message, err := p.Message(sessionProof)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return ErrConnectorPeerPairRetireProof
	}
	return nil
}

// VerifySessionProof requires the second proof even after a valid signature.
// the publisher knows the endpoint key but cannot replace the enrolled signer.
func (p ConnectorPeerPairRetireProof) VerifySessionProof(sessionKey, sessionProof []byte) error {
	if len(sessionProof) != sha256.Size {
		return ErrConnectorPeerPairRetireProof
	}
	expected, err := p.SessionProof(sessionKey)
	if err != nil {
		return err
	}
	defer clear(expected)
	if !hmac.Equal(expected, sessionProof) {
		return ErrConnectorPeerPairRetireProof
	}
	return nil
}

// RequestDigest identifies the canonical full proof for identical lost-reply
// retries. callers authenticate both proofs before using it as a state receipt.
func (p ConnectorPeerPairRetireProof) RequestDigest(sessionProof, signature []byte) ([sha256.Size]byte, error) {
	if len(sessionProof) != sha256.Size || len(signature) != ed25519.SignatureSize {
		return [sha256.Size]byte{}, ErrConnectorPeerPairRetireProof
	}
	body, err := p.body()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	digest := sha256.New()
	_, _ = digest.Write(body)
	_, _ = digest.Write(sessionProof)
	_, _ = digest.Write(signature)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}
