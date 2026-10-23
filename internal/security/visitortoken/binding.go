package visitortoken

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// NativeProofMessage binds permission to one authenticated infrastructure session,
// visitor connection and exact opening bytes. replay exclusion belongs to ingress.
func NativeProofMessage(token Token, session, connection string, initial []byte) ([]byte, error) {
	if len(token.Reveal()) == 0 || len(token.Reveal()) > MaxTokenBytes || !opaqueid.Valid(session, opaqueid.ConnectorSessionPrefix) || !opaqueid.Valid(connection, opaqueid.VisitorConnectionPrefix) || len(initial) > 64<<10 {
		return nil, ErrBinding
	}
	permissionHash, initialHash := sha256.Sum256([]byte(token.Reveal())), sha256.Sum256(initial)
	body, err := json.Marshal(struct {
		Session    string   `json:"session_id"`
		Connection string   `json:"visitor_connection_id"`
		Token      [32]byte `json:"token_sha256"`
		Initial    [32]byte `json:"initial_sha256"`
	}{session, connection, permissionHash, initialHash})
	if err != nil {
		return nil, ErrBinding
	}
	return append([]byte("tnl visitor opening v1\x00"), body...), nil
}

func VerifyNative(token Token, view View, expectedSubject Subject, session, connection string, initial []byte, public ed25519.PublicKey, signature []byte, now time.Time) (Permission, error) {
	permission, err := verify(token, view, now)
	if err != nil {
		return Permission{}, err
	}
	var expectedKey string
	switch subject := permission.Subject.(type) {
	case Device:
		expectedKey = subject.KeySHA256
	case Workload:
		expectedKey = subject.KeySHA256
	default:
		return Permission{}, ErrBinding
	}
	if permission.Subject != expectedSubject {
		return Permission{}, ErrBinding
	}
	digest, err := KeyDigest(public)
	if err != nil || digest != expectedKey || len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return Permission{}, ErrBinding
	}
	message, err := NativeProofMessage(token, session, connection, initial)
	if err != nil || !ed25519.Verify(public, message, signature) {
		return Permission{}, ErrBinding
	}
	return permission, nil
}

func VerifyCertificate(token Token, view View, state tls.ConnectionState, now time.Time) (Permission, error) {
	permission, err := verify(token, view, now)
	if err != nil {
		return Permission{}, err
	}
	subject, ok := permission.Subject.(Certificate)
	if !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 || len(state.PeerCertificates) == 0 || !state.PeerCertificates[0].Equal(state.VerifiedChains[0][0]) {
		return Permission{}, ErrBinding
	}
	leaf := state.PeerCertificates[0]
	digest, err := KeyDigest(leaf.PublicKey)
	if err != nil || digest != subject.KeySHA256 || leaf.SerialNumber == nil || leaf.SerialNumber.Text(16) != subject.Serial || !now.Before(leaf.NotAfter) || now.Before(leaf.NotBefore) || permission.ExpiresAt.After(leaf.NotAfter) {
		return Permission{}, ErrBinding
	}
	return permission, nil
}
