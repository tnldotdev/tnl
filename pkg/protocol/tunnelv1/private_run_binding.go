package tunnelv1

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

// PrivateRunKeyBinding is the publisher-signed assertion for one prepared run.
// control reads these identities from the authenticated grant and locked run,
// not from an unchecked request body. the publisher holds the TLS private key.
type PrivateRunKeyBinding struct {
	TeamID              string
	PrivateServiceID    string
	PrivateRunID        string
	RunNumber           uint64
	PublisherIdentityID string
	PublisherGrantID    string
	PublisherKeyID      string
	IdempotencyKey      string
	BindingNonce        []byte
	StreamPublicKey     ed25519.PublicKey
}

// PrivateRunBindingDigest is stable across retries of the same preparation.
// the caller signs this digest with the enrolled publisher identity's key.
func PrivateRunBindingDigest(b PrivateRunKeyBinding) ([]byte, error) {
	if !opaqueid.Valid(b.TeamID, opaqueid.TeamPrefix) ||
		!opaqueid.Valid(b.PrivateServiceID, opaqueid.PrivateServicePrefix) ||
		!opaqueid.Valid(b.PrivateRunID, opaqueid.PrivateRunPrefix) || b.RunNumber == 0 ||
		!opaqueid.Valid(b.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) ||
		!opaqueid.Valid(b.PublisherGrantID, opaqueid.PublisherGrantPrefix) ||
		!opaqueid.Valid(b.PublisherKeyID, opaqueid.PublisherIdentityKeyPrefix) ||
		!validPrivateIdentifier(b.IdempotencyKey) ||
		len(b.BindingNonce) != 32 || len(b.StreamPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("tunnelv1: invalid private run key binding")
	}
	h := sha256.New()
	h.Write([]byte("tnl/private-run-key/v1\x00"))
	for _, field := range [][]byte{
		[]byte(b.TeamID), []byte(b.PrivateServiceID), []byte(b.PrivateRunID),
		[]byte(b.PublisherIdentityID), []byte(b.PublisherGrantID), []byte(b.PublisherKeyID),
		[]byte(b.IdempotencyKey), b.BindingNonce, b.StreamPublicKey,
	} {
		writePrivateBindingField(h, field)
	}
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], b.RunNumber)
	h.Write(number[:])
	return h.Sum(nil), nil
}

func writePrivateBindingField(h hash.Hash, field []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(field)))
	h.Write(length[:])
	h.Write(field)
}

func VerifyPrivateRunKeyBinding(enrolledPublicKey ed25519.PublicKey, binding PrivateRunKeyBinding, signature []byte) bool {
	digest, err := PrivateRunBindingDigest(binding)
	return err == nil && len(enrolledPublicKey) == ed25519.PublicKeySize &&
		len(signature) == ed25519.SignatureSize && ed25519.Verify(enrolledPublicKey, digest, signature)
}
