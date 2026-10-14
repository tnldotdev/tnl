package publisheridentity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var ErrRunProof = errors.New("publisher run proof is invalid")

func runProofMessage(publicURLID, idempotencyKey string) []byte {
	return []byte("tnl publisher run v1\x00" + publicURLID + "\x00" + idempotencyKey)
}

// SignRun signs one run attempt; the signature also derives its retry secret.
func SignRun(private ed25519.PrivateKey, publicURLID, idempotencyKey string) (string, error) {
	if len(private) != ed25519.PrivateKeySize || publicURLID == "" || idempotencyKey == "" {
		return "", ErrRunProof
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, runProofMessage(publicURLID, idempotencyKey))), nil
}

// VerifyRun binds the retry secret to the registered key, url, and run attempt.
func VerifyRun(public ed25519.PublicKey, proof, publicURLID, idempotencyKey string) ([32]byte, error) {
	if len(public) != ed25519.PublicKeySize || len(proof) != 86 || publicURLID == "" || idempotencyKey == "" {
		return [32]byte{}, ErrRunProof
	}
	signature, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(public, runProofMessage(publicURLID, idempotencyKey), signature) {
		return [32]byte{}, ErrRunProof
	}
	return sha256.Sum256(append([]byte("tnl publisher run retry v1\x00"), signature...)), nil
}
