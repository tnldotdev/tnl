package tunnelv1

import (
	"crypto/ed25519"
	"encoding/base64"
)

// NativeVisitorPermission carries a signed visit and proof for one opening.
// its key must match the signed subject and the authenticated connector session.
type NativeVisitorPermission struct {
	Token     string `json:"visitor_token"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

func (NativeVisitorPermission) String() string   { return "native visitor permission" }
func (NativeVisitorPermission) GoString() string { return "native visitor permission" }

func (p NativeVisitorPermission) valid() bool {
	public, keyErr := base64.RawURLEncoding.Strict().DecodeString(p.PublicKey)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(p.Signature)
	return len(p.Token) > 0 && len(p.Token) <= 2048 && validCredential(p.Token) && keyErr == nil && signatureErr == nil && len(public) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize
}
