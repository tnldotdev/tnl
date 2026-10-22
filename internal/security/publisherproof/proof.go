// package publisheridentity owns publisher-held Ed25519 proofs. control owns
// the live grants, short-lived access tokens, and replay exclusion.
package publisherproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
const GrantType = "client_credentials"
const AssertionLifetime = time.Minute

var ErrProof = errors.New("publisher proof is invalid")

type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	Key       string `json:"kid"`
}
type claims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	ID       string `json:"jti"`
	Grant    string `json:"grant_id"`
	Issued   int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}
type Assertion struct {
	ID, KeyID, GrantID string
	Until              time.Time
}

func encode(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }

// sign binds the selected grant in the signed claims as well as in the exchange.
func Sign(clientID, keyID, grantID, audience string, private ed25519.PrivateKey, now time.Time) (string, error) {
	if !fields(clientID, keyID, grantID, audience) || len(private) != ed25519.PrivateKeySize {
		return "", ErrProof
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	message := encode(header{"EdDSA", "JWT", keyID}) + "." + encode(claims{clientID, clientID, audience, base64.RawURLEncoding.EncodeToString(nonce[:]), grantID, now.Unix(), now.Add(AssertionLifetime).Unix()})
	return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(message))), nil
}

func fields(values ...string) bool {
	for _, v := range values {
		if v == "" || len(v) > 2048 || strings.ContainsAny(v, "\x00\r\n") {
			return false
		}
	}
	return true
}

func KeyID(token string) (string, error) {
	if len(token) > 8192 {
		return "", ErrProof
	}
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return "", ErrProof
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(p[0])
	var h header
	if err != nil || len(b) > 1024 || json.Unmarshal(b, &h) != nil || !fields(h.Key) {
		return "", ErrProof
	}
	return h.Key, nil
}

// RotationAudience binds the current-key assertion to the exact replacement
// key. a scoped bearer token alone cannot replace an identity's signing key.
func RotationAudience(audience, replacementID string, public ed25519.PublicKey) string {
	return audience + "#" + replacementID + "." + base64.RawURLEncoding.EncodeToString(public)
}

func Verify(token, clientID, keyID, grantID, audience string, public ed25519.PublicKey, now time.Time) (Assertion, error) {
	if !fields(clientID, keyID, grantID, audience) || len(public) != ed25519.PublicKeySize || len(token) > 8192 {
		return Assertion{}, ErrProof
	}
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return Assertion{}, ErrProof
	}
	hb, he := base64.RawURLEncoding.Strict().DecodeString(p[0])
	cb, ce := base64.RawURLEncoding.Strict().DecodeString(p[1])
	sig, se := base64.RawURLEncoding.Strict().DecodeString(p[2])
	var h header
	var c claims
	if he != nil || ce != nil || se != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(public, []byte(p[0]+"."+p[1]), sig) || json.Unmarshal(hb, &h) != nil || json.Unmarshal(cb, &c) != nil ||
		h.Algorithm != "EdDSA" || h.Type != "JWT" || h.Key != keyID || c.Issuer != clientID || c.Subject != clientID || c.Grant != grantID || c.Audience != audience ||
		len(c.ID) < 24 || len(c.ID) > 128 || !fields(c.ID) || strings.ContainsAny(c.ID, " \t") || c.Issued > now.Unix()+5 || c.Issued < now.Add(-AssertionLifetime).Unix() || c.Expires <= now.Unix() || c.Expires <= c.Issued || c.Expires > c.Issued+60 {
		return Assertion{}, ErrProof
	}
	return Assertion{c.ID, keyID, grantID, time.Unix(c.Expires, 0).UTC()}, nil
}

func runMessage(urlID, retry string) []byte {
	return []byte("tnl publisher run v1\x00" + urlID + "\x00" + retry)
}
func SignRun(private ed25519.PrivateKey, urlID, retry string) (string, error) {
	if len(private) != ed25519.PrivateKeySize || !fields(urlID, retry) {
		return "", ErrProof
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, runMessage(urlID, retry))), nil
}
func VerifyRun(public ed25519.PublicKey, proof, urlID, retry string) ([32]byte, error) {
	if len(public) != ed25519.PublicKeySize || len(proof) != 86 || !fields(urlID, retry) {
		return [32]byte{}, ErrProof
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(proof)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(public, runMessage(urlID, retry), sig) {
		return [32]byte{}, ErrProof
	}
	return sha256.Sum256(append([]byte("tnl publisher run retry v1\x00"), sig...)), nil
}
