// Package publisheridentity handles publisher-held signing keys and their
// short-lived oauth client assertions. control owns grants and replay state.
package publisheridentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	GrantType     = "client_credentials"
	assertionTTL  = time.Minute
	maxJWTBytes   = 8192
)

var ErrAssertion = errors.New("publisher client assertion is invalid")

type assertionHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

type assertionClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	ID       string `json:"jti"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

// Assertion identifies the key and one replay-resistant request after proof
// of possession. the caller must claim its ID atomically before issuing a token.
type Assertion struct {
	KeyID string
	ID    string
	Until time.Time
}

func Sign(clientID, keyID, audience string, private ed25519.PrivateKey, now time.Time) (string, error) {
	if clientID == "" || keyID == "" || audience == "" || len(private) != ed25519.PrivateKeySize {
		return "", ErrAssertion
	}
	id := make([]byte, 24)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	encode := func(value any) (string, error) {
		encoded, err := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(encoded), err
	}
	header, err := encode(assertionHeader{Algorithm: "EdDSA", Type: "JWT", KeyID: keyID})
	if err != nil {
		return "", err
	}
	claims, err := encode(assertionClaims{
		Issuer: clientID, Subject: clientID, Audience: audience,
		ID: base64.RawURLEncoding.EncodeToString(id), IssuedAt: now.Unix(), Expires: now.Add(assertionTTL).Unix(),
	})
	if err != nil {
		return "", err
	}
	message := header + "." + claims
	return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(message))), nil
}

// Verify checks RFC 7523 client authentication against one registered key.
// replay exclusion belongs to control's transactional assertion store.
func Verify(token, clientID, audience, keyID string, public ed25519.PublicKey, now time.Time) (Assertion, error) {
	if len(token) > maxJWTBytes || len(public) != ed25519.PublicKeySize || clientID == "" || audience == "" || keyID == "" {
		return Assertion{}, ErrAssertion
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Assertion{}, ErrAssertion
	}
	headerBytes, headerErr := base64.RawURLEncoding.DecodeString(parts[0])
	claimsBytes, claimsErr := base64.RawURLEncoding.DecodeString(parts[1])
	signature, signatureErr := base64.RawURLEncoding.DecodeString(parts[2])
	if headerErr != nil || claimsErr != nil || signatureErr != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
		return Assertion{}, ErrAssertion
	}
	var header assertionHeader
	var claims assertionClaims
	if json.Unmarshal(headerBytes, &header) != nil || json.Unmarshal(claimsBytes, &claims) != nil ||
		header.Algorithm != "EdDSA" || header.Type != "JWT" || header.KeyID != keyID ||
		claims.Issuer != clientID || claims.Subject != clientID || claims.Audience != audience ||
		len(claims.ID) < 24 || len(claims.ID) > 128 || strings.ContainsAny(claims.ID, " \t\n") ||
		claims.IssuedAt > now.Unix()+5 || claims.IssuedAt < now.Add(-assertionTTL).Unix() ||
		claims.Expires <= now.Unix() || claims.Expires > claims.IssuedAt+int64(assertionTTL.Seconds()) {
		return Assertion{}, ErrAssertion
	}
	return Assertion{KeyID: keyID, ID: claims.ID, Until: time.Unix(claims.Expires, 0).UTC()}, nil
}

// KeyID reads only the untrusted key selector. callers must fetch the
// registered key and pass it to Verify before using any assertion fields.
func KeyID(token string) (string, error) {
	if len(token) > maxJWTBytes {
		return "", ErrAssertion
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrAssertion
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(headerBytes) > 1024 {
		return "", ErrAssertion
	}
	var header assertionHeader
	if json.Unmarshal(headerBytes, &header) != nil || header.KeyID == "" || len(header.KeyID) > 128 {
		return "", ErrAssertion
	}
	return header.KeyID, nil
}
