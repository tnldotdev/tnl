package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

type Signer struct {
	key *rsa.PrivateKey
}

func NewSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{key: key}
}

func (s *Signer) JWK(kid string) map[string]string {
	return map[string]string{
		"alg": "RS256",
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.key.PublicKey.E)).Bytes()),
		"kid": kid,
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(s.key.PublicKey.N.Bytes()),
		"use": "sig",
	}
}

func (s *Signer) Token(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(encoded))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return encoded + "." + base64.RawURLEncoding.EncodeToString(signature)
}
