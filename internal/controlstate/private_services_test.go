package controlstate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestPrivateServiceSecretsRequireCanonicalRandomBytes(t *testing.T) {
	first, digest, err := privateSecret()
	if err != nil {
		t.Fatal(err)
	}
	second, other, err := privateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || bytes.Equal(digest, other) || len(digest) != 32 {
		t.Fatal("private credentials were reused")
	}
	parsed, err := privateSecretDigest(first)
	if err != nil || !bytes.Equal(parsed, digest) {
		t.Fatalf("valid credential: %v", err)
	}
	for _, invalid := range []string{"", first + "=", first[:len(first)-1], first[:2] + "!" + first[3:]} {
		if _, err := privateSecretDigest(invalid); !errors.Is(err, ErrPrivateServiceAccess) {
			t.Fatalf("accepted noncanonical credential %q: %v", invalid, err)
		}
	}
}

func TestPrivateServiceTrustApprovesOnlyImmutablePublicCASnapshots(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	trust := PrivateServiceTLS{Hostname: "db.internal", PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	seal := func(t *PrivateServiceTLS) {
		mode := "pem"
		if t.System {
			mode = "system"
		}
		digest := sha256.Sum256([]byte(t.Hostname + "\x00" + mode + "\x00" + t.PEM))
		t.Digest = hex.EncodeToString(digest[:])
	}
	seal(&trust)
	if err := (PrivateServiceMetadata{Protocol: "postgres", TLS: &trust}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*PrivateServiceTLS){
		func(t *PrivateServiceTLS) { t.Hostname = "other.internal" },
		func(t *PrivateServiceTLS) { t.PEM += "\nchanged public roots" },
		func(t *PrivateServiceTLS) { t.System = true; seal(t) },
		func(t *PrivateServiceTLS) {
			t.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
			seal(t)
		},
	} {
		invalid := trust
		change(&invalid)
		if err := (PrivateServiceMetadata{Protocol: "postgres", TLS: &invalid}).Validate(); !errors.Is(err, ErrPrivateServiceConflict) {
			t.Fatalf("unapproved or private trust material accepted: %v", err)
		}
	}
}
