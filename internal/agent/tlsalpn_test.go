package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestTLSALPNChallengeCertificate(t *testing.T) {
	digest := sha256.Sum256([]byte("key authorization"))
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	var challenges TLSALPNChallenges
	if err := challenges.Install(TLSALPNChallenge{
		ID:        "challenge-1",
		Hostname:  "route.example",
		Digest:    digest,
		ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatal(err)
	}

	certificate, err := challenges.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      "route.example",
		SupportedProtos: []string{acme.ALPNProto},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.Certificate) != 1 {
		t.Fatalf("certificate chain length = %d; want 1", len(certificate.Certificate))
	}
	leaf := certificate.Leaf
	if leaf == nil {
		t.Fatal("missing parsed leaf certificate")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "route.example" ||
		len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		t.Fatalf("unexpected certificate names: DNS=%v IP=%v email=%v URI=%v", leaf.DNSNames, leaf.IPAddresses, leaf.EmailAddresses, leaf.URIs)
	}
	if leaf.IsCA || !leaf.NotAfter.Equal(expiresAt) {
		t.Fatalf("unexpected CA/expiry: IsCA=%v NotAfter=%s", leaf.IsCA, leaf.NotAfter)
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve.Params().Name != "P-256" {
		t.Fatalf("public key = %T; want ECDSA P-256", leaf.PublicKey)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("unexpected key usage: %v, %v", leaf.KeyUsage, leaf.ExtKeyUsage)
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatalf("self-signature: %v", err)
	}

	var identifiers int
	for _, extension := range leaf.Extensions {
		if !extension.Id.Equal(acmeIdentifierOID) {
			continue
		}
		identifiers++
		if !extension.Critical {
			t.Fatal("ACME identifier extension is not critical")
		}
		var actual []byte
		rest, err := asn1.Unmarshal(extension.Value, &actual)
		if err != nil || len(rest) != 0 {
			t.Fatalf("decode ACME identifier: rest=%x err=%v", rest, err)
		}
		if !bytes.Equal(actual, digest[:]) {
			t.Fatalf("ACME identifier = %x; want %x", actual, digest)
		}
	}
	if identifiers != 1 {
		t.Fatalf("ACME identifier extension count = %d; want 1", identifiers)
	}
}

func TestTLSALPNChallengeSelection(t *testing.T) {
	challenge := TLSALPNChallenge{
		ID:        "challenge-1",
		Hostname:  "route.example",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	var challenges TLSALPNChallenges
	if err := challenges.Install(challenge); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		hello *tls.ClientHelloInfo
	}{
		{name: "nil"},
		{name: "missing SNI", hello: &tls.ClientHelloInfo{SupportedProtos: []string{acme.ALPNProto}}},
		{name: "different SNI", hello: &tls.ClientHelloInfo{ServerName: "other.example", SupportedProtos: []string{acme.ALPNProto}}},
		{name: "non-canonical SNI", hello: &tls.ClientHelloInfo{ServerName: "ROUTE.EXAMPLE", SupportedProtos: []string{acme.ALPNProto}}},
		{name: "ordinary ALPN", hello: &tls.ClientHelloInfo{ServerName: "route.example", SupportedProtos: []string{"h2"}}},
		{name: "mixed ALPN", hello: &tls.ClientHelloInfo{ServerName: "route.example", SupportedProtos: []string{acme.ALPNProto, "h2"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if certificate, err := challenges.GetCertificate(test.hello); certificate != nil || err == nil {
				t.Fatalf("GetCertificate = %v, %v; want nil, error", certificate, err)
			}
		})
	}

	challenges.mu.Lock()
	challenges.byHostname[challenge.Hostname].challenge.ExpiresAt = time.Now().Add(-time.Second)
	challenges.mu.Unlock()
	if certificate, err := challenges.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      challenge.Hostname,
		SupportedProtos: []string{acme.ALPNProto},
	}); certificate != nil || err == nil {
		t.Fatalf("expired GetCertificate = %v, %v; want nil, error", certificate, err)
	}
}

func TestTLSALPNChallengeReplacement(t *testing.T) {
	first := TLSALPNChallenge{ID: "first", Hostname: "route.example", ExpiresAt: time.Now().Add(time.Hour)}
	var challenges TLSALPNChallenges
	if err := challenges.Install(first); err != nil {
		t.Fatal(err)
	}
	before, err := challenges.GetCertificate(challengeHello(first.Hostname))
	if err != nil {
		t.Fatal(err)
	}
	if err := challenges.Install(first); err != nil {
		t.Fatalf("idempotent install: %v", err)
	}
	after, err := challenges.GetCertificate(challengeHello(first.Hostname))
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("idempotent install replaced the certificate")
	}

	conflict := first
	conflict.Digest[0] = 1
	if err := challenges.Install(conflict); err == nil {
		t.Fatal("conflicting challenge ID was accepted")
	}
	second := TLSALPNChallenge{ID: "second", Hostname: first.Hostname, ExpiresAt: time.Now().Add(time.Hour)}
	if err := challenges.Install(second); err != nil {
		t.Fatal(err)
	}
	replacement, err := challenges.GetCertificate(challengeHello(second.Hostname))
	if err != nil {
		t.Fatal(err)
	}
	if replacement == before {
		t.Fatal("replacement retained the old certificate")
	}
	if challenges.Remove(first.ID) {
		t.Fatal("stale challenge removal succeeded")
	}
	if err := challenges.Install(first); err == nil {
		t.Fatal("stale challenge install succeeded")
	}
	if _, err := challenges.GetCertificate(challengeHello(second.Hostname)); err != nil {
		t.Fatalf("stale cleanup removed replacement: %v", err)
	}
	if !challenges.Remove(second.ID) {
		t.Fatal("current challenge removal failed")
	}
	if err := challenges.Install(second); err == nil {
		t.Fatal("removed challenge was reinstalled")
	}
	if certificate, err := challenges.GetCertificate(challengeHello(second.Hostname)); certificate != nil || err == nil {
		t.Fatalf("GetCertificate after removal = %v, %v; want nil, error", certificate, err)
	}
}

func TestTLSALPNChallengesConcurrentAccess(t *testing.T) {
	var challenges TLSALPNChallenges
	var workers sync.WaitGroup
	for index := range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			challenge := TLSALPNChallenge{
				ID:        string(rune('a' + index)),
				Hostname:  "route.example",
				ExpiresAt: time.Now().Add(time.Hour),
			}
			if err := challenges.Install(challenge); err != nil {
				t.Errorf("Install: %v", err)
				return
			}
			_, _ = challenges.GetCertificate(challengeHello(challenge.Hostname))
			challenges.Remove(challenge.ID)
		}()
	}
	workers.Wait()
}

func TestTLSALPNChallengeRejectsInvalidInput(t *testing.T) {
	tests := []TLSALPNChallenge{
		{Hostname: "route.example", ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "id", Hostname: "Route.Example", ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "id", Hostname: "route.example", ExpiresAt: time.Now().Add(-time.Second)},
	}
	for _, challenge := range tests {
		var challenges TLSALPNChallenges
		if err := challenges.Install(challenge); err == nil {
			t.Fatalf("Install(%+v) succeeded", challenge)
		}
	}
}

func challengeHello(hostname string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: hostname, SupportedProtos: []string{acme.ALPNProto}}
}
