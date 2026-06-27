package servicepki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

func TestServiceCertificateIdentityAndProfiles(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	authority, err := GenerateAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	parsedAuthority, err := ParseAuthority(authority.CertificatePEM, authority.PrivateKeyDER, now)
	if err != nil {
		t.Fatal(err)
	}

	for _, identity := range []Identity{
		{Role: RoleIngress, ProcessID: "ingress-a"},
		{Role: RoleRelay, ProcessID: "relay-1", RelayServiceID: "relay-a"},
	} {
		csr := testCSR(t)
		issued, err := SignServiceCSR(parsedAuthority, identity, csr, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		certificate := testCertificate(t, issued.CertificatePEM)
		got, err := CertificateIdentity(certificate)
		if err != nil {
			t.Fatal(err)
		}
		if got != identity {
			t.Fatalf("identity = %#v, want %#v", got, identity)
		}
		if certificate.NotAfter != now.Add(time.Hour) {
			t.Fatalf("not after = %s", certificate.NotAfter)
		}
		if err := certificate.CheckSignatureFrom(parsedAuthority.Certificate); err != nil {
			t.Fatalf("certificate signature: %v", err)
		}
		if certificate.Subject.CommonName != "" || len(certificate.DNSNames) != 0 {
			t.Fatalf("caller-controlled CSR identity was copied into certificate: %#v", certificate)
		}
	}
}

func TestRelayTransportCertificate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	authority, err := GenerateAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := IssueRelayTransportCertificate(authority, "relay-a.example.test", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certificate := testCertificate(t, issued.CertificatePEM)
	if err := certificate.VerifyHostname("relay-a.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, rest := pem.Decode([]byte(issued.PrivateKeyPEM)); len(rest) != 0 {
		t.Fatal("private key contains trailing data")
	}
}

func TestInternalControlCertificateProfile(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	authority, err := GenerateAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := IssueInternalControlCertificate(authority, RoleIngress, "control.example.test", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certificate := testCertificate(t, issued.CertificatePEM)
	role, err := InternalControlCertificateRole(certificate)
	if err != nil || role != RoleIngress {
		t.Fatalf("internal control role = %q, %v", role, err)
	}
	if err := certificate.VerifyHostname("control.example.test"); err != nil {
		t.Fatal(err)
	}
}

func TestSignServiceCSRRejectsCallerIdentityAndWeakKey(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	authority, err := GenerateAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignServiceCSR(authority, Identity{Role: "control", ProcessID: "process"}, testCSR(t), now, time.Hour); err == nil {
		t.Fatal("invalid role accepted")
	}
	if _, err := SignServiceCSR(authority, Identity{Role: RoleRelay, ProcessID: "relay"}, testCSR(t), now, time.Hour); err == nil {
		t.Fatal("relay without relay service accepted")
	}
}

func testCSR(t *testing.T) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "caller-controlled"},
		DNSNames: []string{"caller.example"},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func testCertificate(t *testing.T, value string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		t.Fatal("certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
