package controlstate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestIntegrationRelayCertificateOrderWork(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "relay_certificate")
	account, err := database.EnsureACMEAccount(t.Context(), "https://relay-acme.example.test/directory", "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	account, err = database.UpdateACMEAccountRegistration(t.Context(), account.ID, account.ContactEmail, "https://relay-acme.example.test/account/1", "", now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := database.RegisterRelay(t.Context(), relayLifecycleRegistration("relay-certificate"), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, now, time.Hour); err != nil || !created {
		t.Fatalf("prepare relay order = %t, %v", created, err)
	}
	if created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, now, time.Hour); err != nil || created {
		t.Fatalf("duplicate relay order = %t, %v", created, err)
	}
	work, found, err := database.ClaimRelayCertificateOrderWork(t.Context(), "first", now, 10*time.Millisecond)
	if err != nil || !found || work.State != "pending" || work.Account.AccountURL != account.AccountURL || work.RelayServiceID != lease.RelayServiceID || work.TLSServerName != lease.TLSServerName {
		t.Fatalf("claimed relay order = %#v, %t, %v", work, found, err)
	}
	csr, err := x509.ParseCertificateRequest(work.CSRDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(csr.DNSNames, []string{lease.TLSServerName}) {
		t.Fatalf("CSR names = %v", csr.DNSNames)
	}
	var ciphertext []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT private_key_ciphertext FROM control.relay_certificate_orders WHERE id = $1`, work.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, work.PrivateKeyPEM) {
		t.Fatal("relay order key persisted as plaintext")
	}
	if _, found, err := database.ClaimRelayCertificateOrderWork(t.Context(), "other", now, time.Minute); err != nil || found {
		t.Fatalf("concurrent relay order = %t, %v", found, err)
	}
	recovered, found, err := database.ClaimRelayCertificateOrderWork(t.Context(), "other", now.Add(10*time.Millisecond), time.Minute)
	if err != nil || !found || recovered.ID != work.ID || recovered.WorkEpoch != work.WorkEpoch+1 {
		t.Fatalf("recovered relay order = %#v, %t, %v", recovered, found, err)
	}
	work.AvailableAt = now
	if _, err := database.SaveRelayCertificateOrderWork(t.Context(), work, now.Add(11*time.Millisecond)); !errors.Is(err, ErrRelayCertificateWorkStale) {
		t.Fatalf("stale relay order: %v", err)
	}
	recovered.State, recovered.OrderURL, recovered.FinalizeURL = "presenting", "https://relay-acme.example.test/order/1", "https://relay-acme.example.test/finalize/1"
	recovered.AuthorizationURL, recovered.ChallengeURL = "https://relay-acme.example.test/authz/1", "https://relay-acme.example.test/challenge/1"
	recovered.ChallengeToken, recovered.ChallengeDigest = "token", sha256.Sum256([]byte("token"))
	recovered.PresentationReference, recovered.AvailableAt = "relay_acme_presentation_integration", now
	saved, err := database.SaveRelayCertificateOrderWork(t.Context(), recovered, now.Add(11*time.Millisecond))
	if err != nil || saved.OrderRevision != recovered.OrderRevision+1 {
		t.Fatalf("saved relay order = %#v, %v", saved, err)
	}
	challenge, err := database.GetRelayDNSChallengeContext(t.Context(), saved.ID)
	if err != nil || challenge.PresentationReference != recovered.PresentationReference || len(challenge.Presentations) != 1 || !challenge.Presentations[0].Active {
		t.Fatalf("relay challenge = %#v, %v", challenge, err)
	}
	issued, found, err := database.ClaimRelayCertificateOrderWork(t.Context(), "issuance", now.Add(12*time.Millisecond), time.Minute)
	if err != nil || !found || issued.ID != work.ID {
		t.Fatalf("claim issuance = %#v, %t, %v", issued, found, err)
	}
	certificate, notBefore, notAfter := issueRelayOrderCertificate(t, issued, now)
	renewAt := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3).UTC()
	issued.State, issued.CertificateURL, issued.CertificatePEM = "cleaning", "https://relay-acme.example.test/certificate/1", certificate
	issued.NotBefore, issued.NotAfter, issued.RenewAt, issued.AvailableAt = &notBefore, &notAfter, &renewAt, now
	issued, err = database.SaveRelayCertificateOrderWork(t.Context(), issued, now.Add(13*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	challenge, err = database.GetRelayDNSChallengeContext(t.Context(), issued.ID)
	if err != nil || len(challenge.Presentations) != 1 || challenge.Presentations[0].Active {
		t.Fatalf("cleaning relay challenge = %#v, %v", challenge, err)
	}
	issued, found, err = database.ClaimRelayCertificateOrderWork(t.Context(), "cleanup", now.Add(14*time.Millisecond), time.Minute)
	if err != nil || !found {
		t.Fatalf("claim cleanup = %t, %v", found, err)
	}
	issued.State, issued.AvailableAt = "complete", renewAt
	completed, err := database.SaveRelayCertificateOrderWork(t.Context(), issued, now.Add(15*time.Millisecond))
	if err != nil || completed.State != "complete" {
		t.Fatalf("completed relay order = %#v, %v", completed, err)
	}
	installed, err := database.GetRelayTransportCertificate(t.Context(), lease.RelayLeaseIdentity, now.Add(16*time.Millisecond))
	if err != nil || installed.CertificatePEM != string(certificate) || installed.PrivateKeyPEM != string(work.PrivateKeyPEM) {
		t.Fatalf("installed relay certificate differs from issued material: %v", err)
	}
	if created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, now, time.Hour); err != nil || created {
		t.Fatalf("early renewal = %t, %v", created, err)
	}
	if created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, renewAt, time.Hour); err != nil || !created {
		t.Fatalf("due renewal = %t, %v", created, err)
	}
}

func TestIntegrationRelayCertificateRejectsStaleLease(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "relay_certificate_lease")
	lease, err := database.RegisterRelay(t.Context(), relayLifecycleRegistration("relay-certificate"), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	certificate, key := testRelayCertificate(t, lease.TLSServerName, now)
	if _, err := database.StoreRelayTransportCertificate(t.Context(), lease.RelayServiceID, lease.TLSServerName, certificate, key, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetRelayTransportCertificate(t.Context(), lease.RelayLeaseIdentity, now); err != nil {
		t.Fatalf("current lease: %v", err)
	}
	for _, kind := range []string{"run", "revision", "expired"} {
		t.Run(kind, func(t *testing.T) {
			identity, at := lease.RelayLeaseIdentity, now
			switch kind {
			case "run":
				identity.RelayRunID = "stale-run"
			case "revision":
				identity.RelayLeaseRevision++
			case "expired":
				at = lease.LeaseExpiresAt
			}
			if _, err := database.GetRelayTransportCertificate(t.Context(), identity, at); !errors.Is(err, ErrRelayTransportCertificateLeaseStale) {
				t.Fatalf("%s lease: %v", kind, err)
			}
		})
	}
}

func issueRelayOrderCertificate(t *testing.T, work RelayCertificateOrderWork, now time.Time) ([]byte, time.Time, time.Time) {
	t.Helper()
	block, rest := decodeTestPEM(t, work.PrivateKeyPEM, "PRIVATE KEY")
	if len(rest) != 0 {
		t.Fatal("unexpected data after relay order private key")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := value.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("relay order private key type = %T, want ECDSA", value)
	}
	now = now.Truncate(time.Second)
	notBefore, notAfter := now.Add(-time.Minute), now.Add(90*24*time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(43), DNSNames: []string{work.TLSServerName}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), notBefore, notAfter
}

func testRelayCertificate(t *testing.T, hostname string, now time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), DNSNames: []string{hostname}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
