// package managedcert replaces only the external CA exchange in state tests.
// runtime topology tests use the configured ACME worker and Pebble.
package managedcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func Install(t *testing.T, d *controlstate.Database, prep controlstate.PrivateRunPreparation, run controlstate.PrivateRunState, now time.Time) {
	t.Helper()
	ctx := t.Context()
	const directory = "https://acme.example.test/directory"
	account, err := d.EnsureACMEAccount(ctx, directory, "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.UpdateACMEAccountRegistration(ctx, account.ID, account.ContactEmail, "https://acme.example.test/account/1", "", now); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: prep.CertificatePlan.Identifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := d.CreatePrivateCertificateIssuance(ctx, run.ServiceID, run.RunID, run.Token, directory, "test-issuance", run.RunNumber, csr, now)
	if err != nil {
		t.Fatalf("create private certificate fixture: %v", err)
	}
	work, found, err := d.ClaimACMEOrderWork(ctx, "managed-state-test", now, time.Minute)
	if err != nil || !found || work.ID != issue.ID {
		t.Fatalf("private work claim: %+v %t %v", work, found, err)
	}
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &issuer.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: prep.CertificatePlan.Identifiers, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	work.State = "waiting_for_install"
	work.NotBefore = &leaf.NotBefore
	work.NotAfter = &leaf.NotAfter
	work.CertificatePEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root})...)
	work.OrderURL, work.FinalizeURL, work.CertificateURL = "https://acme.example.test/order/"+issue.ID, "https://acme.example.test/finalize/"+issue.ID, "https://acme.example.test/certificate/"+issue.ID
	for _, name := range prep.CertificatePlan.Identifiers {
		expires := now.Add(time.Hour)
		work.Authorizations = append(work.Authorizations, controlstate.ACMEAuthorizationWork{Identifier: name, AuthorizationURL: "https://acme.example.test/auth/" + issue.ID + "/" + name, ChallengeType: "dns-01", ChallengeURL: "https://acme.example.test/challenge/" + issue.ID + "/" + name, ChallengeToken: "token", ChallengeDigest: sha256.Sum256([]byte(name)), State: "complete", AvailableAt: now, PresentedAt: &now, ValidatedAt: &now, CleanupCompletedAt: &now, ExpiresAt: &expires})
	}
	if _, err = d.SaveACMEOrderWork(ctx, work, now); err != nil {
		t.Fatalf("save private certificate fixture: %v", err)
	}
	if err = d.MarkPrivateCertificateInstalled(ctx, run.ServiceID, run.RunID, run.Token, issue.ID, run.RunNumber, leaf.NotAfter, now); err != nil {
		t.Fatalf("install private certificate fixture: %v", err)
	}
}
