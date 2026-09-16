package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationRelayLifecycleCleanupCrossesCertificateExpiry(t *testing.T) {
	database, sql := relayLifecycleDatabase(t)
	now := time.Now().UTC().Truncate(time.Second)
	lease, err := database.RegisterRelay(t.Context(), controlstate.RelayRegistration{
		RelayServiceID: "relay-a", RelayID: "relay-a-1", RelayRunID: "relay-a-run", ProtocolVersion: 1,
		RelayAddress: "relay-a.example.test:443", TLSServerName: "relay-a.example.test",
		InternalRelayAddress: "relay-a.internal:9445", ConnectionCapacity: 1, StreamCapacity: 10,
	}, now, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	account, err := database.EnsureACMEAccount(t.Context(), "https://acme.example.test/directory", "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	account, err = database.UpdateACMEAccountRegistration(t.Context(), account.ID, account.ContactEmail, "https://acme.example.test/account/1", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, now, time.Hour); err != nil || !created {
		t.Fatalf("prepare: created %v, error %v", created, err)
	}
	work, found, err := database.ClaimRelayCertificateOrderWork(t.Context(), "worker-initial", now, time.Minute)
	if err != nil || !found {
		t.Fatalf("claim: found %v, error %v", found, err)
	}
	block, _ := pem.Decode(work.PrivateKeyPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := key.(*ecdsa.PrivateKey)
	notBefore, notAfter := now, now.Add(10*time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{work.TLSServerName}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	renewAt := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3).Truncate(time.Microsecond)
	work.CertificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	work.NotBefore, work.NotAfter, work.RenewAt = &notBefore, &notAfter, &renewAt
	work.State = "complete"
	// The real store must still reject expired completion. A permissive stub
	// would hide the cleaning-loop regression this test exercises.
	if _, err := database.SaveRelayCertificateOrderWork(t.Context(), work, notAfter); !errors.Is(err, controlstate.ErrRelayCertificateWorkInvalid) {
		t.Fatalf("expired material was accepted as complete: %v", err)
	}
	work.State = "cleaning"
	work.AuthorizationURL, work.ChallengeURL = "https://acme.example.test/auth/1", "https://acme.example.test/challenge/1"
	work.ChallengeToken, work.PresentationReference = "token", "presentation-1"
	work.ChallengeDigest = sha256.Sum256([]byte("challenge"))
	if _, err := database.SaveRelayCertificateOrderWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	current := notAfter.Add(-time.Second)
	dns := &relayDNSChallengesStub{cleanup: func(context.Context) error {
		current = notAfter
		return nil
	}}
	worker := &RelayWorker{
		store: database,
		config: RelayConfig{WorkerID: "worker-cleanup", AccountID: account.ID, LeaseDuration: time.Minute,
			FailedRetryInterval: time.Hour, DNSChallenges: dns},
		now:    func() time.Time { return current },
		client: func(controlstate.ACMEAccount) (acmeAPI, error) { return &acmeStub{}, nil },
	}
	if found, err := worker.processOne(t.Context()); err != nil || !found {
		t.Fatalf("cleanup: found %v, error %v", found, err)
	}
	var state, lastError string
	var availableAt time.Time
	if err := sql.QueryRow(t.Context(), `SELECT state, last_error, available_at FROM control.relay_certificate_orders WHERE id = $1`, work.ID).Scan(&state, &lastError, &availableAt); err != nil {
		t.Fatal(err)
	}
	if state != "failed" || lastError == "" || dns.cleaned != work.ID || !availableAt.Equal(notAfter.Add(time.Hour)) {
		t.Fatalf("expired cleanup: state %q, error %q, available %v, cleaned %q", state, lastError, availableAt, dns.cleaned)
	}
	if _, err := database.GetRelayServiceCertificate(t.Context(), lease.RelayLeaseIdentity, current); !errors.Is(err, controlstate.ErrRelayServiceCertificateNotFound) {
		t.Fatalf("expired certificate was installed: %v", err)
	}
	for _, at := range []time.Time{current, availableAt.Add(-time.Microsecond), availableAt} {
		created, err := database.PrepareRelayCertificateOrder(t.Context(), account.ID, at, time.Hour)
		if err != nil || created != at.Equal(availableAt) {
			t.Fatalf("replacement at %v: created %v, error %v", at, created, err)
		}
	}
	replacement, found, err := database.ClaimRelayCertificateOrderWork(t.Context(), "worker-replacement", availableAt, time.Minute)
	if err != nil || !found || replacement.ID == work.ID || replacement.State != "pending" {
		t.Fatalf("replacement: found %v, error %v, ID %q, state %q", found, err, replacement.ID, replacement.State)
	}
}

func relayLifecycleDatabase(t *testing.T) (*controlstate.Database, *pgx.Conn) {
	t.Helper()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "relay_lifecycle")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	sql, err := pgx.Connect(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sql.Close(context.Background()) })
	return database, sql
}
