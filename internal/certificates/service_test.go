package certificates

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/state"
	legoacme "github.com/go-acme/lego/v5/acme"
	legoapi "github.com/go-acme/lego/v5/acme/api"
)

const (
	testRouteID  = "route_0123456789abcdef0123456789abcdef"
	testHostname = "unit.tnl.test"
)

func TestServiceCertificateLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	db := testDatabase(t)
	key, csrDER := testCSR(t, testHostname, pkix.Name{})
	chain, roots := testCertificateChain(t, key, testHostname, now)
	fake := &fakeACME{now: now, certificate: chain}
	probeCalls := 0
	service, err := New(context.Background(), db, Config{
		DirectoryURL: "https://acme.test/directory",
		Email:        "operator@example.com",
		AcceptTerms:  true,
		Profile:      "tlsserver",
		Roots:        roots,
		Probe: func(_ context.Context, job Job) error {
			probeCalls++
			if job.Hostname != testHostname || job.ChallengeDigest != sha256.Sum256([]byte("key-authorization")) {
				t.Fatalf("unexpected challenge probe: %+v", job)
			}
			return nil
		},
		Now: func() time.Time { return now },
		newACME: func(_ *http.Client, _, kid string, _ crypto.Signer) (acmeClient, error) {
			if kid != "" {
				t.Fatalf("initial account KID = %q", kid)
			}
			return fake, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	job, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != StateWaitingChallenge || job.OrderAttempts != 1 || job.Challenge() == nil {
		t.Fatalf("created job = %+v", job)
	}
	idempotent, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent.ID != job.ID || fake.orders != 1 {
		t.Fatalf("idempotent job ID = %q, orders = %d", idempotent.ID, fake.orders)
	}

	job, err = service.ChallengeReady(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if probeCalls != 1 || job.State != StateWaitingForInstall || len(job.CertificatePEM) == 0 ||
		!job.NotBefore.Equal(now.Add(-time.Hour)) || !job.NotAfter.Equal(now.Add(89*24*time.Hour)) {
		t.Fatalf("validated job = %+v, probes = %d", job, probeCalls)
	}
	if !job.RenewAt.After(job.NotBefore) || !job.RenewAt.Before(job.NotAfter) {
		t.Fatalf("renewal time = %v outside validity", job.RenewAt)
	}
	if _, err := service.Installed(context.Background(), job.ID, testRouteID, 1); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("install before cleanup error = %v", err)
	}
	job, err = service.ChallengeRemoved(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	job, err = service.Installed(context.Background(), job.ID, testRouteID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != StateSucceeded || job.InstalledAt.IsZero() {
		t.Fatalf("installed job = %+v", job)
	}
	_, replacementCSR := testCSR(t, testHostname, pkix.Name{})
	if _, err := service.Create(
		context.Background(), testRouteID, 1, "tlsserver", replacementCSR,
	); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("early replacement error = %v", err)
	}
	for generation := 2; generation <= 5; generation++ {
		if _, err := db.Exec(`UPDATE routes SET generation = ? WHERE id = ?`, generation, testRouteID); err != nil {
			t.Fatal(err)
		}
		reused, err := service.Create(
			context.Background(), testRouteID, uint64(generation), "tlsserver", csrDER,
		)
		if err != nil {
			t.Fatalf("reuse at generation %d: %v", generation, err)
		}
		if reused.State != StateWaitingForInstall || reused.OrderAttempts != 0 || len(reused.CertificatePEM) == 0 {
			t.Fatalf("reused job at generation %d = %+v", generation, reused)
		}
	}
}

func TestServiceReusesPersistedAccountKey(t *testing.T) {
	db := testDatabase(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	var firstPublic, secondPublic []byte
	newClient := func(destination *[]byte) func(*http.Client, string, string, crypto.Signer) (acmeClient, error) {
		return func(_ *http.Client, _, _ string, signer crypto.Signer) (acmeClient, error) {
			encoded, err := x509.MarshalPKIXPublicKey(signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			*destination = encoded
			return &fakeACME{now: now}, nil
		}
	}
	config := Config{
		DirectoryURL: "https://acme.test/directory", Email: "operator@example.com", AcceptTerms: true,
		Profile: "tlsserver", Probe: func(context.Context, Job) error { return nil }, Now: func() time.Time { return now },
		newACME: newClient(&firstPublic),
	}
	if _, err := New(context.Background(), db, config); err != nil {
		t.Fatal(err)
	}
	config.newACME = newClient(&secondPublic)
	if _, err := New(context.Background(), db, config); err != nil {
		t.Fatal(err)
	}
	if string(firstPublic) != string(secondPublic) {
		t.Fatal("ACME account key changed across restart")
	}
}

func TestServiceRequiresExplicitChangedTermsAcceptance(t *testing.T) {
	db := testDatabase(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	fake := &fakeACME{now: now, terms: "https://acme.test/terms/v1"}
	config := Config{
		DirectoryURL: "https://acme.test/directory", Email: "operator@example.com", AcceptTerms: true,
		Profile: "tlsserver", Probe: func(context.Context, Job) error { return nil }, Now: func() time.Time { return now },
		newACME: func(*http.Client, string, string, crypto.Signer) (acmeClient, error) { return fake, nil },
	}
	if _, err := New(context.Background(), db, config); err != nil {
		t.Fatal(err)
	}
	fake.terms = "https://acme.test/terms/v2"
	config.AcceptTerms = false
	if _, err := New(context.Background(), db, config); err == nil {
		t.Fatal("changed terms were accepted implicitly")
	}
	config.AcceptTerms = true
	if _, err := New(context.Background(), db, config); err != nil {
		t.Fatalf("explicit changed terms acceptance: %v", err)
	}
}

func TestServiceUpdatesAccountContact(t *testing.T) {
	db := testDatabase(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	fake := &fakeACME{now: now}
	config := Config{
		DirectoryURL: "https://acme.test/directory", Email: "operator@example.com", AcceptTerms: true,
		Profile: "tlsserver", Probe: func(context.Context, Job) error { return nil }, Now: func() time.Time { return now },
		newACME: func(*http.Client, string, string, crypto.Signer) (acmeClient, error) { return fake, nil },
	}
	if _, err := New(context.Background(), db, config); err != nil {
		t.Fatal(err)
	}
	config.Email = "new@example.com"
	if _, err := New(context.Background(), db, config); err != nil {
		t.Fatal(err)
	}
	if fake.updatedContact != "mailto:new@example.com" {
		t.Fatalf("updated contact = %q", fake.updatedContact)
	}
}

func TestServiceResumesProcessingAuthorization(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	db := testDatabase(t)
	key, csrDER := testCSR(t, testHostname, pkix.Name{})
	chain, roots := testCertificateChain(t, key, testHostname, now)
	fake := &fakeACME{now: now, certificate: chain}
	service := testService(t, db, fake, roots, now)
	job, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	job.State = StateValidating
	if err := service.store.saveJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	fake.authorizationStatuses = []string{legoacme.StatusProcessing, legoacme.StatusValid}
	job, err = service.ChallengeReady(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != StateWaitingForInstall {
		t.Fatalf("resumed state = %q", job.State)
	}
}

func TestServiceResumesPreauthorizedFinalization(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	db := testDatabase(t)
	key, csrDER := testCSR(t, testHostname, pkix.Name{})
	chain, roots := testCertificateChain(t, key, testHostname, now)
	fake := &fakeACME{
		now: now, certificate: chain, authorizationStatuses: []string{legoacme.StatusValid},
		finalizeErr: errors.New("temporary finalize failure"),
	}
	service := testService(t, db, fake, roots, now)
	if _, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("initial create error = %v", err)
	}
	fake.finalizeErr = nil
	service.now = func() time.Time { return now.Add(10 * time.Second) }
	job, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != StateWaitingForInstall || job.Challenge() != nil {
		t.Fatalf("resumed preauthorized job = %+v", job)
	}
}

func TestValidateCSRPolicy(t *testing.T) {
	_, valid := testCSR(t, testHostname, pkix.Name{})
	if _, _, _, err := validateCSR(valid, testHostname); err != nil {
		t.Fatalf("valid CSR: %v", err)
	}
	_, wrongHost := testCSR(t, "other.tnl.test", pkix.Name{})
	_, subject := testCSR(t, testHostname, pkix.Name{CommonName: testHostname})
	for name, csr := range map[string][]byte{
		"wrong hostname": wrongHost,
		"subject":        subject,
		"malformed":      []byte("not a CSR"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := validateCSR(csr, testHostname); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestValidateCertificateChainRejectsWrongKeyAndTrailingData(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	key, _ := testCSR(t, testHostname, pkix.Name{})
	chain, roots := testCertificateChain(t, key, testHostname, now)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateCertificateChain(chain, testHostname, sha256.Sum256(spki), now, roots); err != nil {
		t.Fatalf("valid chain: %v", err)
	}
	if _, _, err := validateCertificateChain(chain, testHostname, [32]byte{1}, now, roots); err == nil {
		t.Fatal("wrong SPKI accepted")
	}
	if _, _, err := validateCertificateChain(append(chain, []byte("garbage")...), testHostname, sha256.Sum256(spki), now, roots); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestStoreRateLimitsActualOrderAttempts(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	store, err := newStore(testDatabase(t), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for index := byte(1); index <= 3; index++ {
		csrHash := [32]byte{index}
		job, _, err := store.createJob(
			context.Background(), testRouteID, 1, testHostname, "tlsserver", []byte{index}, csrHash, [32]byte{index},
		)
		if err != nil {
			t.Fatal(err)
		}
		job.State = StateInvalid
		job.OrderAttempts = 1
		if err := store.saveJob(context.Background(), job); err != nil {
			t.Fatal(err)
		}
	}
	err = store.allowJobCreation(context.Background(), testRouteID, 1, [32]byte{4}, now)
	var limit *RateLimitError
	if !errors.As(err, &limit) || !limit.RetryAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("rate limit error = %#v", err)
	}
}

type fakeACME struct {
	now                   time.Time
	certificate           []byte
	account               bool
	accepted              bool
	finalized             bool
	orders                int
	authorizationStatuses []string
	finalizeErr           error
	terms                 string
	updatedContact        string
}

func (f *fakeACME) Directory() legoacme.Directory {
	terms := f.terms
	if terms == "" {
		terms = "https://acme.test/terms"
	}
	return legoacme.Directory{Meta: legoacme.Meta{
		TermsOfService: terms, Profiles: map[string]string{"tlsserver": "server certificate"},
	}}
}

func (*fakeACME) KeyAuthorization(string) (string, error) { return "key-authorization", nil }

func (f *fakeACME) CreateAccount(context.Context, legoacme.Account) (legoacme.ExtendedAccount, error) {
	f.account = true
	return legoacme.ExtendedAccount{Account: legoacme.Account{Status: legoacme.StatusValid}, Location: "https://acme.test/account/1"}, nil
}

func (*fakeACME) GetAccount(context.Context, string) (legoacme.Account, error) {
	return legoacme.Account{Status: legoacme.StatusValid, Contact: []string{"mailto:operator@example.com"}}, nil
}

func (f *fakeACME) UpdateAccount(_ context.Context, _ string, request legoacme.Account) (legoacme.Account, error) {
	if len(request.Contact) == 1 {
		f.updatedContact = request.Contact[0]
	}
	return legoacme.Account{Status: legoacme.StatusValid}, nil
}

func (f *fakeACME) CreateOrder(context.Context, []string, *legoapi.OrderOptions) (legoacme.ExtendedOrder, error) {
	f.orders++
	return legoacme.ExtendedOrder{Order: legoacme.Order{
		Status: legoacme.StatusPending, Expires: f.now.Add(time.Hour).Format(time.RFC3339),
		Profile:        "tlsserver",
		Authorizations: []string{"https://acme.test/authz/1"}, Finalize: "https://acme.test/order/1/finalize",
	}, Location: "https://acme.test/order/1"}, nil
}

func (f *fakeACME) GetOrder(context.Context, string) (legoacme.ExtendedOrder, error) {
	status := legoacme.StatusReady
	certificateURL := ""
	if f.finalized {
		status = legoacme.StatusValid
		certificateURL = "https://acme.test/certificate/1"
	}
	return legoacme.ExtendedOrder{Order: legoacme.Order{Status: status, Certificate: certificateURL}, Location: "https://acme.test/order/1"}, nil
}

func (f *fakeACME) GetAuthorization(context.Context, string) (legoacme.Authorization, error) {
	status := legoacme.StatusPending
	if len(f.authorizationStatuses) != 0 {
		status = f.authorizationStatuses[0]
		f.authorizationStatuses = f.authorizationStatuses[1:]
	} else if f.accepted {
		status = legoacme.StatusValid
	}
	return legoacme.Authorization{
		Status: status, Expires: f.now.Add(time.Hour), Identifier: legoacme.Identifier{Type: "dns", Value: testHostname},
		Challenges: []legoacme.Challenge{{Type: tlsALPNChallengeType, URL: "https://acme.test/challenge/1", Token: "token"}},
	}, nil
}

func (f *fakeACME) AcceptChallenge(context.Context, string) (legoacme.ExtendedChallenge, error) {
	f.accepted = true
	return legoacme.ExtendedChallenge{}, nil
}

func (f *fakeACME) FinalizeOrder(context.Context, string, []byte) (legoacme.ExtendedOrder, error) {
	if f.finalizeErr != nil {
		return legoacme.ExtendedOrder{}, f.finalizeErr
	}
	f.finalized = true
	return legoacme.ExtendedOrder{Order: legoacme.Order{Status: legoacme.StatusProcessing}}, nil
}

func testService(t *testing.T, db *sql.DB, fake *fakeACME, roots *x509.CertPool, now time.Time) *Service {
	t.Helper()
	service, err := New(context.Background(), db, Config{
		DirectoryURL: "https://acme.test/directory", Email: "operator@example.com", AcceptTerms: true,
		Profile: "tlsserver", Roots: roots, Probe: func(context.Context, Job) error { return nil },
		Now: func() time.Time { return now },
		newACME: func(*http.Client, string, string, crypto.Signer) (acmeClient, error) {
			return fake, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func (f *fakeACME) GetCertificate(context.Context, string) (*legoacme.RawCertificate, error) {
	return &legoacme.RawCertificate{Cert: f.certificate}, nil
}

func testDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO principals (id, display_name, email, created_at)
		VALUES ('principal', 'Principal', 'principal@example.com', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO hostname_claims (id, principal_id, hostname, created_at)
		VALUES ('claim', 'principal', ?, 1)`, testHostname); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO routes
		(id, claim_id, principal_id, hostname, display_target, state, generation, created_at)
		VALUES (?, 'claim', 'principal', ?, 'http://127.0.0.1:3000', 'active', 1, 1)`, testRouteID, testHostname); err != nil {
		t.Fatal(err)
	}
	return db
}

func testCSR(t *testing.T, hostname string, subject pkix.Name) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: subject, DNSNames: []string{hostname}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, csrDER
}

func testCertificateChain(
	t *testing.T,
	leafKey *ecdsa.PrivateKey,
	hostname string,
	now time.Time,
) ([]byte, *x509.CertPool) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(89 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), roots
}
