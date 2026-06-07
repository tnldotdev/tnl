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

	legoacme "github.com/go-acme/lego/v5/acme"
	legoapi "github.com/go-acme/lego/v5/acme/api"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

const (
	testRouteID  = "route_0123456789abcdef0123456789abcdef"
	testHostname = "unit.tnl.test"
)

func TestServiceCertificateLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	db := testDatabase(t)
	queries := statedb.New(db)
	key, csrDER := testCSR(t, testHostname, pkix.Name{})
	chain, roots := testCertificateChain(t, key, testHostname, now)
	fake := &fakeACME{now: now, certificate: chain}
	probeCalls := 0
	service, err := New(context.Background(), db, Config{
		DirectoryURL: "https://acme.test/directory",
		Email:        "operator@example.com",
		AcceptTerms:  true,
		ACMEProfile:  "tlsserver",
		Roots:        roots,
		Probe: func(_ context.Context, issuance Issuance) error {
			probeCalls++
			if issuance.Hostname != testHostname || issuance.ChallengeDigest != sha256.Sum256([]byte("key-authorization")) {
				t.Fatalf("unexpected challenge probe: %+v", issuance)
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

	issuance, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.Status != StatusWaitingChallenge || issuance.OrderAttempts != 1 || issuance.Challenge() == nil {
		t.Fatalf("created issuance = %+v", issuance)
	}
	idempotent, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent.ID != issuance.ID || fake.orders != 1 {
		t.Fatalf("idempotent issuance ID = %q, orders = %d", idempotent.ID, fake.orders)
	}
	if err := queries.AdvanceRouteVersion(context.Background(), statedb.AdvanceRouteVersionParams{
		RouteVersion: 2,
		RouteID:      testRouteID,
	}); err != nil {
		t.Fatal(err)
	}
	issuance, err = service.Create(context.Background(), testRouteID, 2, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.ID != idempotent.ID || issuance.RouteVersion != 2 || fake.orders != 1 {
		t.Fatalf("rebound issuance = %+v, orders = %d", issuance, fake.orders)
	}
	issuance.Status = StatusValidating
	if err := service.store.saveIssuance(context.Background(), issuance); err != nil {
		t.Fatal(err)
	}
	if err := queries.AdvanceRouteVersion(context.Background(), statedb.AdvanceRouteVersionParams{
		RouteVersion: 3,
		RouteID:      testRouteID,
	}); err != nil {
		t.Fatal(err)
	}
	issuance, err = service.Create(context.Background(), testRouteID, 3, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.ID != idempotent.ID || issuance.RouteVersion != 3 || issuance.Status != StatusValidating || fake.orders != 1 {
		t.Fatalf("processing rebound issuance = %+v, orders = %d", issuance, fake.orders)
	}

	issuance, err = service.ChallengeReady(context.Background(), issuance.ID)
	if err != nil {
		t.Fatal(err)
	}
	if probeCalls != 1 || issuance.Status != StatusWaitingForInstall || len(issuance.CertificatePEM) == 0 ||
		!issuance.NotBefore.Equal(now.Add(-time.Hour)) || !issuance.NotAfter.Equal(now.Add(89*24*time.Hour)) {
		t.Fatalf("validated issuance = %+v, probes = %d", issuance, probeCalls)
	}
	if !issuance.RenewAt.After(issuance.NotBefore) || !issuance.RenewAt.Before(issuance.NotAfter) {
		t.Fatalf("renewal time = %v outside validity", issuance.RenewAt)
	}
	if _, err := service.Installed(context.Background(), issuance.ID, testRouteID, 3); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("install before cleanup error = %v", err)
	}
	issuance, err = service.ChallengeRemoved(context.Background(), issuance.ID)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err = service.Installed(context.Background(), issuance.ID, testRouteID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.Status != StatusInstalled || issuance.InstalledAt.IsZero() {
		t.Fatalf("installed issuance = %+v", issuance)
	}
	_, replacementCSR := testCSR(t, testHostname, pkix.Name{})
	if _, err := service.Create(
		context.Background(), testRouteID, 3, "tlsserver", replacementCSR,
	); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("early replacement error = %v", err)
	}
	for version := 4; version <= 7; version++ {
		if err := queries.AdvanceRouteVersion(context.Background(), statedb.AdvanceRouteVersionParams{
			RouteVersion: int64(version),
			RouteID:      testRouteID,
		}); err != nil {
			t.Fatal(err)
		}
		reused, err := service.Create(
			context.Background(), testRouteID, uint64(version), "tlsserver", csrDER,
		)
		if err != nil {
			t.Fatalf("reuse at version %d: %v", version, err)
		}
		if reused.Status != StatusWaitingForInstall || reused.OrderAttempts != 0 || len(reused.CertificatePEM) == 0 {
			t.Fatalf("reused issuance at version %d = %+v", version, reused)
		}
	}
}

func TestServiceRecoversAccountCreationWithPersistedKey(t *testing.T) {
	db := testDatabase(t)
	queries := statedb.New(db)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	fake := &fakeACME{now: now}
	var firstPublic, secondPublic []byte
	newClient := func(destination *[]byte) func(*http.Client, string, string, crypto.Signer) (acmeClient, error) {
		return func(_ *http.Client, _, _ string, signer crypto.Signer) (acmeClient, error) {
			encoded, err := x509.MarshalPKIXPublicKey(signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			*destination = encoded
			return fake, nil
		}
	}
	config := Config{
		DirectoryURL: "https://acme.test/directory", Email: "operator@example.com", AcceptTerms: true,
		ACMEProfile: "tlsserver", Probe: func(context.Context, Issuance) error { return nil }, Now: func() time.Time { return now },
		newACME: newClient(&firstPublic),
	}
	if _, err := New(context.Background(), db, config); err != nil {
		t.Fatal(err)
	}
	if err := queries.ClearACMEAccountKID(context.Background(), config.DirectoryURL); err != nil {
		t.Fatal(err)
	}
	config.newACME = newClient(&secondPublic)
	if _, err := New(context.Background(), db, config); err != nil {
		t.Fatal(err)
	}
	if string(firstPublic) != string(secondPublic) || fake.createAccountCalls != 2 {
		t.Fatalf("account key changed or creation did not converge: calls = %d", fake.createAccountCalls)
	}
	if _, err := New(context.Background(), db, config); err != nil {
		t.Fatal(err)
	}
	if fake.createAccountCalls != 2 {
		t.Fatalf("persisted account creation was replayed %d times", fake.createAccountCalls)
	}
}

func TestServiceRequiresExplicitChangedTermsAcceptance(t *testing.T) {
	db := testDatabase(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	fake := &fakeACME{now: now, terms: "https://acme.test/terms/v1"}
	config := Config{
		DirectoryURL: "https://acme.test/directory", Email: "operator@example.com", AcceptTerms: true,
		ACMEProfile: "tlsserver", Probe: func(context.Context, Issuance) error { return nil }, Now: func() time.Time { return now },
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
	queries := statedb.New(db)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	fake := &fakeACME{now: now}
	config := Config{
		DirectoryURL: "https://acme.test/directory", Email: "operator@example.com", AcceptTerms: true,
		ACMEProfile: "tlsserver", Probe: func(context.Context, Issuance) error { return nil }, Now: func() time.Time { return now },
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
	if err := queries.SetACMEAccountEmail(context.Background(), "operator@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), db, config); err != nil {
		t.Fatal(err)
	}
	if fake.updateAccountCalls != 1 {
		t.Fatalf("completed account update was replayed %d times", fake.updateAccountCalls)
	}
	account, err := queries.GetACMEAccount(context.Background(), config.DirectoryURL)
	if err != nil {
		t.Fatal(err)
	}
	if account.Email != "new@example.com" {
		t.Fatalf("persisted account email = %q", account.Email)
	}
}

func TestServiceBlocksAmbiguousOrderCreation(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for _, cause := range []error{
		errors.New("connection reset after write"),
		&legoacme.ProblemDetails{HTTPStatus: http.StatusServiceUnavailable},
	} {
		db := testDatabase(t)
		fake := &fakeACME{now: now, createOrderErrors: []error{cause}}
		service := testService(t, db, fake, nil, now)
		_, csrDER := testCSR(t, testHostname, pkix.Name{})
		if _, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("ambiguous order error = %v", err)
		}
		fake.orders = 1
		restarted := testService(t, db, fake, nil, now.Add(6*time.Second))
		if _, err := restarted.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER); !errors.Is(err, ErrInvalidStatus) {
			t.Fatalf("ambiguous order error = %v", err)
		}
		_, csrHash, _, err := validateCSR(csrDER, testHostname)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := restarted.store.findBoundIssuance(context.Background(), testRouteID, 1, csrHash)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Status != StatusBlocked || stored.OrderAttempts != 1 || fake.createOrderCalls != 1 || fake.orders != 1 {
			t.Fatalf("ambiguous issuance = %+v, calls = %d, remote orders = %d", stored, fake.createOrderCalls, fake.orders)
		}
	}
}

func TestServiceRetriesRejectedOrderCreation(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name  string
		cause error
		want  error
		delay time.Duration
	}{
		{
			name: "bad nonce", cause: &legoacme.ProblemDetails{HTTPStatus: http.StatusBadRequest, Type: legoacme.BadNonceErrorType},
			want: ErrUnavailable, delay: 5 * time.Second,
		},
		{
			name: "rate limit",
			cause: &legoacme.RateLimitedError{
				ProblemDetails: &legoacme.ProblemDetails{HTTPStatus: http.StatusTooManyRequests, Type: legoacme.RateLimitedErrorType},
				RetryAfter:     time.Minute,
			},
			want: ErrRateLimited, delay: time.Minute,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := testDatabase(t)
			_, csrDER := testCSR(t, testHostname, pkix.Name{})
			fake := &fakeACME{now: now, createOrderErrors: []error{test.cause}}
			service := testService(t, db, fake, nil, now)
			if _, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER); !errors.Is(err, test.want) {
				t.Fatalf("first create error = %v", err)
			}
			_, csrHash, _, err := validateCSR(csrDER, testHostname)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := service.store.findBoundIssuance(context.Background(), testRouteID, 1, csrHash)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Status != StatusCreatingOrder || stored.OrderAttempts != 0 || !stored.RetryAt.Equal(now.Add(test.delay)) {
				t.Fatalf("retryable order issuance = %+v", stored)
			}
			restarted := testService(t, db, fake, nil, now.Add(test.delay+time.Second))
			issuance, err := restarted.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER)
			if err != nil {
				t.Fatal(err)
			}
			if issuance.Status != StatusWaitingChallenge || fake.createOrderCalls != 2 || fake.orders != 1 {
				t.Fatalf("retried issuance = %+v, calls = %d, orders = %d", issuance, fake.createOrderCalls, fake.orders)
			}
		})
	}
}

func TestServiceDoesNotReplayAcceptedChallenge(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	db := testDatabase(t)
	key, csrDER := testCSR(t, testHostname, pkix.Name{})
	chain, roots := testCertificateChain(t, key, testHostname, now)
	fake := &fakeACME{now: now, certificate: chain}
	service := testService(t, db, fake, roots, now)
	issuance, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	issuance.Status = StatusValidating
	if err := service.store.saveIssuance(context.Background(), issuance); err != nil {
		t.Fatal(err)
	}
	fake.authorizationStatuses = []string{legoacme.StatusPending, legoacme.StatusValid}
	fake.challengeStatus = legoacme.StatusProcessing
	restarted := testService(t, db, fake, roots, now)
	issuance, err = restarted.ChallengeReady(context.Background(), issuance.ID)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.Status != StatusWaitingForInstall || fake.acceptChallengeCalls != 0 {
		t.Fatalf("resumed issuance = %+v, challenge accepts = %d", issuance, fake.acceptChallengeCalls)
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
	issuance, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.Status != StatusWaitingForInstall || issuance.Challenge() != nil {
		t.Fatalf("resumed preauthorized issuance = %+v", issuance)
	}
}

func TestServiceDoesNotReplayFinalization(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	db := testDatabase(t)
	key, csrDER := testCSR(t, testHostname, pkix.Name{})
	chain, roots := testCertificateChain(t, key, testHostname, now)
	fake := &fakeACME{now: now, certificate: chain}
	service := testService(t, db, fake, roots, now)
	issuance, err := service.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	issuance.Status = StatusFinalizing
	if err := service.store.saveIssuance(context.Background(), issuance); err != nil {
		t.Fatal(err)
	}
	fake.orderStatuses = []string{legoacme.StatusProcessing, legoacme.StatusValid}
	restarted := testService(t, db, fake, roots, now)
	issuance, err = restarted.Create(context.Background(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.Status != StatusWaitingForInstall || fake.finalizeOrderCalls != 0 {
		t.Fatalf("resumed issuance = %+v, finalizations = %d", issuance, fake.finalizeOrderCalls)
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
		issuance, _, err := store.createIssuance(
			context.Background(), testRouteID, 1, testHostname, "tlsserver", []byte{index}, csrHash, [32]byte{index},
		)
		if err != nil {
			t.Fatal(err)
		}
		issuance.Status = StatusFailed
		issuance.OrderAttempts = 1
		if err := store.saveIssuance(context.Background(), issuance); err != nil {
			t.Fatal(err)
		}
	}
	err = store.allowIssuanceCreation(context.Background(), testRouteID, 1, [32]byte{4}, now)
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
	createOrderCalls      int
	createAccountCalls    int
	updateAccountCalls    int
	acceptChallengeCalls  int
	finalizeOrderCalls    int
	accountContact        string
	challengeStatus       string
	authorizationStatuses []string
	orderStatuses         []string
	createOrderErrors     []error
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

func (f *fakeACME) CreateAccount(_ context.Context, request legoacme.Account) (legoacme.ExtendedAccount, error) {
	f.account = true
	f.createAccountCalls++
	if len(request.Contact) == 1 && f.accountContact == "" {
		f.accountContact = request.Contact[0]
	}
	return legoacme.ExtendedAccount{Account: legoacme.Account{Status: legoacme.StatusValid}, Location: "https://acme.test/account/1"}, nil
}

func (f *fakeACME) GetAccount(context.Context, string) (legoacme.Account, error) {
	contact := f.accountContact
	if contact == "" {
		contact = "mailto:operator@example.com"
	}
	return legoacme.Account{Status: legoacme.StatusValid, Contact: []string{contact}}, nil
}

func (f *fakeACME) UpdateAccount(_ context.Context, _ string, request legoacme.Account) (legoacme.Account, error) {
	f.updateAccountCalls++
	if len(request.Contact) == 1 {
		f.updatedContact = request.Contact[0]
		f.accountContact = request.Contact[0]
	}
	return legoacme.Account{Status: legoacme.StatusValid}, nil
}

func (f *fakeACME) CreateOrder(context.Context, []string, *legoapi.OrderOptions) (legoacme.ExtendedOrder, error) {
	f.createOrderCalls++
	if len(f.createOrderErrors) != 0 {
		err := f.createOrderErrors[0]
		f.createOrderErrors = f.createOrderErrors[1:]
		return legoacme.ExtendedOrder{}, err
	}
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
	if len(f.orderStatuses) != 0 {
		status = f.orderStatuses[0]
		f.orderStatuses = f.orderStatuses[1:]
	} else if f.finalized {
		status = legoacme.StatusValid
	}
	if status == legoacme.StatusValid {
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
	challengeStatus := f.challengeStatus
	if challengeStatus == "" {
		challengeStatus = legoacme.StatusPending
		if f.accepted {
			challengeStatus = legoacme.StatusValid
		}
	}
	return legoacme.Authorization{
		Status: status, Expires: f.now.Add(time.Hour), Identifier: legoacme.Identifier{Type: "dns", Value: testHostname},
		Challenges: []legoacme.Challenge{{
			Type: tlsALPNChallengeType, URL: "https://acme.test/challenge/1", Token: "token", Status: challengeStatus,
		}},
	}, nil
}

func (f *fakeACME) AcceptChallenge(context.Context, string) (legoacme.ExtendedChallenge, error) {
	f.accepted = true
	f.acceptChallengeCalls++
	return legoacme.ExtendedChallenge{}, nil
}

func (f *fakeACME) FinalizeOrder(context.Context, string, []byte) (legoacme.ExtendedOrder, error) {
	f.finalizeOrderCalls++
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
		ACMEProfile: "tlsserver", Roots: roots, Probe: func(context.Context, Issuance) error { return nil },
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
	queries := statedb.New(db)
	if err := queries.UpsertIdentity(context.Background(), statedb.UpsertIdentityParams{
		IdentityID:  "identity",
		DisplayName: "Identity",
		Email:       "identity@example.com",
		CreatedAt:   1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := queries.InsertHostname(context.Background(), statedb.InsertHostnameParams{
		ID:         "hostname",
		IdentityID: "identity",
		Hostname:   testHostname,
		CreatedAt:  1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := queries.InsertRoute(context.Background(), statedb.InsertRouteParams{
		RouteID:     testRouteID,
		HostnameID:  sql.NullString{String: "hostname", Valid: true},
		IdentityID:  "identity",
		Hostname:    testHostname,
		LocalTarget: "http://127.0.0.1:3000",
		CreatedAt:   1,
	}); err != nil {
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
