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
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

const (
	testDirectoryURL = "https://acme.test/directory"
	testRouteID      = "route_0123456789abcdef0123456789abcdef"
	testHostname     = "unit.tnl.test"
)

func TestServiceCertificateLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	queries := statedb.New(db)
	key, csrDER := testCSR(t, testHostname, pkix.Name{})
	chain, roots := testCertificateChain(t, key, testHostname, now)
	fake := &fakeACME{now: now, certificate: chain}
	probeCalls := 0
	service := testServiceWithConfig(t, db, fake, roots, clock, testDirectoryURL, "tlsserver", func(_ context.Context, issuance Issuance) error {
		probeCalls++
		if issuance.Hostname != testHostname || issuance.ChallengeDigest != sha256.Sum256([]byte("key-authorization")) {
			t.Fatalf("unexpected challenge probe: %+v", issuance)
		}
		return nil
	}, nil)

	issuance := driveNormalIssuance(t, service, clock, csrDER)
	if probeCalls != 2 || issuance.Status != StatusWaitingForInstall || len(issuance.CertificatePEM) == 0 ||
		issuance.Challenge() == nil || !issuance.NotBefore.Equal(now.Add(-time.Hour)) ||
		!issuance.NotAfter.Equal(now.Add(89*24*time.Hour)) {
		t.Fatalf("issued certificate = %+v, probes = %d", issuance, probeCalls)
	}
	if fake.createOrderCalls != 1 || fake.getAuthorizationCalls != 3 || fake.acceptChallengeCalls != 1 ||
		fake.getOrderCalls != 2 || fake.finalizeOrderCalls != 1 || fake.getCertificateCalls != 1 {
		t.Fatalf("remote milestones: create=%d authorization=%d accept=%d order=%d finalize=%d certificate=%d",
			fake.createOrderCalls, fake.getAuthorizationCalls, fake.acceptChallengeCalls,
			fake.getOrderCalls, fake.finalizeOrderCalls, fake.getCertificateCalls)
	}
	if !issuance.RenewAt.After(issuance.NotBefore) || !issuance.RenewAt.Before(issuance.NotAfter) {
		t.Fatalf("renewal time = %v outside validity", issuance.RenewAt)
	}
	if _, err := service.Installed(t.Context(), issuance.ID, testRouteID, 1); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("install before cleanup error = %v", err)
	}

	issuance, err := service.ChallengeRemoved(t.Context(), issuance.ID)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.Challenge() != nil || issuance.ChallengeURL != "" || issuance.ChallengeExpires != (time.Time{}) ||
		issuance.ChallengeDigest != ([sha256.Size]byte{}) {
		t.Fatalf("challenge was not atomically cleared: %+v", issuance)
	}
	cleanupUpdatedAt := issuance.UpdatedAt
	clock.Add(time.Hour)
	issuance, err = service.ChallengeRemoved(t.Context(), issuance.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !issuance.UpdatedAt.Equal(cleanupUpdatedAt) {
		t.Fatalf("idempotent cleanup changed updated time: %v != %v", issuance.UpdatedAt, cleanupUpdatedAt)
	}
	issuance, err = service.Installed(t.Context(), issuance.ID, testRouteID, 1)
	if err != nil {
		t.Fatal(err)
	}
	installedUpdatedAt := issuance.UpdatedAt
	issuance, err = service.Installed(t.Context(), issuance.ID, testRouteID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.Status != StatusInstalled || !issuance.UpdatedAt.Equal(installedUpdatedAt) {
		t.Fatalf("idempotent installation = %+v", issuance)
	}

	if err := queries.AdvanceRouteVersion(t.Context(), statedb.AdvanceRouteVersionParams{RouteID: testRouteID, RouteVersion: 2}); err != nil {
		t.Fatal(err)
	}
	service.hostnameReady = func(context.Context, string) error { return errors.New("DNS unavailable") }
	rebound, err := service.Create(t.Context(), testRouteID, 2, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if rebound.ID != issuance.ID || rebound.RouteVersion != 2 || rebound.Status != StatusWaitingForInstall || fake.createOrderCalls != 1 {
		t.Fatalf("rebound certificate = %+v, order calls = %d", rebound, fake.createOrderCalls)
	}
	count, err := queries.CountCertificateIssuancesByRoute(t.Context(), testRouteID)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rebind created %d issuance rows", count)
	}
}

func TestServicePreauthorizedAuthorizationInstallsWithoutCleanup(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	key, csrDER := testCSR(t, testHostname, pkix.Name{})
	chain, roots := testCertificateChain(t, key, testHostname, now)
	fake := &fakeACME{now: now, certificate: chain, authorizationStatuses: []string{legoacme.StatusValid}}
	service := testService(t, db, fake, roots, clock)

	issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusAuthorizing {
		t.Fatalf("create order = %+v, %v", issuance, err)
	}
	service.hostnameReady = func(context.Context, string) error { return errors.New("DNS unavailable") }
	issuance, err = service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusReadyToFinalize || issuance.Challenge() != nil {
		t.Fatalf("preauthorized authorization = %+v, %v", issuance, err)
	}
	issuance, err = service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusFinalizing {
		t.Fatalf("finalize = %+v, %v", issuance, err)
	}
	clock.Add(retryDelay + time.Second)
	issuance, err = service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusWaitingForInstall || issuance.Challenge() != nil {
		t.Fatalf("download = %+v, %v", issuance, err)
	}
	issuance, err = service.Installed(t.Context(), issuance.ID, testRouteID, 1)
	if err != nil || issuance.Status != StatusInstalled {
		t.Fatalf("install preauthorized certificate = %+v, %v", issuance, err)
	}
}

func TestServiceDoesNotReplayAmbiguousOrder(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	_, csrDER := testCSR(t, testHostname, pkix.Name{})
	fake := &fakeACME{now: now, createOrderErrors: []error{errors.New("connection reset after write")}}
	service := testService(t, db, fake, nil, clock)
	if _, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ambiguous order error = %v", err)
	}
	issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.Status != StatusFailed || issuance.OrderStartedAt.IsZero() || fake.createOrderCalls != 1 {
		t.Fatalf("ambiguous issuance = %+v, calls = %d", issuance, fake.createOrderCalls)
	}
}

func TestServiceDoesNotReplayAmbiguousFinalization(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	_, csrDER := testCSR(t, testHostname, pkix.Name{})
	fake := &fakeACME{
		now: now, authorizationStatuses: []string{legoacme.StatusValid},
		finalizeErrors: []error{errors.New("connection reset after write")},
	}
	service := testService(t, db, fake, nil, clock)
	mustReachReadyToFinalize(t, service, csrDER)
	if _, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ambiguous finalize error = %v", err)
	}
	clock.Add(retryDelay + time.Second)
	fake.orderStatuses = []string{legoacme.StatusProcessing}
	issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.Status != StatusFinalizing || fake.finalizeOrderCalls != 1 {
		t.Fatalf("reconciled finalization = %+v, calls = %d", issuance, fake.finalizeOrderCalls)
	}
}

func TestServiceRetriesKnownOrderRejections(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name  string
		cause error
		want  error
		delay time.Duration
	}{
		{
			name: "bad nonce", cause: &legoacme.ProblemDetails{HTTPStatus: http.StatusBadRequest, Type: legoacme.BadNonceErrorType},
			want: ErrUnavailable, delay: retryDelay,
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
			clock := &testClock{now: now}
			db := testDatabase(t)
			_, csrDER := testCSR(t, testHostname, pkix.Name{})
			fake := &fakeACME{now: now, createOrderErrors: []error{test.cause}}
			service := testService(t, db, fake, nil, clock)
			if _, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER); !errors.Is(err, test.want) {
				t.Fatalf("first create error = %v", err)
			}
			stored := boundIssuance(t, service, csrDER)
			if stored.Status != StatusCreatingOrder || !stored.OrderStartedAt.IsZero() || !stored.RetryAt.Equal(now.Add(test.delay)) {
				t.Fatalf("retryable order issuance = %+v", stored)
			}
			if issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER); err != nil ||
				issuance.Status != StatusCreatingOrder || fake.createOrderCalls != 1 {
				t.Fatalf("early retry = %+v, %v, calls = %d", issuance, err, fake.createOrderCalls)
			}
			clock.Add(test.delay + time.Second)
			issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
			if err != nil || issuance.Status != StatusAuthorizing || fake.createOrderCalls != 2 {
				t.Fatalf("retried order = %+v, %v, calls = %d", issuance, err, fake.createOrderCalls)
			}
		})
	}
}

func TestServiceReturnsPermanentPostOrderFailure(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	_, csrDER := testCSR(t, testHostname, pkix.Name{})
	fake := &fakeACME{now: now, getAuthorizationErrors: []error{
		&legoacme.ProblemDetails{HTTPStatus: http.StatusBadRequest, Type: "urn:ietf:params:acme:error:malformed"},
	}}
	service := testService(t, db, fake, nil, clock)
	if _, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER); err != nil {
		t.Fatal(err)
	}
	issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusFailed || issuance.LastError == "" {
		t.Fatalf("permanent failure = %+v, %v", issuance, err)
	}
}

func TestServiceReturnsDefinitiveFinalizationFailure(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	_, csrDER := testCSR(t, testHostname, pkix.Name{})
	fake := &fakeACME{
		now: now, authorizationStatuses: []string{legoacme.StatusValid},
		finalizeErrors: []error{&legoacme.ProblemDetails{
			HTTPStatus: http.StatusBadRequest, Type: "urn:ietf:params:acme:error:badCSR",
		}},
	}
	service := testService(t, db, fake, nil, clock)
	mustReachReadyToFinalize(t, service, csrDER)
	issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusFailed || fake.finalizeOrderCalls != 1 {
		t.Fatalf("definitive finalization failure = %+v, %v, calls = %d", issuance, err, fake.finalizeOrderCalls)
	}
}

func TestServiceRetriesDefinitiveFinalizationRejections(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name  string
		cause error
		want  error
		delay time.Duration
	}{
		{
			name: "bad nonce", cause: &legoacme.ProblemDetails{HTTPStatus: http.StatusBadRequest, Type: legoacme.BadNonceErrorType},
			want: ErrUnavailable, delay: retryDelay,
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
			clock := &testClock{now: now}
			db := testDatabase(t)
			_, csrDER := testCSR(t, testHostname, pkix.Name{})
			fake := &fakeACME{
				now: now, authorizationStatuses: []string{legoacme.StatusValid},
				finalizeErrors: []error{test.cause},
			}
			service := testService(t, db, fake, nil, clock)
			mustReachReadyToFinalize(t, service, csrDER)
			if _, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER); !errors.Is(err, test.want) {
				t.Fatalf("first finalization error = %v", err)
			}
			issuance := boundIssuance(t, service, csrDER)
			if issuance.Status != StatusReadyToFinalize || !issuance.RetryAt.Equal(now.Add(test.delay)) {
				t.Fatalf("retryable finalization = %+v", issuance)
			}
			if _, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER); err != nil || fake.finalizeOrderCalls != 1 {
				t.Fatalf("early retry error = %v, calls = %d", err, fake.finalizeOrderCalls)
			}
			clock.Add(test.delay + time.Second)
			issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
			if err != nil || issuance.Status != StatusFinalizing || fake.finalizeOrderCalls != 2 {
				t.Fatalf("retried finalization = %+v, %v, calls = %d", issuance, err, fake.finalizeOrderCalls)
			}
		})
	}
}

func TestServiceExpiredPendingChallengeFails(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	_, csrDER := testCSR(t, testHostname, pkix.Name{})
	fake := &fakeACME{now: now}
	service := testService(t, db, fake, nil, clock)
	mustReachWaitingForChallenge(t, service, csrDER)
	clock.Add(2 * time.Hour)
	fake.authorizationStatuses = []string{legoacme.StatusPending}
	issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusFailed || fake.getAuthorizationCalls != 2 {
		t.Fatalf("expired pending challenge = %+v, %v, calls = %d", issuance, err, fake.getAuthorizationCalls)
	}
}

func TestServiceExpiredValidChallengeFinalizesAndRequiresCleanup(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	key, csrDER := testCSR(t, testHostname, pkix.Name{})
	chain, roots := testCertificateChain(t, key, testHostname, now)
	fake := &fakeACME{now: now, certificate: chain}
	service := testService(t, db, fake, roots, clock)
	issuance := mustReachWaitingForChallenge(t, service, csrDER)
	originalChallenge := issuance.ChallengeURL
	clock.Add(2 * time.Hour)
	fake.authorizationStatuses = []string{legoacme.StatusValid}
	issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusReadyToFinalize || issuance.ChallengeURL != originalChallenge {
		t.Fatalf("expired valid challenge = %+v, %v", issuance, err)
	}
	issuance, err = service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusFinalizing {
		t.Fatalf("finalize expired challenge = %+v, %v", issuance, err)
	}
	clock.Add(retryDelay + time.Second)
	issuance, err = service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusWaitingForInstall || issuance.Challenge() == nil || issuance.ChallengeExpires.After(clock.Now()) {
		t.Fatalf("certificate with outstanding expired challenge = %+v, %v", issuance, err)
	}
	if _, err := service.Installed(t.Context(), issuance.ID, testRouteID, 1); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("installed before expired challenge cleanup: %v", err)
	}
	issuance, err = service.ChallengeRemoved(t.Context(), issuance.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Installed(t.Context(), issuance.ID, testRouteID, 1); err != nil {
		t.Fatal(err)
	}
}

func TestServiceRouteVersionRacesFenceMutations(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	queries := statedb.New(db)
	_, csrDER := testCSR(t, testHostname, pkix.Name{})
	fake := &fakeACME{now: now}
	service := testService(t, db, fake, nil, clock)
	issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	fake.getAuthorizationHook = func() {
		if err := queries.AdvanceRouteVersion(t.Context(), statedb.AdvanceRouteVersionParams{RouteID: testRouteID, RouteVersion: 2}); err != nil {
			t.Fatal(err)
		}
		fake.getAuthorizationHook = nil
	}
	if _, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("stale progress error = %v", err)
	}
	stored, err := service.store.getIssuance(t.Context(), issuance.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != StatusAuthorizing || stored.RouteVersion != 1 {
		t.Fatalf("stale progress was persisted: %+v", stored)
	}
	stored.Status = StatusFailed
	if err := service.store.saveIssuance(t.Context(), stored); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("stale save error = %v", err)
	}
	if err := queries.AdvanceRouteVersion(t.Context(), statedb.AdvanceRouteVersionParams{RouteID: testRouteID, RouteVersion: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.store.rebindIssuance(t.Context(), stored, 2); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("stale rebind error = %v", err)
	}
}

func TestServiceRouteVersionChangeDuringChallengeReconciliationPreventsAcceptance(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	queries := statedb.New(db)
	_, csrDER := testCSR(t, testHostname, pkix.Name{})
	fake := &fakeACME{now: now}
	service := testService(t, db, fake, nil, clock)
	issuance := mustReachWaitingForChallenge(t, service, csrDER)
	fake.getAuthorizationHook = func() {
		if err := queries.AdvanceRouteVersion(t.Context(), statedb.AdvanceRouteVersionParams{RouteID: testRouteID, RouteVersion: 2}); err != nil {
			t.Fatal(err)
		}
		fake.getAuthorizationHook = nil
	}
	if _, err := service.ChallengeReady(t.Context(), issuance.ID); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("stale challenge error = %v", err)
	}
	if fake.acceptChallengeCalls != 0 {
		t.Fatalf("stale challenge was accepted %d times", fake.acceptChallengeCalls)
	}
}

func TestServiceScopesCAOperationsToConfiguration(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	_, csrDER := testCSR(t, testHostname, pkix.Name{})
	ownerACME := &fakeACME{now: now}
	owner := testService(t, db, ownerACME, nil, clock)
	issuance, err := owner.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []struct{ directory, profile string }{
		{directory: "https://other-acme.test/directory", profile: "tlsserver"},
		{directory: testDirectoryURL, profile: "shortlived"},
	} {
		foreignACME := &fakeACME{now: now}
		foreign := testServiceWithConfig(t, db, foreignACME, nil, clock, config.directory, config.profile, func(context.Context, Issuance) error { return nil }, nil)
		if _, err := foreign.ChallengeReady(t.Context(), issuance.ID); !errors.Is(err, ErrInvalidStatus) {
			t.Fatalf("foreign configuration %q/%q error = %v", config.directory, config.profile, err)
		}
		if foreignACME.getAuthorizationCalls != 0 {
			t.Fatalf("foreign configuration called the CA %d times", foreignACME.getAuthorizationCalls)
		}
	}
	if issuance.DirectoryURL != testDirectoryURL || issuance.ACMEProfile != "tlsserver" {
		t.Fatalf("persisted issuance scope = %+v", issuance)
	}
}

func TestServiceHonorsChallengeRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	_, csrDER := testCSR(t, testHostname, pkix.Name{})
	fake := &fakeACME{now: now, acceptChallengeRetryAfter: time.Minute}
	service := testService(t, testDatabase(t), fake, nil, clock)
	issuance := mustReachWaitingForChallenge(t, service, csrDER)
	issuance, err := service.ChallengeReady(t.Context(), issuance.ID)
	if err != nil || !issuance.RetryAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("accepted challenge = %+v, %v", issuance, err)
	}
}

func TestServiceDNSFailureDoesNotCreateIssuance(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	queries := statedb.New(db)
	_, csrDER := testCSR(t, testHostname, pkix.Name{})
	fake := &fakeACME{now: now}
	service := testServiceWithConfig(t, db, fake, nil, clock, testDirectoryURL, "tlsserver", func(context.Context, Issuance) error { return nil }, func(context.Context, string) error {
		return errors.New("DNS unavailable")
	})
	if _, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("DNS readiness error = %v", err)
	}
	count, err := queries.CountCertificateIssuancesByRoute(t.Context(), testRouteID)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || fake.createOrderCalls != 0 {
		t.Fatalf("DNS failure created %d rows and %d orders", count, fake.createOrderCalls)
	}
}

func TestServiceCallerCancellationDoesNotRecordRetry(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	db := testDatabase(t)
	_, csrDER := testCSR(t, testHostname, pkix.Name{})
	ctx, cancel := context.WithCancel(t.Context())
	fake := &fakeACME{now: now}
	fake.createOrderHook = cancel
	fake.createOrderErrors = []error{context.Canceled}
	service := testService(t, db, fake, nil, clock)
	if _, err := service.Create(ctx, testRouteID, 1, "tlsserver", csrDER); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	stored := boundIssuance(t, service, csrDER)
	if stored.OrderStartedAt.IsZero() || !stored.RetryAt.IsZero() || stored.LastError != "" {
		t.Fatalf("cancellation persisted a retry failure: %+v", stored)
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
		DirectoryURL: testDirectoryURL, Email: "operator@example.com", AcceptTerms: true,
		ACMEProfile: "tlsserver", Probe: func(context.Context, Issuance) error { return nil }, Now: func() time.Time { return now },
		newACME: newClient(&firstPublic),
	}
	if _, err := New(t.Context(), db, config); err != nil {
		t.Fatal(err)
	}
	if err := queries.ClearACMEAccountKID(t.Context(), config.DirectoryURL); err != nil {
		t.Fatal(err)
	}
	config.newACME = newClient(&secondPublic)
	if _, err := New(t.Context(), db, config); err != nil {
		t.Fatal(err)
	}
	if string(firstPublic) != string(secondPublic) || fake.createAccountCalls != 2 {
		t.Fatalf("account key changed or creation did not converge: calls = %d", fake.createAccountCalls)
	}
	if _, err := New(t.Context(), db, config); err != nil {
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
		DirectoryURL: testDirectoryURL, Email: "operator@example.com", AcceptTerms: true,
		ACMEProfile: "tlsserver", Probe: func(context.Context, Issuance) error { return nil }, Now: func() time.Time { return now },
		newACME: func(*http.Client, string, string, crypto.Signer) (acmeClient, error) { return fake, nil },
	}
	if _, err := New(t.Context(), db, config); err != nil {
		t.Fatal(err)
	}
	fake.terms = "https://acme.test/terms/v2"
	config.AcceptTerms = false
	if _, err := New(t.Context(), db, config); err == nil {
		t.Fatal("changed terms were accepted implicitly")
	}
	config.AcceptTerms = true
	if _, err := New(t.Context(), db, config); err != nil {
		t.Fatalf("explicit changed terms acceptance: %v", err)
	}
}

func TestServiceUpdatesAccountContact(t *testing.T) {
	db := testDatabase(t)
	queries := statedb.New(db)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	fake := &fakeACME{now: now}
	config := Config{
		DirectoryURL: testDirectoryURL, Email: "operator@example.com", AcceptTerms: true,
		ACMEProfile: "tlsserver", Probe: func(context.Context, Issuance) error { return nil }, Now: func() time.Time { return now },
		newACME: func(*http.Client, string, string, crypto.Signer) (acmeClient, error) { return fake, nil },
	}
	if _, err := New(t.Context(), db, config); err != nil {
		t.Fatal(err)
	}
	config.Email = "new@example.com"
	if _, err := New(t.Context(), db, config); err != nil {
		t.Fatal(err)
	}
	if fake.updatedContact != "mailto:new@example.com" {
		t.Fatalf("updated contact = %q", fake.updatedContact)
	}
	if err := queries.SetACMEAccountEmail(t.Context(), "operator@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(t.Context(), db, config); err != nil {
		t.Fatal(err)
	}
	if fake.updateAccountCalls != 1 {
		t.Fatalf("completed account update was replayed %d times", fake.updateAccountCalls)
	}
}

func TestValidateCSRPolicy(t *testing.T) {
	_, valid := testCSR(t, testHostname, pkix.Name{})
	if _, _, _, err := validateCSR(valid, testHostname); err != nil {
		t.Fatalf("valid CSR: %v", err)
	}
	_, wrongHost := testCSR(t, "other.tnl.test", pkix.Name{})
	_, subject := testCSR(t, testHostname, pkix.Name{CommonName: testHostname})
	for name, csr := range map[string][]byte{"wrong hostname": wrongHost, "subject": subject, "malformed": []byte("not a CSR")} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := validateCSR(csr, testHostname); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCertificateStatusMatchesGeneratedAPI(t *testing.T) {
	statuses := []string{
		StatusCreatingOrder,
		StatusAuthorizing,
		StatusWaitingChallenge,
		StatusReadyToFinalize,
		StatusFinalizing,
		StatusWaitingForInstall,
		StatusInstalled,
		StatusFailed,
	}
	for _, status := range statuses {
		if !serverv1.CertificateIssuanceStatus(status).Valid() {
			t.Fatalf("generated API rejects certificate status %q", status)
		}
	}
	for _, removed := range []serverv1.CertificateIssuanceStatus{"validating", "downloading", "blocked", "canceled"} {
		if removed.Valid() {
			t.Fatalf("generated API still accepts removed certificate status %q", removed)
		}
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

func TestStoreRateLimitsStartedOrders(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	current := now.Add(-2 * time.Hour)
	store, err := newStore(testDatabase(t), func() time.Time { return current }, testDirectoryURL, "tlsserver")
	if err != nil {
		t.Fatal(err)
	}
	for index := byte(1); index <= 3; index++ {
		current = now.Add(-2 * time.Hour)
		csrHash := [32]byte{index}
		issuance, _, err := store.createIssuance(t.Context(), testRouteID, 1, testHostname, []byte{index}, csrHash, [32]byte{index})
		if err != nil {
			t.Fatal(err)
		}
		current = now
		issuance.Status = StatusFailed
		issuance.OrderStartedAt = now
		if err := store.saveIssuance(t.Context(), issuance); err != nil {
			t.Fatal(err)
		}
	}
	err = store.allowIssuanceCreation(t.Context(), testRouteID, 1, [32]byte{4}, now)
	var limit *RateLimitError
	if !errors.As(err, &limit) || !limit.RetryAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("rate limit error = %#v", err)
	}
}

func driveNormalIssuance(t *testing.T, service *Service, clock *testClock, csrDER []byte) Issuance {
	t.Helper()
	issuance := mustReachWaitingForChallenge(t, service, csrDER)
	var err error
	issuance, err = service.ChallengeReady(t.Context(), issuance.ID)
	if err != nil || issuance.Status != StatusWaitingChallenge || issuance.RetryAt.IsZero() {
		t.Fatalf("accept challenge = %+v, %v", issuance, err)
	}
	clock.Add(retryDelay + time.Second)
	issuance, err = service.ChallengeReady(t.Context(), issuance.ID)
	if err != nil || issuance.Status != StatusReadyToFinalize {
		t.Fatalf("validate challenge = %+v, %v", issuance, err)
	}
	issuance, err = service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusFinalizing {
		t.Fatalf("finalize order = %+v, %v", issuance, err)
	}
	clock.Add(retryDelay + time.Second)
	issuance, err = service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusWaitingForInstall {
		t.Fatalf("download certificate = %+v, %v", issuance, err)
	}
	return issuance
}

func mustReachWaitingForChallenge(t *testing.T, service *Service, csrDER []byte) Issuance {
	t.Helper()
	issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusAuthorizing {
		t.Fatalf("create order = %+v, %v", issuance, err)
	}
	issuance, err = service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusWaitingChallenge || issuance.Challenge() == nil {
		t.Fatalf("authorize = %+v, %v", issuance, err)
	}
	return issuance
}

func mustReachReadyToFinalize(t *testing.T, service *Service, csrDER []byte) Issuance {
	t.Helper()
	issuance, err := service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusAuthorizing {
		t.Fatalf("create order = %+v, %v", issuance, err)
	}
	issuance, err = service.Create(t.Context(), testRouteID, 1, "tlsserver", csrDER)
	if err != nil || issuance.Status != StatusReadyToFinalize {
		t.Fatalf("authorize = %+v, %v", issuance, err)
	}
	return issuance
}

func boundIssuance(t *testing.T, service *Service, csrDER []byte) Issuance {
	t.Helper()
	_, csrHash, _, err := validateCSR(csrDER, testHostname)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := service.store.findBoundIssuance(t.Context(), testRouteID, 1, csrHash)
	if err != nil {
		t.Fatal(err)
	}
	return issuance
}

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) Add(delay time.Duration) { c.now = c.now.Add(delay) }

type fakeACME struct {
	now                       time.Time
	certificate               []byte
	accountContact            string
	accepted                  bool
	finalized                 bool
	createOrderCalls          int
	getOrderCalls             int
	getAuthorizationCalls     int
	acceptChallengeCalls      int
	finalizeOrderCalls        int
	getCertificateCalls       int
	createAccountCalls        int
	updateAccountCalls        int
	authorizationStatuses     []string
	challengeStatuses         []string
	orderStatuses             []string
	createOrderErrors         []error
	getOrderErrors            []error
	getAuthorizationErrors    []error
	acceptChallengeErrors     []error
	acceptChallengeRetryAfter time.Duration
	finalizeErrors            []error
	getCertificateErrors      []error
	createOrderHook           func()
	getAuthorizationHook      func()
	finalizeHook              func()
	terms                     string
	updatedContact            string
}

func (f *fakeACME) Directory() legoacme.Directory {
	terms := f.terms
	if terms == "" {
		terms = "https://acme.test/terms"
	}
	return legoacme.Directory{Meta: legoacme.Meta{
		TermsOfService: terms,
		Profiles:       map[string]string{"tlsserver": "server certificate", "shortlived": "short-lived certificate"},
	}}
}

func (*fakeACME) KeyAuthorization(string) (string, error) { return "key-authorization", nil }

func (f *fakeACME) CreateAccount(_ context.Context, request legoacme.Account) (legoacme.ExtendedAccount, error) {
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
	if f.createOrderHook != nil {
		f.createOrderHook()
	}
	if err := popError(&f.createOrderErrors); err != nil {
		return legoacme.ExtendedOrder{}, err
	}
	return legoacme.ExtendedOrder{Order: legoacme.Order{
		Status: legoacme.StatusPending, Expires: f.now.Add(24 * time.Hour).Format(time.RFC3339), Profile: "tlsserver",
		Authorizations: []string{"https://acme.test/authz/1"}, Finalize: "https://acme.test/order/1/finalize",
	}, Location: "https://acme.test/order/1"}, nil
}

func (f *fakeACME) GetOrder(context.Context, string) (legoacme.ExtendedOrder, error) {
	f.getOrderCalls++
	if err := popError(&f.getOrderErrors); err != nil {
		return legoacme.ExtendedOrder{}, err
	}
	status := legoacme.StatusReady
	if len(f.orderStatuses) != 0 {
		status, f.orderStatuses = f.orderStatuses[0], f.orderStatuses[1:]
	} else if f.finalized {
		status = legoacme.StatusValid
	}
	certificateURL := ""
	if status == legoacme.StatusValid {
		certificateURL = "https://acme.test/certificate/1"
	}
	return legoacme.ExtendedOrder{Order: legoacme.Order{Status: status, Certificate: certificateURL}, Location: "https://acme.test/order/1"}, nil
}

func (f *fakeACME) GetAuthorization(context.Context, string) (legoacme.Authorization, error) {
	f.getAuthorizationCalls++
	if f.getAuthorizationHook != nil {
		f.getAuthorizationHook()
	}
	if err := popError(&f.getAuthorizationErrors); err != nil {
		return legoacme.Authorization{}, err
	}
	status := legoacme.StatusPending
	if len(f.authorizationStatuses) != 0 {
		status, f.authorizationStatuses = f.authorizationStatuses[0], f.authorizationStatuses[1:]
	} else if f.accepted {
		status = legoacme.StatusValid
	}
	challengeStatus := legoacme.StatusPending
	if len(f.challengeStatuses) != 0 {
		challengeStatus, f.challengeStatuses = f.challengeStatuses[0], f.challengeStatuses[1:]
	} else if f.accepted {
		challengeStatus = legoacme.StatusValid
	}
	return legoacme.Authorization{
		Status: status, Expires: f.now.Add(time.Hour), Identifier: legoacme.Identifier{Type: "dns", Value: testHostname},
		Challenges: []legoacme.Challenge{{
			Type: tlsALPNChallengeType, URL: "https://acme.test/challenge/1", Token: "token", Status: challengeStatus,
		}},
	}, nil
}

func (f *fakeACME) AcceptChallenge(context.Context, string) (legoacme.ExtendedChallenge, error) {
	f.acceptChallengeCalls++
	if err := popError(&f.acceptChallengeErrors); err != nil {
		return legoacme.ExtendedChallenge{}, err
	}
	f.accepted = true
	return legoacme.ExtendedChallenge{RetryAfter: f.acceptChallengeRetryAfter}, nil
}

func (f *fakeACME) FinalizeOrder(context.Context, string, []byte) (legoacme.ExtendedOrder, error) {
	f.finalizeOrderCalls++
	if f.finalizeHook != nil {
		f.finalizeHook()
	}
	if err := popError(&f.finalizeErrors); err != nil {
		return legoacme.ExtendedOrder{}, err
	}
	f.finalized = true
	return legoacme.ExtendedOrder{Order: legoacme.Order{Status: legoacme.StatusProcessing}, Location: "https://acme.test/order/1"}, nil
}

func (f *fakeACME) GetCertificate(context.Context, string) (*legoacme.RawCertificate, error) {
	f.getCertificateCalls++
	if err := popError(&f.getCertificateErrors); err != nil {
		return nil, err
	}
	return &legoacme.RawCertificate{Cert: f.certificate}, nil
}

func popError(values *[]error) error {
	if len(*values) == 0 {
		return nil
	}
	err := (*values)[0]
	*values = (*values)[1:]
	return err
}

func testService(t *testing.T, db *sql.DB, fake *fakeACME, roots *x509.CertPool, clock *testClock) *Service {
	t.Helper()
	return testServiceWithConfig(t, db, fake, roots, clock, testDirectoryURL, "tlsserver", func(context.Context, Issuance) error { return nil }, nil)
}

func testServiceWithConfig(
	t *testing.T,
	db *sql.DB,
	fake *fakeACME,
	roots *x509.CertPool,
	clock *testClock,
	directoryURL, profile string,
	probe ProbeFunc,
	hostnameReady func(context.Context, string) error,
) *Service {
	t.Helper()
	service, err := New(t.Context(), db, Config{
		DirectoryURL: directoryURL, Email: "operator@example.com", AcceptTerms: true, ACMEProfile: profile,
		Roots: roots, Probe: probe, HostnameReady: hostnameReady, Now: clock.Now,
		newACME: func(*http.Client, string, string, crypto.Signer) (acmeClient, error) { return fake, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := state.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	if err := queries.UpsertIdentity(t.Context(), statedb.UpsertIdentityParams{
		IdentityID: "identity", DisplayName: "Identity", Email: "identity@example.com", CreatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := queries.InsertHostname(t.Context(), statedb.InsertHostnameParams{
		ID: "hostname", IdentityID: "identity", Hostname: testHostname, CreatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := queries.InsertRoute(t.Context(), statedb.InsertRouteParams{
		RouteID: testRouteID, HostnameID: sql.NullString{String: "hostname", Valid: true}, IdentityID: "identity",
		Hostname: testHostname, LocalTarget: "http://127.0.0.1:3000", CreatedAt: 1,
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

func testCertificateChain(t *testing.T, leafKey *ecdsa.PrivateKey, hostname string, now time.Time) ([]byte, *x509.CertPool) {
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
