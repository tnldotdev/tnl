package certificateworker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestIntegrationPostgresPebbleCertificateWorker(t *testing.T) {
	postgresURL := os.Getenv("TNL_TEST_POSTGRES_URL")
	directoryURL := os.Getenv("TNL_TEST_ACME_DIRECTORY_URL")
	caFile := os.Getenv("TNL_TEST_ACME_CA_FILE")
	if postgresURL == "" || directoryURL == "" || caFile == "" {
		t.Skip("TNL_TEST_POSTGRES_URL, TNL_TEST_ACME_DIRECTORY_URL, and TNL_TEST_ACME_CA_FILE are not set")
	}
	database := newIntegrationDatabase(t, postgresURL)
	httpClient := integrationACMEHTTPClient(t, caFile)
	now := time.Now().UTC().Truncate(time.Microsecond)
	account, err := database.EnsureACMEAccount(t.Context(), directoryURL, "worker-integration@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	account, err = ReconcileAccount(t.Context(), database, httpClient, account, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if account.AccountURL == "" {
		t.Fatal("reconciled account has no account URL")
	}
	controlSession, err := database.CreateBuiltinControlSession(
		t.Context(), "tunnels.example.test", 1, time.Hour, 24*time.Hour, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := database.AuthenticateAccessToken(t.Context(), controlSession.AccessToken, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	membership := controlSession.Identity.Memberships[0]
	domains, err := database.ListTeamDomains(t.Context(), principal.IdentityID, membership.TeamID)
	if err != nil || len(domains) != 1 {
		t.Fatalf("managed domains = %#v, %v", domains, err)
	}
	randomValue := make([]byte, 6)
	if _, err := rand.Read(randomValue); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(randomValue)
	hostname := "worker-" + suffix + "." + membership.ManagedLabel + ".tunnels.example.test"
	route, err := database.CreateRoute(t.Context(), controlstate.CreateRouteRequest{
		TeamID: membership.TeamID, DomainID: domains[0].ID, MembershipID: membership.ID,
		ActingIdentityID: principal.IdentityID, IdempotencyKey: "worker-route-" + suffix,
		RequestDigest: sha256.Sum256([]byte("worker-route-" + suffix)), CanonicalHostname: hostname,
		Target: "http://127.0.0.1:3000", RouteScope: "member", DNSState: "unmanaged",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	leases := make(map[string]controlstate.RelayLease, 2)
	for index := range 2 {
		relayID := fmt.Sprintf("worker-relay-%s-%d", suffix, index)
		relayServiceID := fmt.Sprintf("worker-relay-service-%s-%d", suffix, index)
		lease, err := database.RegisterRelay(t.Context(), controlstate.RelayRegistration{
			RelayID: relayID, RelayServiceID: relayServiceID, RelayRunID: "run-" + relayID, ProtocolVersion: 1,
			RelayAddress: relayID + ".example.test:443", TLSServerName: relayID + ".example.test",
			InternalRelayAddress: relayID + ".internal:9443", ConnectionCapacity: 10, StreamCapacity: 100,
		}, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		leases[relayServiceID] = lease
	}
	setup, err := database.CreateRouteSession(t.Context(), controlstate.RouteSessionRequest{
		RouteID: route.ID, TeamID: route.TeamID, ActingIdentityID: principal.IdentityID,
		RetrySecret: principal.RetrySecret[:], IdempotencyKey: "worker-session-" + suffix,
		RequestDigest: sha256.Sum256([]byte("worker-session-" + suffix)), PolicyRevision: uint64(route.PolicyRevision),
		CertificateCacheKey: "worker-certificate-" + suffix, CertificateScope: "route",
		CertificateIdentifiers: []string{hostname}, CertificateChallenge: "tls-alpn-01",
		ExpectedMutationRevision: route.MutationRevision,
	}, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	connection := setup.PublisherConnections[0]
	credentialDigest, err := credentials.ParsePublisherConnectionCredential(connection.PublisherConnectionCredential)
	if err != nil {
		t.Fatal(err)
	}
	lease := leases[connection.RelayServiceID]
	claim := controlstate.PublisherConnectionClaimRequest{
		ConnectionAssignmentIdentity: connection.ConnectionAssignmentIdentity,
		RelayLeaseIdentity:           lease.RelayLeaseIdentity,
		ClaimID:                      "worker-claim-" + suffix, CredentialDigest: [32]byte(credentialDigest),
	}
	if _, err := database.ClaimPublisherConnection(t.Context(), claim, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.MarkPublisherConnectionReady(t.Context(), claim, now); err != nil {
		t.Fatal(err)
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader, &x509.CertificateRequest{DNSNames: []string{hostname}}, certificateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	authentication := controlstate.RouteSessionAuthentication{
		RouteSessionID: setup.RouteSessionID, RouteID: setup.RouteID,
		RouteVersion: setup.RouteVersion, SessionToken: setup.SessionToken,
	}
	issuance, err := database.CreateCertificateIssuance(t.Context(), controlstate.CreateCertificateIssuanceRequest{
		Authentication: authentication, DirectoryURL: directoryURL, IdempotencyKey: "worker-issuance-" + suffix,
		RequestDigest: sha256.Sum256([]byte("worker-issuance-" + suffix)), CSRDER: csrDER,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	firstWorker, err := New(database, Config{
		WorkerID: "certificate-worker-first-" + suffix, Profile: "tlsserver", HTTPClient: httpClient,
		LeaseDuration: 10 * time.Second, OperationTimeout: 5 * time.Second, PollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if found, err := firstWorker.processOne(t.Context()); err != nil || !found {
		t.Fatalf("initial worker iteration = %v, %v", found, err)
	}
	worker, err := New(database, Config{
		WorkerID: "certificate-worker-restarted-" + suffix, Profile: "tlsserver", HTTPClient: httpClient,
		LeaseDuration: 10 * time.Second, OperationTimeout: 5 * time.Second, PollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	issuance = advanceUntil(t, database, worker, issuance.ID, setup.SessionToken, func(value controlstate.CertificateIssuance) bool {
		return len(value.Challenges) == 1
	})
	if issuance.State != "authorizing" || issuance.Challenges[0].Method != "tls-alpn-01" {
		t.Fatalf("presenting issuance = %#v", issuance)
	}
	ingressNow := time.Now().UTC()
	ingressLease, err := database.RegisterIngress(t.Context(), controlstate.IngressRegistration{
		IngressID: "worker-ingress-" + suffix, IngressRunID: "worker-ingress-run-" + suffix,
		ProtocolVersion: 1, ConnectionCapacity: 10,
	}, ingressNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.MarkCertificateChallengeReady(t.Context(), issuance.ID, setup.SessionToken, time.Now()); err != nil {
		t.Fatal(err)
	}
	snapshotNow := time.Now().UTC()
	snapshot, err := database.ReadIngressRoutingTableSnapshot(
		t.Context(), ingressLease.IngressLeaseIdentity, snapshotNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RenewIngress(t.Context(), controlstate.IngressRenewal{
		IngressLeaseIdentity: ingressLease.IngressLeaseIdentity,
		RoutingTableRevision: snapshot.RoutingTableRevision,
	}, snapshotNow, time.Minute); err != nil {
		t.Fatal(err)
	}
	issuance = advanceUntil(t, database, worker, issuance.ID, setup.SessionToken, func(value controlstate.CertificateIssuance) bool {
		return value.State == "waiting_for_install"
	})
	if issuance.CertificatePEM == "" || issuance.NotBefore == nil || issuance.NotAfter == nil {
		t.Fatalf("issued certificate = %#v", issuance)
	}
	if _, err := database.MarkCertificateChallengeRemoved(t.Context(), issuance.ID, setup.SessionToken, time.Now()); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := database.MarkRouteCertificateInstalled(
		t.Context(), authentication, issuance.ID, *issuance.NotAfter, time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle.CertificateAt == nil || lifecycle.ReadyAt != nil || lifecycle.ReadyPublisherConnectionCount != 1 {
		t.Fatalf("certificate lifecycle = %#v", lifecycle)
	}
	runCtx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error, 1)
	go func() { runErr <- worker.Run(runCtx) }()
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("worker cancellation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
}

func advanceUntil(
	t *testing.T,
	database *controlstate.Database,
	worker *Worker,
	issuanceID string,
	sessionToken credentials.SessionToken,
	complete func(controlstate.CertificateIssuance) bool,
) controlstate.CertificateIssuance {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		if _, err := worker.processOne(ctx); err != nil {
			t.Fatal(err)
		}
		issuance, err := database.GetCertificateIssuance(ctx, issuanceID, sessionToken, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if complete(issuance) {
			return issuance
		}
		if issuance.State == "failed" || issuance.State == "canceled" {
			t.Fatalf("certificate issuance became %q", issuance.State)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func newIntegrationDatabase(t *testing.T, directURL string) *controlstate.Database {
	t.Helper()
	adminConfig, err := pgx.ParseConfig(directURL)
	if err != nil {
		t.Fatal(err)
	}
	adminDB := stdlib.OpenDB(*adminConfig)
	t.Cleanup(func() { _ = adminDB.Close() })
	databaseName := "tnl_certificateworker_" + randomHex(t, 8)
	identifier := pgx.Identifier{databaseName}.Sanitize()
	if _, err := adminDB.ExecContext(t.Context(), "CREATE DATABASE "+identifier); err != nil {
		t.Skipf("certificate worker integration requires permission to create a database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = adminDB.ExecContext(cleanupCtx, `
			SELECT pg_terminate_backend(pid)
			FROM pg_stat_activity
			WHERE datname = $1 AND pid <> pg_backend_pid()
		`, databaseName)
		_, _ = adminDB.ExecContext(cleanupCtx, "DROP DATABASE IF EXISTS "+identifier)
	})
	testURL, err := databaseURLWithName(directURL, databaseName)
	if err != nil {
		t.Fatal(err)
	}
	if err := controlstate.Migrate(t.Context(), testURL); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), testURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	return database
}

func integrationACMEHTTPClient(t *testing.T, caFile string) *http.Client {
	t.Helper()
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("ACME CA file contains no certificates")
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}},
		Timeout:   10 * time.Second,
	}
}

func databaseURLWithName(rawURL, databaseName string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	parsed.Path = "/" + databaseName
	return parsed.String(), nil
}

func randomHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}
