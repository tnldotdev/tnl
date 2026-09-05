package controlstate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/routeusage"
	"github.com/tnldotdev/tnl/internal/servicepki"
	"golang.org/x/crypto/acme/autocert"
)

func TestIntegrationPostgresMigrationAndOpen(t *testing.T) {
	directURL := os.Getenv("TNL_TEST_POSTGRES_URL")
	if directURL == "" {
		t.Skip("TNL_TEST_POSTGRES_URL is not set")
	}

	adminConfig, err := parseDirectConfig(directURL)
	if err != nil {
		t.Fatalf("parse TNL_TEST_POSTGRES_URL: %v", err)
	}
	adminDB := stdlib.OpenDB(*adminConfig)
	t.Cleanup(func() { _ = adminDB.Close() })
	if err := adminDB.PingContext(t.Context()); err != nil {
		t.Fatalf("connect using TNL_TEST_POSTGRES_URL: %v", err)
	}

	databaseName := "tnl_controlstate_" + randomHex(t, 8)
	identifier := pgx.Identifier{databaseName}.Sanitize()
	if _, err := adminDB.ExecContext(t.Context(), "CREATE DATABASE "+identifier); err != nil {
		t.Skipf("fixed control schema requires a disposable database and the configured role cannot create one: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), bootstrapRetryDelay*400)
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
	const migrationCallers = 4
	migrationErrors := make(chan error, migrationCallers)
	var migrations sync.WaitGroup
	for range migrationCallers {
		migrations.Add(1)
		go func() {
			defer migrations.Done()
			migrationErrors <- Migrate(t.Context(), testURL)
		}()
	}
	migrations.Wait()
	close(migrationErrors)
	for err := range migrationErrors {
		if err != nil {
			t.Fatalf("concurrent migration: %v", err)
		}
	}
	if err := Migrate(t.Context(), testURL); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}

	database, err := Open(t.Context(), testURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Health(t.Context()); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Readiness(t.Context()); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if database.pool.Config().ConnConfig.DefaultQueryExecMode != pgx.QueryExecModeExec {
		database.Close()
		t.Fatalf("query execution mode = %v, want %v", database.pool.Config().ConnConfig.DefaultQueryExecMode, pgx.QueryExecModeExec)
	}

	for _, table := range []string{
		"identities",
		"teams",
		"domains",
		"routes",
		"route_sessions",
		"route_session_connections",
		"relay_services",
		"service_authorities",
		"service_enrollment_tokens",
		"service_enrollment_events",
		"relay_leases",
		"ingress_leases",
		"ingress_routing_table_events",
		"control_tls_cache",
		"acme_orders",
		"route_usage_buckets",
		"route_recovery_episodes",
		"admin_audit_events",
	} {
		var exists bool
		if err := database.pool.QueryRow(t.Context(), `
			SELECT EXISTS (
				SELECT 1
				FROM information_schema.tables
				WHERE table_schema = 'control' AND table_name = $1
			)
		`, table).Scan(&exists); err != nil {
			database.Close()
			t.Fatal(err)
		}
		if !exists {
			database.Close()
			t.Fatalf("control.%s does not exist", table)
		}
	}
	testBuiltinAuthentication(t, database)
	testControlTLSState(t, database)
	testRouteManagement(t, database)
	testRouteSessionCreation(t, database)
	testIngressUsage(t, database)
	testRelayControlState(t, database)

	var version int64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT MAX(version_id) FILTER (WHERE is_applied)
		FROM control.goose_db_version
	`).Scan(&version); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if version != schemaVersion {
		database.Close()
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.goose_db_version (version_id, is_applied)
		VALUES ($1, true)
	`, schemaVersion+1); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Readiness(t.Context()); err == nil {
		database.Close()
		t.Fatal("Readiness succeeded with an incompatible schema version")
	}
	database.Close()

	if incompatible, err := Open(t.Context(), testURL); err == nil {
		incompatible.Close()
		t.Fatal("Open succeeded with an incompatible schema version")
	}
}

func testControlTLSState(t *testing.T, database *Database) {
	t.Helper()
	cache, err := database.ControlTLSCache("https://acme.example.test/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(t.Context(), "control.example.test"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("missing control TLS cache error = %v", err)
	}
	if err := cache.Put(t.Context(), "control.example.test", []byte("certificate state")); err != nil {
		t.Fatal(err)
	}
	data, err := cache.Get(t.Context(), "control.example.test")
	if err != nil || string(data) != "certificate state" {
		t.Fatalf("control TLS cache data = %q, %v", data, err)
	}
	if err := cache.Delete(t.Context(), "control.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(t.Context(), "control.example.test"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("deleted control TLS cache error = %v", err)
	}

	firstStarted := make(chan struct{})
	firstRelease := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- database.RunControlTLSLeader(t.Context(), func(context.Context) error {
			close(firstStarted)
			<-firstRelease
			return nil
		})
	}()
	select {
	case <-firstStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first control TLS leader did not start")
	}
	secondCtx, cancelSecond := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancelSecond()
	secondRan := false
	if err := database.RunControlTLSLeader(secondCtx, func(context.Context) error {
		secondRan = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if secondRan {
		t.Fatal("concurrent control TLS leader ran")
	}
	close(firstRelease)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	thirdRan := false
	if err := database.RunControlTLSLeader(t.Context(), func(context.Context) error {
		thirdRan = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !thirdRan {
		t.Fatal("replacement control TLS leader did not run")
	}
}

func testBuiltinAuthentication(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	const callers = 4
	results := make(chan ControlSession, callers)
	exchangeErrors := make(chan error, callers)
	var exchanges sync.WaitGroup
	for range callers {
		exchanges.Add(1)
		go func() {
			defer exchanges.Done()
			result, err := database.CreateBuiltinControlSession(
				t.Context(), "tunnels.example.test", 7, time.Hour, 24*time.Hour, now,
			)
			results <- result
			exchangeErrors <- err
		}()
	}
	exchanges.Wait()
	close(results)
	close(exchangeErrors)
	for err := range exchangeErrors {
		if err != nil {
			t.Fatalf("concurrent builtin authentication: %v", err)
		}
	}
	issued := <-results
	if issued.Identity.Identity.ID == "" || issued.Identity.PersonalTeamID == "" ||
		len(issued.Identity.Memberships) != 1 || issued.Identity.Memberships[0].Role != "owner" {
		t.Fatalf("builtin identity context = %#v", issued.Identity)
	}
	teamRows, err := database.ListTeams(t.Context(), issued.Identity.Identity.ID)
	if err != nil || len(teamRows) != 1 || teamRows[0].ID != issued.Identity.PersonalTeamID || teamRows[0].DefaultDomainID == "" {
		t.Fatalf("builtin teams = %#v, %v", teamRows, err)
	}
	team, err := database.GetTeam(t.Context(), issued.Identity.Identity.ID, issued.Identity.PersonalTeamID)
	if err != nil || team != teamRows[0] {
		t.Fatalf("builtin team = %#v, %v", team, err)
	}
	domainsForTeam, err := database.ListTeamDomains(t.Context(), issued.Identity.Identity.ID, team.ID)
	if err != nil || len(domainsForTeam) != 1 || domainsForTeam[0].CanonicalDomain != "tunnels.example.test" ||
		domainsForTeam[0].ID != team.DefaultDomainID {
		t.Fatalf("builtin team domains = %#v, %v", domainsForTeam, err)
	}
	principal, err := database.AuthenticateAccessToken(t.Context(), issued.AccessToken, 7, now)
	if err != nil || principal.IdentityID != issued.Identity.Identity.ID || !principal.Administrator {
		t.Fatalf("authenticated principal = %#v, %v", principal, err)
	}
	testServiceEnrollmentState(t, database, principal.IdentityID, now.Add(time.Second))
	retrySecret := principal.RetrySecret
	if _, err := database.AuthenticateAccessToken(t.Context(), issued.AccessToken, 8, now); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("stale login source authentication error = %v", err)
	}
	if _, err := database.CreateBuiltinControlSession(
		t.Context(), "other.example.test", 7, time.Hour, 24*time.Hour, now,
	); !errors.Is(err, ErrManagedDomainMismatch) {
		t.Fatalf("managed domain mismatch error = %v", err)
	}

	refreshed, err := database.RefreshControlSession(t.Context(), issued.RefreshToken, 7, time.Hour, now.Add(time.Minute))
	if err != nil || refreshed.SessionID != issued.SessionID || !refreshed.RefreshExpiresAt.Equal(issued.RefreshExpiresAt) {
		t.Fatalf("refreshed control session = %#v, %v", refreshed, err)
	}
	if _, err := database.AuthenticateAccessToken(t.Context(), issued.AccessToken, 7, now.Add(time.Minute)); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("rotated access-token error = %v", err)
	}
	if _, err := database.RefreshControlSession(t.Context(), issued.RefreshToken, 7, time.Hour, now.Add(time.Minute)); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("rotated refresh-token error = %v", err)
	}
	principal, err = database.AuthenticateAccessToken(t.Context(), refreshed.AccessToken, 7, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if principal.RetrySecret == ([32]byte{}) || principal.RetrySecret != retrySecret {
		t.Fatal("control-session retry secret changed during credential rotation")
	}
	if err := database.RevokeControlSession(t.Context(), principal, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AuthenticateAccessToken(t.Context(), refreshed.AccessToken, 7, now.Add(2*time.Minute)); !errors.Is(err, ErrControlAuthentication) {
		t.Fatalf("revoked access-token error = %v", err)
	}

	var identities, teams, memberships, domains int
	if err := database.pool.QueryRow(t.Context(), `
		SELECT
			(SELECT count(*) FROM control.identities WHERE kind = 'builtin'),
			(SELECT count(*) FROM control.teams WHERE kind = 'personal'),
			(SELECT count(*) FROM control.team_memberships),
			(SELECT count(*) FROM control.domains WHERE kind = 'managed')
	`).Scan(&identities, &teams, &memberships, &domains); err != nil {
		t.Fatal(err)
	}
	if identities != 1 || teams != 1 || memberships != 1 || domains != 1 {
		t.Fatalf("bootstrap row counts = identities %d, teams %d, memberships %d, domains %d", identities, teams, memberships, domains)
	}
}

func testServiceEnrollmentState(t *testing.T, database *Database, administratorID string, now time.Time) {
	t.Helper()

	const initializationCount = 4
	authorities := make(chan ServiceAuthority, initializationCount)
	errorsByInitialization := make(chan error, initializationCount)
	var initializations sync.WaitGroup
	for range initializationCount {
		initializations.Add(1)
		go func() {
			defer initializations.Done()
			authority, err := database.EnsureServiceAuthority(t.Context(), now)
			authorities <- authority
			errorsByInitialization <- err
		}()
	}
	initializations.Wait()
	close(authorities)
	close(errorsByInitialization)
	for err := range errorsByInitialization {
		if err != nil {
			t.Fatalf("initialize service authority: %v", err)
		}
	}
	var authorityPEM string
	for authority := range authorities {
		if authorityPEM == "" {
			authorityPEM = authority.CertificatePEM
		} else if authority.CertificatePEM != authorityPEM {
			t.Fatal("concurrent service authority initialization returned different roots")
		}
	}

	ingressToken, err := database.CreateServiceEnrollmentToken(t.Context(), CreateServiceEnrollmentTokenRequest{
		Role: ServiceEnrollmentRoleIngress, ActorIdentityID: administratorID,
		AuditRequestID: "request_enrollment_ingress", CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	relayToken, err := database.CreateServiceEnrollmentToken(t.Context(), CreateServiceEnrollmentTokenRequest{
		Role: ServiceEnrollmentRoleRelay, RelayServiceID: "relay-a",
		RelayAddress: "relay-a.example.test:443", TLSServerName: "relay-a.example.test",
		ActorIdentityID: administratorID, AuditRequestID: "request_enrollment_relay", CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	csr := serviceEnrollmentCSR(t)
	if _, err := database.EnrollService(t.Context(), ServiceEnrollmentRequest{
		Token: ingressToken.Token, Role: ServiceEnrollmentRoleRelay, ProcessID: "relay-wrong-role",
		CSRPEM: csr, EnrolledAt: now.Add(time.Minute),
	}); !errors.Is(err, ErrServiceEnrollmentCredential) {
		t.Fatalf("cross-role enrollment error = %v", err)
	}
	ingressEnrollment, err := database.EnrollService(t.Context(), ServiceEnrollmentRequest{
		Token: ingressToken.Token, Role: ServiceEnrollmentRoleIngress, ProcessID: "ingress-a",
		CSRPEM: csr, EnrolledAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ingressEnrollment.TrustBundlePEM != authorityPEM || ingressEnrollment.RelayTransportMaterial != nil ||
		!ingressEnrollment.CertificateExpiresAt.Equal(now.Add(time.Minute+time.Hour)) {
		t.Fatalf("ingress enrollment = %#v", ingressEnrollment)
	}
	ingressCertificate := parsePEMCertificate(t, ingressEnrollment.ServiceCertificatePEM)
	ingressIdentity, err := servicepki.CertificateIdentity(ingressCertificate)
	if err != nil || ingressIdentity != (servicepki.Identity{Role: servicepki.RoleIngress, ProcessID: "ingress-a"}) {
		t.Fatalf("ingress certificate identity = %#v, %v", ingressIdentity, err)
	}

	relayEnrollment, err := database.EnrollService(t.Context(), ServiceEnrollmentRequest{
		Token: relayToken.Token, Role: ServiceEnrollmentRoleRelay, ProcessID: "relay-a-1",
		CSRPEM: serviceEnrollmentCSR(t), EnrolledAt: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if relayEnrollment.RelayServiceID != "relay-a" || relayEnrollment.RelayAddress != "relay-a.example.test:443" ||
		relayEnrollment.TLSServerName != "relay-a.example.test" || relayEnrollment.RelayTransportMaterial == nil {
		t.Fatalf("relay enrollment = %#v", relayEnrollment)
	}
	repeatedRelayEnrollment, err := database.EnrollService(t.Context(), ServiceEnrollmentRequest{
		Token: relayToken.Token, Role: ServiceEnrollmentRoleRelay, ProcessID: "relay-a-2",
		CSRPEM: serviceEnrollmentCSR(t), EnrolledAt: now.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if repeatedRelayEnrollment.RelayTransportMaterial.CertificatePEM != relayEnrollment.RelayTransportMaterial.CertificatePEM ||
		repeatedRelayEnrollment.RelayTransportMaterial.PrivateKeyPEM != relayEnrollment.RelayTransportMaterial.PrivateKeyPEM {
		t.Fatal("relay processes in one service received different transport material")
	}
	for _, identity := range []struct{ serviceID, relayID string }{
		{serviceID: "standalone-a", relayID: "standalone-relay-a"},
		{serviceID: "standalone-b", relayID: "standalone-relay-b"},
	} {
		local, err := database.EnrollLocalService(t.Context(), LocalServiceEnrollmentRequest{
			Role: ServiceEnrollmentRoleRelay, ProcessID: identity.relayID,
			CSRPEM: serviceEnrollmentCSR(t), RelayServiceID: identity.serviceID,
			RelayAddress: "relay.example.test:443", TLSServerName: "relay.example.test",
			EnrolledAt: now.Add(3 * time.Minute),
		})
		if err != nil {
			t.Fatalf("enroll local relay %q: %v", identity.serviceID, err)
		}
		certificate := parsePEMCertificate(t, local.ServiceCertificatePEM)
		got, err := servicepki.CertificateIdentity(certificate)
		want := servicepki.Identity{Role: servicepki.RoleRelay, ProcessID: identity.relayID, RelayServiceID: identity.serviceID}
		if err != nil || got != want || local.RelayTransportMaterial == nil {
			t.Fatalf("local relay enrollment = %#v, identity %#v, %v", local, got, err)
		}
	}

	if _, err := database.RevokeServiceEnrollmentToken(
		t.Context(), ingressToken.EnrollmentToken.ID, administratorID, "request_revoke_ingress", now.Add(4*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.EnrollService(t.Context(), ServiceEnrollmentRequest{
		Token: ingressToken.Token, Role: ServiceEnrollmentRoleIngress, ProcessID: "ingress-b",
		CSRPEM: serviceEnrollmentCSR(t), EnrolledAt: now.Add(5 * time.Minute),
	}); !errors.Is(err, ErrServiceEnrollmentCredential) {
		t.Fatalf("revoked token enrollment error = %v", err)
	}
	tokens, err := database.ListServiceEnrollmentTokens(t.Context())
	if err != nil || len(tokens) != 2 {
		t.Fatalf("service enrollment tokens = %#v, %v", tokens, err)
	}
	var authorityCount, enrollmentEventCount int
	if err := database.pool.QueryRow(t.Context(), `
		SELECT
			(SELECT count(*) FROM control.service_authorities),
			(SELECT count(*) FROM control.service_enrollment_events)
	`).Scan(&authorityCount, &enrollmentEventCount); err != nil {
		t.Fatal(err)
	}
	if authorityCount != 1 || enrollmentEventCount != 3 {
		t.Fatalf("service PKI rows = authorities %d, enrollment events %d", authorityCount, enrollmentEventCount)
	}
}

func serviceEnrollmentCSR(t *testing.T) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func parsePEMCertificate(t *testing.T, certificatePEM string) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode([]byte(certificatePEM))
	if block == nil || len(rest) != 0 {
		t.Fatal("certificate is not one PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func testRouteManagement(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	session, err := database.CreateBuiltinControlSession(
		t.Context(), "tunnels.example.test", 7, time.Hour, 24*time.Hour, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := database.AuthenticateAccessToken(t.Context(), session.AccessToken, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	membership := session.Identity.Memberships[0]
	domains, err := database.ListTeamDomains(t.Context(), principal.IdentityID, membership.TeamID)
	if err != nil || len(domains) != 1 {
		t.Fatalf("route test domains = %#v, %v", domains, err)
	}
	request := CreateRouteRequest{
		TeamID: membership.TeamID, DomainID: domains[0].ID, MembershipID: membership.ID,
		ActingIdentityID: principal.IdentityID, IdempotencyKey: "route-management-create",
		RequestDigest:     sha256.Sum256([]byte("route-management-create")),
		CanonicalHostname: "demo." + membership.ManagedLabel + ".tunnels.example.test",
		Target:            "http://127.0.0.1:3000", RouteScope: "member", DNSState: "unmanaged",
	}
	route, err := database.CreateRoute(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if route.TeamID != request.TeamID || route.MembershipID != request.MembershipID ||
		route.CanonicalHostname != request.CanonicalHostname || route.PolicyRevision != membership.PolicyRevision ||
		route.NextRouteVersion != 1 || route.LifecycleState != "enabled" {
		t.Fatalf("created route = %#v", route)
	}
	repeated, err := database.CreateRoute(t.Context(), request, now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeated, route) {
		t.Fatalf("idempotent route = %#v, %v", repeated, err)
	}
	changed := request
	changed.RequestDigest = sha256.Sum256([]byte("route-management-changed"))
	if _, err := database.CreateRoute(t.Context(), changed, now.Add(2*time.Second)); !errors.Is(err, ErrRouteIdempotency) {
		t.Fatalf("route idempotency error = %v", err)
	}
	conflict := request
	conflict.IdempotencyKey = "route-management-conflict"
	conflict.RequestDigest = sha256.Sum256([]byte("route-management-conflict"))
	if _, err := database.CreateRoute(t.Context(), conflict, now.Add(3*time.Second)); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("route hostname conflict error = %v", err)
	}
	concurrent := request
	concurrent.IdempotencyKey = "route-management-concurrent"
	concurrent.RequestDigest = sha256.Sum256([]byte("route-management-concurrent"))
	concurrent.CanonicalHostname = "concurrent." + membership.ManagedLabel + ".tunnels.example.test"
	const concurrentCallers = 4
	created := make(chan Route, concurrentCallers)
	creationErrors := make(chan error, concurrentCallers)
	var creations sync.WaitGroup
	for range concurrentCallers {
		creations.Add(1)
		go func() {
			defer creations.Done()
			createdRoute, err := database.CreateRoute(t.Context(), concurrent, now.Add(4*time.Second))
			created <- createdRoute
			creationErrors <- err
		}()
	}
	creations.Wait()
	close(created)
	close(creationErrors)
	for err := range creationErrors {
		if err != nil {
			t.Fatalf("concurrent route creation: %v", err)
		}
	}
	var concurrentRoute Route
	for createdRoute := range created {
		if concurrentRoute.ID == "" {
			concurrentRoute = createdRoute
		} else if !reflect.DeepEqual(createdRoute, concurrentRoute) {
			t.Fatalf("concurrent route = %#v, want %#v", createdRoute, concurrentRoute)
		}
	}
	deeper := request
	deeper.IdempotencyKey = "route-management-deeper"
	deeper.RequestDigest = sha256.Sum256([]byte("route-management-deeper"))
	deeper.CanonicalHostname = "too.deep." + membership.ManagedLabel + ".tunnels.example.test"
	if _, err := database.CreateRoute(t.Context(), deeper, now.Add(5*time.Second)); !errors.Is(err, ErrRouteAccess) {
		t.Fatalf("deep member hostname error = %v", err)
	}
	page, err := database.ListRoutes(t.Context(), principal.IdentityID, membership.TeamID, "")
	if err != nil || len(page.Routes) != 2 || page.NextCursor != "" {
		t.Fatalf("route page = %#v, %v", page, err)
	}
	loaded, err := database.GetRoute(t.Context(), principal.IdentityID, route.ID)
	if err != nil || !reflect.DeepEqual(loaded, route) {
		t.Fatalf("loaded route = %#v, %v", loaded, err)
	}
	if err := database.DeleteRoute(t.Context(), principal.IdentityID, route.ID, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.DeleteRoute(t.Context(), principal.IdentityID, concurrentRoute.ID, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetRoute(t.Context(), principal.IdentityID, route.ID); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("deleted route read error = %v", err)
	}
	if _, err := database.CreateRoute(t.Context(), request, now.Add(7*time.Second)); !errors.Is(err, ErrRouteIdempotency) {
		t.Fatalf("deleted route retry error = %v", err)
	}
}

func testRouteSessionCreation(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	seedControlRoute(t, database, now, "session")
	placementLeases := make(map[string]RelayLease, routeSessionConnectionCount)
	for index := range routeSessionConnectionCount {
		name := fmt.Sprintf("placement_%d", index)
		lease, err := database.RegisterRelay(t.Context(), RelayRegistration{
			RelayServiceID: name, RelayID: "relay_" + name, RelayRunID: "run_" + name, ProtocolVersion: 1,
			RelayAddress: name + ".example:443", TLSServerName: name + ".example",
			InternalRelayAddress: name + ".internal:9443", ConnectionCapacity: 10, StreamCapacity: 100,
		}, now, time.Minute)
		if err != nil {
			t.Fatalf("register placement relay %q: %v", name, err)
		}
		placementLeases[name] = lease
	}
	request := RouteSessionRequest{
		RouteID: "route_session", TeamID: "team_session", ActingIdentityID: "identity_session",
		RetrySecret: bytes.Repeat([]byte{7}, 32), IdempotencyKey: "request_session_1",
		RequestDigest: sha256.Sum256([]byte("request-session-1")), PolicyRevision: 1,
		CertificateCacheKey: "certificate_session", CertificateScope: "route",
		CertificateIdentifiers: []string{"route-session.example.test"}, CertificateChallenge: "tls-alpn-01",
		AllowedIPPrefixes: []string{"192.0.2.0/24"},
	}
	setup, err := database.CreateRouteSession(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if setup.RouteID != request.RouteID || setup.RouteVersion != 1 || setup.State != "starting" || setup.SessionToken == "" {
		t.Fatalf("route session setup = %#v", setup)
	}
	route, err := database.GetRoute(t.Context(), "identity_session", request.RouteID)
	if err != nil || !reflect.DeepEqual(route.AllowedIPPrefixes, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}) {
		t.Fatalf("route policy = %#v, %v", route.AllowedIPPrefixes, err)
	}
	services := make(map[string]bool)
	for slot, connection := range setup.PublisherConnections {
		if connection.ConnectionSlot != slot || connection.RouteSessionID != setup.RouteSessionID ||
			connection.RouteID != setup.RouteID || connection.RouteVersion != setup.RouteVersion ||
			connection.ConnectionAssignmentRevision != 1 {
			t.Fatalf("publisher connection slot %d = %#v", slot, connection)
		}
		if _, err := credentials.ParsePublisherConnectionCredential(connection.PublisherConnectionCredential); err != nil {
			t.Fatalf("publisher connection slot %d credential: %v", slot, err)
		}
		services[connection.RelayServiceID] = true
	}
	if len(services) != routeSessionConnectionCount {
		t.Fatalf("relay services = %#v", services)
	}
	repeated, err := database.CreateRouteSession(t.Context(), request, now.Add(time.Second), 30*time.Second, time.Minute)
	if err != nil || !reflect.DeepEqual(repeated, setup) {
		t.Fatalf("idempotent route session setup = %#v, %v", repeated, err)
	}
	changed := request
	changed.RequestDigest = sha256.Sum256([]byte("different request"))
	if _, err := database.CreateRouteSession(t.Context(), changed, now.Add(2*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrRouteSessionIdempotency) {
		t.Fatalf("idempotency conflict error = %v", err)
	}
	changed = request
	changed.IdempotencyKey = "request_session_2"
	changed.RequestDigest = sha256.Sum256([]byte("request-session-2"))
	changed.AllowedIPPrefixes = []string{}
	if _, err := database.CreateRouteSession(t.Context(), changed, now.Add(3*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrRouteSessionConflict) {
		t.Fatalf("live route session conflict error = %v", err)
	}
	route, err = database.GetRoute(t.Context(), "identity_session", request.RouteID)
	if err != nil || !reflect.DeepEqual(route.AllowedIPPrefixes, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}) {
		t.Fatalf("failed session changed route policy = %#v, %v", route.AllowedIPPrefixes, err)
	}
	staleAuthority := changed
	staleAuthority.PolicyRevision = 2
	if _, err := database.CreateRouteSession(t.Context(), staleAuthority, now.Add(4*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrRouteAuthority) {
		t.Fatalf("stale route authority error = %v", err)
	}

	closedAt := now.Add(5 * time.Second)
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.route_sessions
		SET state = 'closed', closed_at = $2, close_reason = 'test'
		WHERE id = $1
	`, setup.RouteSessionID, closedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.maintenance_controls
		SET enabled = false, revision = revision + 1, updated_at = $1, updated_by = 'test'
		WHERE control_name = 'route_session_creation'
	`, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	closedSetup := setup
	closedSetup.State = "closed"
	retry, err := database.CreateRouteSession(t.Context(), request, now.Add(7*time.Second), 30*time.Second, time.Minute)
	if retry.ClosedAt == nil || !retry.ClosedAt.Equal(closedAt) {
		t.Fatalf("idempotent route session close time = %v, want %v", retry.ClosedAt, closedAt)
	}
	retry.ClosedAt = nil
	if err != nil || !reflect.DeepEqual(retry, closedSetup) {
		t.Fatalf("gated idempotent retry = %#v, %v", retry, err)
	}
	if _, err := database.CreateRouteSession(t.Context(), changed, now.Add(8*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrRouteSessionCreationGated) {
		t.Fatalf("gated route session error = %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.maintenance_controls
		SET enabled = true, revision = revision + 1, updated_at = $1, updated_by = 'test'
		WHERE control_name = 'route_session_creation'
	`, now.Add(9*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.relay_leases SET draining = true, drain_deadline = $1
		WHERE relay_service_id LIKE 'placement_%'
	`, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRouteSession(t.Context(), changed, now.Add(10*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrInsufficientRelayServices) {
		t.Fatalf("insufficient placement error = %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.relay_leases SET draining = false, drain_deadline = NULL
		WHERE relay_service_id LIKE 'placement_%'
	`); err != nil {
		t.Fatal(err)
	}
	replacement, err := database.CreateRouteSession(t.Context(), changed, now.Add(11*time.Second), 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.RouteVersion != 2 || replacement.RouteSessionID == setup.RouteSessionID || replacement.SessionToken == setup.SessionToken {
		t.Fatalf("replacement route session = %#v", replacement)
	}
	route, err = database.GetRoute(t.Context(), "identity_session", request.RouteID)
	if err != nil || len(route.AllowedIPPrefixes) != 0 {
		t.Fatalf("replacement route policy = %#v, %v", route.AllowedIPPrefixes, err)
	}
	testRouteSessionReadiness(t, database, request, replacement, placementLeases, now.Add(12*time.Second))
}

func testRouteSessionReadiness(
	t *testing.T,
	database *Database,
	request RouteSessionRequest,
	setup RouteSessionSetup,
	leases map[string]RelayLease,
	now time.Time,
) {
	t.Helper()
	ingressLease, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_readiness", IngressRunID: "run_readiness", ProtocolVersion: 1,
		ConnectionCapacity: 100,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authentication := RouteSessionAuthentication{
		RouteSessionID: setup.RouteSessionID, RouteID: setup.RouteID,
		RouteVersion: setup.RouteVersion, SessionToken: setup.SessionToken,
	}
	claims := make([]PublisherConnectionClaimRequest, 0, len(setup.PublisherConnections))
	claimConnection := func(slot int, at time.Time) {
		plan := setup.PublisherConnections[slot]
		digest, err := credentials.ParsePublisherConnectionCredential(plan.PublisherConnectionCredential)
		if err != nil {
			t.Fatal(err)
		}
		lease := leases[plan.RelayServiceID]
		claim := PublisherConnectionClaimRequest{
			ConnectionAssignmentIdentity: plan.ConnectionAssignmentIdentity,
			RelayLeaseIdentity:           lease.RelayLeaseIdentity,
			ClaimID:                      fmt.Sprintf("readiness_claim_%d", slot), CredentialDigest: [32]byte(digest),
		}
		if _, err := database.ClaimPublisherConnection(t.Context(), claim, at); err != nil {
			t.Fatal(err)
		}
		if _, err := database.MarkPublisherConnectionReady(t.Context(), claim, at); err != nil {
			t.Fatal(err)
		}
		claims = append(claims, claim)
	}
	claimConnection(0, now)
	account, err := database.EnsureACMEAccount(
		t.Context(), "https://acme.example.test/directory", "operator@example.test", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	repeatedAccount, err := database.EnsureACMEAccount(
		t.Context(), "https://acme.example.test/directory", "operator@example.test", now.Add(time.Millisecond),
	)
	if err != nil || repeatedAccount.ID != account.ID || !bytes.Equal(repeatedAccount.AccountKeyDER, account.AccountKeyDER) {
		t.Fatalf("idempotent ACME account = %#v, %v", repeatedAccount, err)
	}
	registeredAccount, err := database.UpdateACMEAccountRegistration(
		t.Context(), account.ID, account.ContactEmail, "https://acme.example.test/account/1",
		"https://acme.example.test/terms", now.Add(2*time.Millisecond),
	)
	if err != nil || registeredAccount.AccountURL != "https://acme.example.test/account/1" ||
		registeredAccount.AcceptedTerms != "https://acme.example.test/terms" {
		t.Fatalf("registered ACME account = %#v, %v", registeredAccount, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader, &x509.CertificateRequest{DNSNames: []string{request.CertificateIdentifiers[0]}}, key,
	)
	if err != nil {
		t.Fatal(err)
	}
	issuanceRequest := CreateCertificateIssuanceRequest{
		Authentication: authentication, DirectoryURL: account.DirectoryURL,
		IdempotencyKey: "issuance-readiness", RequestDigest: sha256.Sum256([]byte("issuance-readiness")), CSRDER: csrDER,
	}
	issuance, err := database.CreateCertificateIssuance(t.Context(), issuanceRequest, now)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.State != "pending" || issuance.RouteSessionID != setup.RouteSessionID ||
		issuance.RouteVersion != setup.RouteVersion || !reflect.DeepEqual(issuance.CertificatePlan.Identifiers, request.CertificateIdentifiers) {
		t.Fatalf("certificate issuance = %#v", issuance)
	}
	repeatedIssuance, err := database.CreateCertificateIssuance(t.Context(), issuanceRequest, now.Add(time.Millisecond))
	if err != nil || !reflect.DeepEqual(repeatedIssuance, issuance) {
		t.Fatalf("idempotent certificate issuance = %#v, %v", repeatedIssuance, err)
	}
	changedIssuance := issuanceRequest
	changedIssuance.RequestDigest = sha256.Sum256([]byte("issuance-changed"))
	if _, err := database.CreateCertificateIssuance(t.Context(), changedIssuance, now.Add(2*time.Millisecond)); !errors.Is(err, ErrCertificateIssuanceIdempotency) {
		t.Fatalf("certificate issuance idempotency error = %v", err)
	}
	loadedIssuance, err := database.GetCertificateIssuance(t.Context(), issuance.ID, setup.SessionToken, now)
	if err != nil || !reflect.DeepEqual(loadedIssuance, issuance) {
		t.Fatalf("loaded certificate issuance = %#v, %v", loadedIssuance, err)
	}
	firstWork, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-worker-1", now.Add(3*time.Millisecond), 10*time.Millisecond)
	if err != nil || !found || firstWork.ID != issuance.ID || firstWork.WorkEpoch != 1 ||
		firstWork.Account.AccountURL != registeredAccount.AccountURL {
		t.Fatalf("first ACME order work = %#v, %v, %v", firstWork, found, err)
	}
	if otherWork, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-worker-2", now.Add(4*time.Millisecond), time.Minute); err != nil || found {
		t.Fatalf("concurrent ACME order work = %#v, %v, %v", otherWork, found, err)
	}
	recoveredWork, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-worker-2", now.Add(14*time.Millisecond), time.Minute)
	if err != nil || !found || recoveredWork.ID != issuance.ID || recoveredWork.WorkEpoch != 2 {
		t.Fatalf("recovered ACME order work = %#v, %v, %v", recoveredWork, found, err)
	}
	firstWork.AvailableAt = now
	if _, err := database.SaveACMEOrderWork(t.Context(), firstWork, now.Add(5*time.Millisecond)); !errors.Is(err, ErrACMEWorkFenced) {
		t.Fatalf("stale ACME order work error = %v", err)
	}
	recoveredWork.State = "authorizing"
	recoveredWork.AvailableAt = now
	authorizationExpiresAt := now.Add(time.Hour)
	recoveredWork.Authorizations = []ACMEAuthorizationWork{{
		Identifier:       request.CertificateIdentifiers[0],
		AuthorizationURL: "https://acme.example.test/authz/worker",
		ChallengeType:    "tls-alpn-01", ChallengeURL: "https://acme.example.test/challenge/worker",
		ChallengeToken: "challenge-worker", ChallengeDigest: sha256.Sum256([]byte("challenge-worker")),
		State: "presenting", AvailableAt: now, ExpiresAt: &authorizationExpiresAt,
		CreatedAt: now, UpdatedAt: now,
	}}
	savedWork, err := database.SaveACMEOrderWork(t.Context(), recoveredWork, now.Add(15*time.Millisecond))
	if err != nil {
		t.Fatalf("save recovered ACME order work: %v", err)
	}
	if savedWork.OrderRevision != recoveredWork.OrderRevision+1 || len(savedWork.Authorizations) != 1 ||
		!opaqueid.Valid(savedWork.Authorizations[0].ID, "acme_authorization_") || savedWork.Authorizations[0].Revision != 1 {
		t.Fatalf("saved ACME order work = %#v", savedWork)
	}
	if otherWork, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-worker-3", now.Add(16*time.Millisecond), time.Minute); err != nil || !found {
		t.Fatalf("released ACME order work = %#v, %v, %v", otherWork, found, err)
	} else {
		if _, err := database.pool.Exec(t.Context(), `
			UPDATE control.acme_authorizations
			SET authorization_revision = authorization_revision + 1
			WHERE order_id = $1
		`, issuance.ID); err != nil {
			t.Fatal(err)
		}
		otherWork.AvailableAt = now
		if _, err := database.SaveACMEOrderWork(t.Context(), otherWork, now.Add(17*time.Millisecond)); !errors.Is(err, ErrACMEWorkFenced) {
			t.Fatalf("stale ACME authorization work error = %v", err)
		}
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders SET work_owner = NULL, work_expires_at = NULL WHERE id = $1
	`, issuance.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		DELETE FROM control.acme_authorizations WHERE order_id = $1
	`, issuance.ID); err != nil {
		t.Fatal(err)
	}
	orderWork, found, err := database.ClaimACMEOrderWork(t.Context(), "certificate-worker-4", now.Add(18*time.Millisecond), time.Minute)
	if err != nil || !found {
		t.Fatalf("order-revision ACME work = %#v, %v, %v", orderWork, found, err)
	}
	expiredLeaseWork := orderWork
	expiredLeaseWork.AvailableAt = now
	if _, err := database.SaveACMEOrderWork(t.Context(), expiredLeaseWork, now.Add(2*time.Minute)); !errors.Is(err, ErrACMEWorkFenced) {
		t.Fatalf("expired ACME work lease error = %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders SET order_revision = order_revision + 1 WHERE id = $1
	`, issuance.ID); err != nil {
		t.Fatal(err)
	}
	orderWork.AvailableAt = now
	if _, err := database.SaveACMEOrderWork(t.Context(), orderWork, now.Add(19*time.Millisecond)); !errors.Is(err, ErrACMEWorkFenced) {
		t.Fatalf("stale ACME order revision error = %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders SET work_owner = NULL, work_expires_at = NULL WHERE id = $1
	`, issuance.ID); err != nil {
		t.Fatal(err)
	}
	issuanceID := issuance.ID
	notAfter := now.Add(time.Hour)
	challengeDigest := sha256.Sum256([]byte("challenge-readiness"))
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders SET state = 'authorizing', updated_at = $2 WHERE id = $1
	`, issuanceID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.acme_authorizations (
			id, order_id, identifier, authorization_url, challenge_type,
			challenge_url, challenge_token, challenge_digest, state,
			available_at, expires_at, created_at, updated_at
		) VALUES (
			'authorization_readiness', $1, $2, 'https://acme.example.test/authz/readiness', 'tls-alpn-01',
			'https://acme.example.test/challenge/readiness', 'challenge-readiness', $3, 'presenting',
			$4, $5, $4, $4
		)
	`, issuanceID, request.CertificateIdentifiers[0], challengeDigest[:], now, notAfter); err != nil {
		t.Fatal(err)
	}
	presentedIssuance, err := database.MarkCertificateChallengeReady(t.Context(), issuanceID, setup.SessionToken, now)
	if err != nil || len(presentedIssuance.Challenges) != 1 || presentedIssuance.Challenges[0].Token != "challenge-readiness" {
		t.Fatalf("presented certificate challenge = %#v, %v", presentedIssuance, err)
	}
	if _, err := database.MarkCertificateChallengeReady(t.Context(), issuanceID, setup.SessionToken, now.Add(time.Millisecond)); err != nil {
		t.Fatalf("idempotent certificate challenge ready: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders SET state = 'failed', last_error = 'terminal failure', updated_at = $2 WHERE id = $1
	`, issuanceID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_authorizations SET state = 'failed', last_error = 'terminal failure', updated_at = $2 WHERE order_id = $1
	`, issuanceID, now); err != nil {
		t.Fatal(err)
	}
	removedIssuance, err := database.MarkCertificateChallengeRemoved(t.Context(), issuanceID, setup.SessionToken, now)
	if err != nil || len(removedIssuance.Challenges) != 0 {
		t.Fatalf("removed failed certificate challenge = %#v, %v", removedIssuance, err)
	}
	if _, err := database.MarkCertificateChallengeRemoved(t.Context(), issuanceID, setup.SessionToken, now.Add(time.Millisecond)); err != nil {
		t.Fatalf("idempotent failed certificate challenge removal: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.acme_orders
		SET state = 'waiting_for_install', certificate_pem = 'certificate',
			not_before = $2, not_after = $3, updated_at = $2
		WHERE id = $1
	`, issuanceID, now, notAfter); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := database.MarkRouteCertificateInstalled(t.Context(), authentication, issuanceID, notAfter, now)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle.State != "starting" || lifecycle.CertificateAt == nil || lifecycle.ReadyAt != nil || lifecycle.Routable {
		t.Fatalf("certificate-only lifecycle = %#v", lifecycle)
	}
	if lifecycle.ReadyPublisherConnectionCount != 1 {
		t.Fatalf("certificate lifecycle ready publisher connections = %d, want 1", lifecycle.ReadyPublisherConnectionCount)
	}
	if _, err := database.MarkRouteSessionReady(t.Context(), authentication, now.Add(time.Second)); !errors.Is(err, ErrRouteSessionNotReady) {
		t.Fatalf("early route readiness error = %v", err)
	}
	installedIssuance, err := database.GetCertificateIssuance(t.Context(), issuance.ID, setup.SessionToken, now)
	if err != nil || installedIssuance.State != "installed" {
		t.Fatalf("installed certificate issuance = %#v, %v", installedIssuance, err)
	}
	if _, err := database.MarkRouteCertificateInstalled(
		t.Context(), authentication, "issuance_other", notAfter, now.Add(time.Millisecond),
	); !errors.Is(err, ErrRouteCertificate) {
		t.Fatalf("certificate acknowledgement conflict error = %v", err)
	}

	for slot := 1; slot < len(setup.PublisherConnections); slot++ {
		claimConnection(slot, now.Add(time.Duration(slot)*time.Second))
		lifecycle, err = database.MarkRouteCertificateInstalled(
			t.Context(), authentication, issuanceID, notAfter, now.Add(time.Duration(slot)*time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		if slot == 1 {
			lifecycle, err = database.MarkRouteSessionReady(t.Context(), authentication, now.Add(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
		}
		if slot >= 1 && (lifecycle.ReadyAt == nil || !lifecycle.Routable || lifecycle.ReadyPublisherConnectionCount != slot+1) {
			t.Fatalf("ready lifecycle after slot %d = %#v", slot, lifecycle)
		}
	}

	heartbeatAt := now.Add(3 * time.Second)
	heartbeat, err := database.HeartbeatRouteSession(t.Context(), authentication, heartbeatAt, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !heartbeat.ExpiresAt.Equal(heartbeatAt.Add(30*time.Second)) || heartbeat.RouteVersion != setup.RouteVersion {
		t.Fatalf("heartbeat setup = %#v", heartbeat)
	}
	snapshot, err := database.ReadIngressRoutingTableSnapshot(
		t.Context(), ingressLease.IngressLeaseIdentity, heartbeatAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RoutingTableRevision != 4 || len(snapshot.Routes) != 1 ||
		len(snapshot.Routes[0].Projection.PublisherConnections) != routeSessionConnectionCount {
		t.Fatalf("ingress routing-table snapshot = %#v", snapshot)
	}
	firstPage, err := database.ReadIngressRoutingTableEvents(
		t.Context(), ingressLease.IngressLeaseIdentity, 0, 3, heartbeatAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Events) != 3 || firstPage.NextRevision != 3 || !firstPage.More || firstPage.ResnapshotRequired {
		t.Fatalf("first ingress routing-table page = %#v", firstPage)
	}
	if firstPage.Events[0].Kind != "challenge_upsert" || firstPage.Events[1].Kind != "challenge_tombstone" ||
		firstPage.Events[2].Kind != "route_upsert" {
		t.Fatalf("initial ingress routing-table event kinds = %#v", firstPage.Events)
	}
	secondPage, err := database.ReadIngressRoutingTableEvents(
		t.Context(), ingressLease.IngressLeaseIdentity, firstPage.NextRevision, 3, heartbeatAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondPage.Events) != 1 || secondPage.NextRevision != 4 || secondPage.More || secondPage.ResnapshotRequired {
		t.Fatalf("second ingress routing-table page = %#v", secondPage)
	}
	for index := len(claims) - 1; index >= 0; index-- {
		if _, err := database.DisconnectPublisherConnection(
			t.Context(), claims[index], heartbeatAt.Add(time.Duration(len(claims)-index)*time.Second), true,
		); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := database.pool.Query(t.Context(), `
		SELECT event_kind, entry_revision, projection
		FROM control.ingress_routing_table_events
		WHERE route_id = $1 AND route_version = $2
		ORDER BY routing_table_revision
	`, setup.RouteID, setup.RouteVersion)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events int
	for rows.Next() {
		var eventKind string
		var revision int64
		var payload []byte
		if err := rows.Scan(&eventKind, &revision, &payload); err != nil {
			t.Fatal(err)
		}
		events++
		if revision != int64(events) {
			t.Fatalf("routing-table entry revision = %d, want %d", revision, events)
		}
		var projection IngressRoutingTableProjection
		if err := json.Unmarshal(payload, &projection); err != nil {
			t.Fatal(err)
		}
		if projection.RouteID != setup.RouteID || projection.RouteVersion != setup.RouteVersion ||
			projection.CanonicalHostname != request.CertificateIdentifiers[0] {
			t.Fatalf("ingress routing-table projection = %#v", projection)
		}
		if events == 6 && (eventKind != "route_tombstone" || len(projection.PublisherConnections) != 0) {
			t.Fatalf("final ingress routing-table event = %q, %#v", eventKind, projection)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if events != 6 {
		t.Fatalf("ingress routing-table events = %d, want 6", events)
	}
	emptySnapshot, err := database.ReadIngressRoutingTableSnapshot(
		t.Context(), ingressLease.IngressLeaseIdentity, heartbeatAt.Add(4*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if emptySnapshot.RoutingTableRevision != 6 || len(emptySnapshot.Routes) != 0 {
		t.Fatalf("tombstoned ingress routing-table snapshot = %#v", emptySnapshot)
	}
	if _, err := database.pool.Exec(t.Context(), `
		UPDATE control.ingress_routing_table_clock
		SET retained_after_revision = 3, updated_at = $1
		WHERE singleton = true
	`, heartbeatAt.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	resnapshot, err := database.ReadIngressRoutingTableEvents(
		t.Context(), ingressLease.IngressLeaseIdentity, 2, 10, heartbeatAt.Add(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !resnapshot.ResnapshotRequired || len(resnapshot.Events) != 0 || resnapshot.RetainedAfterRevision != 3 {
		t.Fatalf("retained ingress routing-table page = %#v", resnapshot)
	}
	var episodeID int64
	var episodeOpenedAt time.Time
	if err := database.pool.QueryRow(t.Context(), `
		SELECT episode_id, opened_at FROM control.route_recovery_episodes
		WHERE route_id = $1 AND route_version = $2 AND state = 'open'
	`, setup.RouteID, setup.RouteVersion).Scan(&episodeID, &episodeOpenedAt); err != nil {
		t.Fatal(err)
	}
	replenishAt := heartbeatAt.Add(6 * time.Second)
	replenished, err := database.HeartbeatRouteSession(
		t.Context(), authentication, replenishAt, 30*time.Second, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	for slot, connection := range replenished.PublisherConnections {
		if connection.State != "assigned" ||
			connection.ConnectionAssignmentRevision != setup.PublisherConnections[slot].ConnectionAssignmentRevision+1 ||
			connection.PublisherConnectionID == setup.PublisherConnections[slot].PublisherConnectionID {
			t.Fatalf("replenished publisher connection slot %d = %#v", slot, connection)
		}
	}
	recoveredPlan := replenished.PublisherConnections[0]
	recoveredDigest, err := credentials.ParsePublisherConnectionCredential(recoveredPlan.PublisherConnectionCredential)
	if err != nil {
		t.Fatal(err)
	}
	recoveredClaim := PublisherConnectionClaimRequest{
		ConnectionAssignmentIdentity: recoveredPlan.ConnectionAssignmentIdentity,
		RelayLeaseIdentity:           leases[recoveredPlan.RelayServiceID].RelayLeaseIdentity,
		ClaimID:                      "recovered_claim", CredentialDigest: [32]byte(recoveredDigest),
	}
	if _, err := database.ClaimPublisherConnection(t.Context(), recoveredClaim, replenishAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	recoveredAt := replenishAt.Add(2 * time.Second)
	if _, err := database.MarkPublisherConnectionReady(t.Context(), recoveredClaim, recoveredAt); err != nil {
		t.Fatal(err)
	}
	var recoveredPayload []byte
	if err := database.pool.QueryRow(t.Context(), `
		SELECT projection
		FROM control.ingress_routing_table_events
		WHERE route_id = $1 AND route_version = $2
		ORDER BY routing_table_revision DESC
		LIMIT 1
	`, setup.RouteID, setup.RouteVersion).Scan(&recoveredPayload); err != nil {
		t.Fatal(err)
	}
	var recoveredProjection IngressRoutingTableProjection
	if err := json.Unmarshal(recoveredPayload, &recoveredProjection); err != nil {
		t.Fatal(err)
	}
	if recoveredProjection.RecoveryEpisodeID == nil || *recoveredProjection.RecoveryEpisodeID != uint64(episodeID) ||
		len(recoveredProjection.PublisherConnections) != 1 || recoveredProjection.RouteVersion != setup.RouteVersion {
		t.Fatalf("recovered ingress routing-table projection = %#v", recoveredProjection)
	}
	observedAt := recoveredAt.Add(750 * time.Millisecond)
	wantObservedSeconds := observedAt.Sub(episodeOpenedAt).Seconds()
	observation, err := database.ObserveRouteRecovery(
		t.Context(), ingressLease.IngressLeaseIdentity, setup.RouteID, setup.RouteVersion, uint64(episodeID), observedAt,
	)
	if err != nil || observation.ObservedSeconds != wantObservedSeconds {
		t.Fatalf("recovery observation = %#v, %v", observation, err)
	}
	repeatedObservation, err := database.ObserveRouteRecovery(
		t.Context(), ingressLease.IngressLeaseIdentity, setup.RouteID, setup.RouteVersion,
		uint64(episodeID), observedAt.Add(time.Second),
	)
	if err != nil || !reflect.DeepEqual(repeatedObservation, observation) {
		t.Fatalf("repeated recovery observation = %#v, %v", repeatedObservation, err)
	}
	var count, bucketHalf, bucketOne, bucketTen, bucketInfinite int64
	var sum float64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT observation_count, observation_sum_seconds,
			bucket_le_0_5, bucket_le_1, bucket_le_10, bucket_le_120
		FROM control.route_recovery_histogram
		WHERE singleton = true
	`).Scan(&count, &sum, &bucketHalf, &bucketOne, &bucketTen, &bucketInfinite); err != nil {
		t.Fatal(err)
	}
	if count != 1 || sum != wantObservedSeconds || bucketHalf != 0 || bucketOne != 0 || bucketTen != 1 || bucketInfinite != 1 {
		t.Fatalf("recovery histogram = count %d, sum %f, buckets %d/%d/%d/%d", count, sum, bucketHalf, bucketOne, bucketTen, bucketInfinite)
	}
	wrongToken, _, _, err := credentials.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CloseRouteSession(t.Context(), setup.RouteSessionID, wrongToken, observedAt.Add(2*time.Second)); !errors.Is(err, ErrRouteSessionCredential) {
		t.Fatalf("wrong close credential error = %v", err)
	}
	if err := database.CloseRouteSession(t.Context(), setup.RouteSessionID, setup.SessionToken, observedAt.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.CloseRouteSession(t.Context(), setup.RouteSessionID, setup.SessionToken, observedAt.Add(4*time.Second)); err != nil {
		t.Fatalf("idempotent route session close: %v", err)
	}
	usageCompleteAt := observedAt.Add(4 * time.Second)
	if err := database.ReportIngressUsage(t.Context(), ingressLease.IngressLeaseIdentity, IngressUsageBatch{
		ObservedThrough: &usageCompleteAt, Complete: true,
	}, usageCompleteAt); err != nil {
		t.Fatalf("complete readiness ingress usage: %v", err)
	}
}

func seedControlRoute(
	t *testing.T,
	database *Database,
	now time.Time,
	suffix string,
) {
	t.Helper()
	identityID := "identity_" + suffix
	teamID := "team_" + suffix
	reservationID := "reservation_" + suffix
	membershipID := "membership_" + suffix
	domainID := "domain_" + suffix
	routeID := "route_" + suffix
	hostname := "route-" + suffix + ".example.test"
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO control.identities (
			id, kind, display_name, administrator, created_at, updated_at
		) VALUES ($2, 'authority', 'Test identity', true, $1, $1)`, []any{now, identityID}},
		{`INSERT INTO control.teams (
			id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at
		) VALUES ($2, 'personal', 'Team', $3, $4, $1, $1)`, []any{now, teamID, "team-" + suffix, identityID}},
		{`INSERT INTO control.member_slug_reservations (
			id, team_id, member_slug, state, reserved_by_identity_id, created_at, activated_at
		) VALUES ($2, $3, $4, 'active', $5, $1, $1)`, []any{now, reservationID, teamID, "member-" + suffix, identityID}},
		{`INSERT INTO control.team_memberships (
			id, team_id, identity_id, slug_reservation_id, managed_label, role, authority_revision, created_at, updated_at
		) VALUES ($2, $3, $4, $5, $6, 'owner', 1, $1, $1)`, []any{now, membershipID, teamID, identityID, reservationID, "member-" + suffix}},
		{`INSERT INTO control.domains (
			id, kind, team_id, canonical_domain, state, authority_revision,
			created_by_identity_id, created_at, verified_at, updated_at
		) VALUES ($2, 'claimed', $3, $4, 'ready', 1, $5, $1, $1, $1)`,
			[]any{now, domainID, teamID, suffix + ".example.test", identityID}},
		{`UPDATE control.teams SET default_domain_id = $1 WHERE id = $2`, []any{domainID, teamID}},
		{`INSERT INTO control.routes (
			id, team_id, domain_id, created_by_identity_id, idempotency_key, request_digest, canonical_hostname,
			target, route_scope, policy_revision,
			ip_policy, lifecycle_state, dns_state, created_at, updated_at
		) VALUES (
			$2, $3, $4, $5, 'seed', decode(repeat('00', 32), 'hex'), $6,
			'http://127.0.0.1:3000', 'shared', 1,
			'allow_all', 'enabled', 'published', $1, $1
		)`, []any{now, routeID, teamID, domainID, identityID, hostname}},
	} {
		if _, err := database.pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func testIngressUsage(t *testing.T, database *Database) {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Minute)
	seedControlRoute(t, database, base, "usage")
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.route_sessions (
			id, route_id, team_id, acting_identity_id, route_version,
			idempotency_key, request_digest, session_token_id, session_token_digest,
			policy_revision, certificate_cache_key, certificate_scope,
			certificate_identifiers, certificate_challenge, state,
			created_at, last_heartbeat_at, publisher_expires_at
		) VALUES (
			'session_usage', 'route_usage', 'team_usage', 'identity_usage', 1,
			'usage', decode(repeat('01', 32), 'hex'), 'token_usage', decode(repeat('02', 32), 'hex'),
			1, 'usage', 'usage', ARRAY['route-usage.example.test'], 'dns-01', 'starting',
			$1, $1, $2
		)
	`, base, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	lease, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_usage", IngressRunID: "run_usage", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, base, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	assertUsageRun := func(ingressID, runID string, wantObserved, wantExpiry time.Time, wantComplete bool) {
		t.Helper()
		var observedThrough, leaseExpiresAt time.Time
		var complete bool
		if err := database.pool.QueryRow(t.Context(), `
			SELECT observed_through, lease_expires_at, coverage_complete
			FROM control.ingress_usage_runs
			WHERE ingress_id = $1 AND ingress_run_id = $2
		`, ingressID, runID).Scan(&observedThrough, &leaseExpiresAt, &complete); err != nil {
			t.Fatal(err)
		}
		if !observedThrough.Equal(wantObserved) || !leaseExpiresAt.Equal(wantExpiry) || complete != wantComplete {
			t.Fatalf("usage run = observed %v, expiry %v, complete %v", observedThrough, leaseExpiresAt, complete)
		}
	}
	assertUsageRun("ingress_usage", "run_usage", base, base.Add(time.Minute), false)

	observedThrough := base.Add(20 * time.Second)
	report := IngressUsageReport{
		RouteID: "route_usage", RouteVersion: 1, BucketStart: base, BucketEnd: base.Add(time.Minute),
		ObservedThrough: observedThrough, ReportRevision: 1, ConnectionAttempts: 2,
		PolicyDenials: 1, HistogramData: (routeusage.Checkpoint{}).MarshalBinary(),
	}
	batch := IngressUsageBatch{Reports: []IngressUsageReport{report}, ObservedThrough: &observedThrough}
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, batch, base.Add(21*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, batch, base.Add(22*time.Second)); err != nil {
		t.Fatalf("exact usage replay: %v", err)
	}
	assertUsageRun("ingress_usage", "run_usage", observedThrough, base.Add(time.Minute), false)

	report.ReportRevision = 2
	report.Final = true
	report.ConnectionAttempts = 3
	completeAt := base.Add(30 * time.Second)
	report.ObservedThrough = completeAt
	complete := IngressUsageBatch{
		Reports: []IngressUsageReport{report}, ObservedThrough: &completeAt, Complete: true,
	}
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, complete, base.Add(31*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, complete, base.Add(32*time.Second)); err != nil {
		t.Fatalf("exact completed usage replay: %v", err)
	}
	assertUsageRun("ingress_usage", "run_usage", completeAt, base.Add(time.Minute), true)
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, IngressUsageBatch{
		ObservedThrough: &completeAt,
	}, base.Add(33*time.Second)); !errors.Is(err, ErrIngressUsageReportStale) {
		t.Fatalf("post-completion usage error = %v", err)
	}

	var attempts int64
	var bucketObserved time.Time
	if err := database.pool.QueryRow(t.Context(), `
		SELECT connection_attempts, observed_through
		FROM control.route_usage_buckets
		WHERE route_id = 'route_usage' AND route_version = 1 AND bucket_start = $1
	`, base).Scan(&attempts, &bucketObserved); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || !bucketObserved.Equal(completeAt) {
		t.Fatalf("usage bucket = attempts %d, observed %v", attempts, bucketObserved)
	}

	idleLease, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_usage_idle", IngressRunID: "run_usage_idle", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, base, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	idleLease, err = database.RenewIngress(t.Context(), IngressRenewal{
		IngressLeaseIdentity: idleLease.IngressLeaseIdentity,
	}, base.Add(10*time.Second), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	assertUsageRun("ingress_usage_idle", "run_usage_idle", base, base.Add(40*time.Second), false)
	if finalized, err := database.FinalizeRouteUsageBuckets(t.Context(), base.Add(time.Minute), base.Add(time.Minute)); err != nil || finalized != 0 {
		t.Fatalf("premature usage finalization = %#v, %v", finalized, err)
	}
	if count, err := database.MarkExpiredIngressUsageRunsIncomplete(t.Context(), base.Add(61*time.Second)); err != nil || count < 1 {
		t.Fatalf("expired usage runs = %d, %v", count, err)
	}
	var incompleteFrom, incompleteUntil time.Time
	if err := database.pool.QueryRow(t.Context(), `
		SELECT incomplete_from, incomplete_until
		FROM control.ingress_usage_runs
		WHERE ingress_id = 'ingress_usage_idle' AND ingress_run_id = 'run_usage_idle'
	`).Scan(&incompleteFrom, &incompleteUntil); err != nil {
		t.Fatal(err)
	}
	if !incompleteFrom.Equal(base) || !incompleteUntil.Equal(base.Add(40*time.Second)) {
		t.Fatalf("incomplete usage interval = %v through %v", incompleteFrom, incompleteUntil)
	}
	finalized, err := database.FinalizeRouteUsageBuckets(t.Context(), base.Add(time.Minute), base.Add(62*time.Second))
	if err != nil || finalized != 1 {
		t.Fatalf("usage finalization = %#v, %v", finalized, err)
	}
	claimedAt := base.Add(63 * time.Second)
	firstClaim, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_first", 32, claimedAt, 10*time.Second,
	)
	if err != nil || len(firstClaim) != 1 {
		t.Fatalf("first usage delivery claim = %#v, %v", firstClaim, err)
	}
	firstWork := firstClaim[0]
	if firstWork.DeliveryKey == "" || firstWork.Attempts != 1 || firstWork.WorkEpoch != 1 ||
		firstWork.ConnectionAttempts != 3 || firstWork.Complete || firstWork.Checkpoint.VisitorNetworks.Estimate() != 0 {
		t.Fatalf("first usage delivery work = %#v", firstWork)
	}
	if concurrent, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_concurrent", 32, claimedAt.Add(time.Second), time.Minute,
	); err != nil || len(concurrent) != 0 {
		t.Fatalf("concurrent usage delivery claim = %#v, %v", concurrent, err)
	}
	reclaimedAt := claimedAt.Add(11 * time.Second)
	reclaimed, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_reclaimed", 32, reclaimedAt, 10*time.Second,
	)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].WorkEpoch != 2 || reclaimed[0].Attempts != 2 {
		t.Fatalf("reclaimed usage delivery = %#v, %v", reclaimed, err)
	}
	if err := database.CompleteRouteUsageDelivery(t.Context(), firstWork, reclaimedAt); !errors.Is(err, ErrRouteUsageDeliveryFenced) {
		t.Fatalf("stale usage delivery completion error = %v", err)
	}
	retryAt := reclaimedAt.Add(5 * time.Second)
	if err := database.RetryRouteUsageDelivery(
		t.Context(), reclaimed[0], retryAt, "receiver unavailable", reclaimedAt.Add(time.Second),
	); err != nil {
		t.Fatalf("retry usage delivery: %v", err)
	}
	if unavailable, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_early", 32, retryAt.Add(-time.Millisecond), time.Minute,
	); err != nil || len(unavailable) != 0 {
		t.Fatalf("early usage delivery claim = %#v, %v", unavailable, err)
	}
	replayed, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_replay", 32, retryAt, time.Minute,
	)
	if err != nil || len(replayed) != 1 || replayed[0].WorkEpoch != 3 || replayed[0].Attempts != 3 {
		t.Fatalf("replayed usage delivery = %#v, %v", replayed, err)
	}
	replayedWork := replayed[0]
	if replayedWork.DeliveryKey != firstWork.DeliveryKey || replayedWork.SourceRevision != firstWork.SourceRevision ||
		replayedWork.RouteID != firstWork.RouteID || replayedWork.RouteVersion != firstWork.RouteVersion ||
		!replayedWork.BucketStart.Equal(firstWork.BucketStart) || !replayedWork.BucketEnd.Equal(firstWork.BucketEnd) ||
		!replayedWork.ObservedThrough.Equal(firstWork.ObservedThrough) ||
		replayedWork.ConnectionAttempts != firstWork.ConnectionAttempts ||
		!bytes.Equal(replayedWork.Checkpoint.MarshalBinary(), firstWork.Checkpoint.MarshalBinary()) {
		t.Fatalf("usage delivery payload changed: first %#v, replay %#v", firstWork, replayedWork)
	}
	completedAt := retryAt.Add(time.Second)
	if err := database.CompleteRouteUsageDelivery(t.Context(), replayedWork, completedAt); err != nil {
		t.Fatalf("complete usage delivery: %v", err)
	}
	if remaining, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_done", 32, completedAt.Add(time.Hour), time.Minute,
	); err != nil || len(remaining) != 0 {
		t.Fatalf("completed usage delivery claim = %#v, %v", remaining, err)
	}
}

func testRelayControlState(t *testing.T, database *Database) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	leaseDuration := 30 * time.Second
	registration := RelayRegistration{
		RelayServiceID: "relay_service_a", RelayID: "relay_a", RelayRunID: "run_a", ProtocolVersion: 1,
		RelayAddress: "relay-a.example:443", TLSServerName: "relay-a.example",
		InternalRelayAddress: "relay-a.internal:9443", ConnectionCapacity: 2, StreamCapacity: 100,
	}
	lease, err := database.RegisterRelay(t.Context(), registration, now, leaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	if lease.RelayLeaseRevision != 1 || lease.RelayID != registration.RelayID ||
		!lease.LeaseExpiresAt.Equal(now.Add(leaseDuration)) {
		t.Fatalf("first relay lease = %#v", lease)
	}
	repeated, err := database.RegisterRelay(t.Context(), registration, now.Add(time.Second), leaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	if repeated.RelayLeaseRevision != lease.RelayLeaseRevision || !repeated.RegisteredAt.Equal(now) {
		t.Fatalf("repeated relay lease = %#v", repeated)
	}
	conflict := registration
	conflict.RelayRunID = "run_conflict"
	if _, err := database.RegisterRelay(t.Context(), conflict, now.Add(2*time.Second), leaseDuration); !errors.Is(err, ErrRelayRegistrationConflict) {
		t.Fatalf("live relay process conflict error = %v", err)
	}

	renewed, err := database.RenewRelay(t.Context(), RelayRenewal{
		RelayLeaseIdentity: lease.RelayLeaseIdentity, ReportedConnections: 1, ReportedStreams: 2,
	}, now.Add(3*time.Second), leaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ReportedConnections != 1 || renewed.ReportedStreams != 2 {
		t.Fatalf("renewed relay lease = %#v", renewed)
	}
	staleIdentity := lease.RelayLeaseIdentity
	staleIdentity.RelayLeaseRevision++
	if _, err := database.RenewRelay(t.Context(), RelayRenewal{
		RelayLeaseIdentity: staleIdentity,
	}, now.Add(4*time.Second), leaseDuration); !errors.Is(err, ErrRelayLeaseStale) {
		t.Fatalf("stale renewal error = %v", err)
	}

	digests := [routeSessionConnectionCount][32]byte{
		sha256.Sum256([]byte("credential-zero")),
		sha256.Sum256([]byte("credential-one")),
	}
	registrationB := registration
	registrationB.RelayServiceID = "relay_service_b"
	registrationB.RelayID = "relay_b"
	registrationB.RelayRunID = "run_b"
	registrationB.RelayAddress = "relay-b.example:443"
	registrationB.TLSServerName = "relay-b.example"
	registrationB.InternalRelayAddress = "relay-b.internal:9443"
	leaseB, err := database.RegisterRelay(t.Context(), registrationB, now.Add(5*time.Second), leaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	seedRelayRouteSession(t, database, now, digests)
	baseClaim := PublisherConnectionClaimRequest{
		ConnectionAssignmentIdentity: ConnectionAssignmentIdentity{
			RouteSessionID: "session_a", RouteID: "route_a", RouteVersion: 1,
			ConnectionSlot: 0, PublisherConnectionID: "connection_0", ConnectionAssignmentRevision: 1,
			RelayServiceID: registration.RelayServiceID,
		},
		RelayLeaseIdentity: renewed.RelayLeaseIdentity,
		CredentialDigest:   digests[0],
	}
	badCredential := baseClaim
	badCredential.ClaimID = "claim_bad"
	badCredential.CredentialDigest = sha256.Sum256([]byte("wrong"))
	if _, err := database.ClaimPublisherConnection(t.Context(), badCredential, now.Add(6*time.Second)); !errors.Is(err, ErrPublisherConnectionCredential) {
		t.Fatalf("bad publisher connection credential error = %v", err)
	}

	claims := []PublisherConnectionClaimRequest{baseClaim, baseClaim}
	claims[0].ClaimID = "claim_quic"
	claims[1].ClaimID = "claim_tcp"
	type claimResult struct {
		request    PublisherConnectionClaimRequest
		connection ClaimedPublisherConnection
		err        error
	}
	results := make(chan claimResult, len(claims))
	for _, request := range claims {
		go func() {
			connection, err := database.ClaimPublisherConnection(t.Context(), request, now.Add(7*time.Second))
			results <- claimResult{request: request, connection: connection, err: err}
		}()
	}
	var winner PublisherConnectionClaimRequest
	for range claims {
		result := <-results
		switch {
		case result.err == nil:
			if winner.ClaimID != "" {
				t.Fatal("both transport candidates claimed one publisher connection")
			}
			winner = result.request
			if result.connection.State != "connected" || result.connection.ClaimID != result.request.ClaimID {
				t.Fatalf("claimed publisher connection = %#v", result.connection)
			}
		case !errors.Is(result.err, ErrPublisherConnectionAlreadyClaimed):
			t.Fatalf("losing transport claim error = %v", result.err)
		}
	}
	if winner.ClaimID == "" {
		t.Fatal("neither transport candidate claimed the publisher connection")
	}
	if _, err := database.ClaimPublisherConnection(t.Context(), winner, now.Add(8*time.Second)); err != nil {
		t.Fatalf("idempotent publisher connection claim: %v", err)
	}
	ready, err := database.MarkPublisherConnectionReady(t.Context(), winner, now.Add(9*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if ready.State != "ready" || ready.ReadyAt == nil {
		t.Fatalf("ready publisher connection = %#v", ready)
	}
	if repeated, err := database.ClaimPublisherConnection(t.Context(), winner, now.Add(10*time.Second)); err != nil || repeated.State != "ready" {
		t.Fatalf("idempotent ready claim = %#v, %v", repeated, err)
	}

	wrongService := winner
	wrongService.ConnectionSlot = 1
	wrongService.PublisherConnectionID = "connection_1"
	wrongService.ConnectionAssignmentIdentity.RelayServiceID = registrationB.RelayServiceID
	wrongService.CredentialDigest = digests[1]
	wrongService.ClaimID = "claim_wrong_service"
	if _, err := database.ClaimPublisherConnection(t.Context(), wrongService, now.Add(11*time.Second)); !errors.Is(err, ErrPublisherConnectionRelayService) {
		t.Fatalf("wrong relay service claim error = %v", err)
	}

	drainingB, err := database.BeginRelayDrain(t.Context(), leaseB.RelayLeaseIdentity, now.Add(12*time.Second), now.Add(20*time.Second))
	if err != nil || !drainingB.Draining {
		t.Fatalf("draining relay lease = %#v, %v", drainingB, err)
	}
	claimWhileDraining := wrongService
	claimWhileDraining.RelayLeaseIdentity = leaseB.RelayLeaseIdentity
	claimWhileDraining.ClaimID = "claim_while_draining"
	if _, err := database.ClaimPublisherConnection(t.Context(), claimWhileDraining, now.Add(13*time.Second)); !errors.Is(err, ErrRelayDraining) {
		t.Fatalf("draining relay claim error = %v", err)
	}

	closed, err := database.DisconnectPublisherConnection(t.Context(), winner, now.Add(14*time.Second), true)
	if err != nil || closed.State != "closed" {
		t.Fatalf("closed publisher connection = %#v, %v", closed, err)
	}
	if _, err := database.DisconnectPublisherConnection(t.Context(), winner, now.Add(15*time.Second), true); !errors.Is(err, ErrConnectionAssignmentStale) {
		t.Fatalf("repeated disconnect error = %v", err)
	}

	replacement := registration
	replacement.RelayRunID = "run_replacement"
	replacementLease, err := database.RegisterRelay(t.Context(), replacement, renewed.LeaseExpiresAt, leaseDuration)
	if err != nil {
		t.Fatal(err)
	}
	if replacementLease.RelayLeaseRevision != renewed.RelayLeaseRevision+1 {
		t.Fatalf("replacement relay lease revision = %d, want %d", replacementLease.RelayLeaseRevision, renewed.RelayLeaseRevision+1)
	}
}

func seedRelayRouteSession(
	t *testing.T,
	database *Database,
	now time.Time,
	digests [routeSessionConnectionCount][32]byte,
) {
	t.Helper()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO control.identities (
			id, kind, display_name, administrator, created_at, updated_at
		) VALUES ('identity_a', 'authority', 'Test identity', true, $1, $1)`, []any{now}},
		{`INSERT INTO control.teams (
			id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at
		) VALUES ('team_a', 'personal', 'Team A', 'team-a', 'identity_a', $1, $1)`, []any{now}},
		{`INSERT INTO control.domains (
			id, kind, team_id, canonical_domain, state, authority_revision,
			created_by_identity_id, created_at, verified_at, updated_at
		) VALUES ('domain_a', 'claimed', 'team_a', 'example.test', 'ready', 1,
			'identity_a', $1, $1, $1)`, []any{now}},
		{`UPDATE control.teams SET default_domain_id = 'domain_a' WHERE id = 'team_a'`, nil},
		{`INSERT INTO control.routes (
			id, team_id, domain_id, created_by_identity_id, idempotency_key, request_digest, canonical_hostname,
			target, route_scope, policy_revision, ip_policy, lifecycle_state,
			dns_state, created_at, updated_at
		) VALUES (
			'route_a', 'team_a', 'domain_a', 'identity_a', 'seed', decode(repeat('00', 32), 'hex'), 'route.example.test',
			'http://127.0.0.1:3000', 'shared', 1, 'allow_all', 'enabled',
			'published', $1, $1
		)`, []any{now}},
		{`INSERT INTO control.route_sessions (
			id, route_id, team_id, acting_identity_id, route_version, idempotency_key,
			request_digest, session_token_id, session_token_digest, policy_revision,
			certificate_cache_key, certificate_scope, certificate_identifiers,
			certificate_challenge, state, created_at, last_heartbeat_at,
			publisher_expires_at, certificate_installed_at, certificate_issuance_id,
			certificate_not_after
		) VALUES (
			'session_a', 'route_a', 'team_a', 'identity_a', 1, 'request_a',
			$2, 'session_token_a', $3, 1,
			'certificate_a', 'route', ARRAY['route.example.test'],
			'tls-alpn-01', 'starting', $1, $1, $4, $1, 'issuance_a', $4
		)`, []any{now, digests[0][:], digests[1][:], now.Add(time.Hour)}},
	} {
		if _, err := database.pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for slot := range routeSessionConnectionCount {
		relayServiceID := fmt.Sprintf("relay_service_%c", 'a'+slot)
		if _, err := database.pool.Exec(t.Context(), `
			INSERT INTO control.route_session_connections (
				route_session_id, route_id, route_version, connection_slot, publisher_connection_id,
				connection_assignment_revision, relay_service_id, relay_address, tls_server_name,
				publisher_connection_credential_digest, publisher_connection_credential_expires_at,
				state, assigned_at
			) VALUES (
				'session_a', 'route_a', 1, $1, $2,
				1, $3, $4, $5, $6, $7, 'assigned', $8
			)
		`, slot, fmt.Sprintf("connection_%d", slot), relayServiceID,
			relayServiceID+".example:443", relayServiceID+".example", digests[slot][:], now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
}

func randomHex(t *testing.T, bytes int) string {
	t.Helper()
	random := make([]byte, bytes)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(random)
}

func databaseURLWithName(rawURL, databaseName string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse PostgreSQL test URL: %w", err)
	}
	parsed.Path = "/" + databaseName
	parsed.RawPath = ""
	return parsed.String(), nil
}
