package controlstate

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/routeusage"
)

func TestIntegrationRouteSessionCreation(t *testing.T) {
	database, now, request, _ := newRouteSessionPrerequisites(t)
	setup, err := database.CreateRouteSession(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if setup.RouteID != request.RouteID || setup.RouteVersion != 1 || setup.State != "starting" || setup.RouteSessionToken == "" {
		t.Fatalf("session setup = %#v", setup)
	}
	services := make(map[string]bool)
	for slot, connection := range setup.PublisherConnections {
		if connection.ConnectionSlot != slot || connection.RouteSessionID != setup.RouteSessionID || connection.RouteID != setup.RouteID || connection.RouteVersion != setup.RouteVersion || connection.ConnectionAssignmentRevision != 1 {
			t.Fatalf("connection slot %d = %#v", slot, connection)
		}
		if _, err := credentials.ParsePublisherConnectionCredential(connection.PublisherConnectionCredential); err != nil {
			t.Fatalf("slot %d credential: %v", slot, err)
		}
		services[connection.RelayServiceID] = true
	}
	if len(services) != routeSessionConnectionCount {
		t.Fatalf("assigned services = %v", services)
	}
	repeated, err := database.CreateRouteSession(t.Context(), request, now.Add(time.Second), 30*time.Second, time.Minute)
	if err != nil || !reflect.DeepEqual(repeated, setup) {
		t.Fatalf("session replay = %#v, %v", repeated, err)
	}
	changed := request
	changed.RequestDigest = sha256.Sum256([]byte("changed"))
	if _, err := database.CreateRouteSession(t.Context(), changed, now, 30*time.Second, time.Minute); !errors.Is(err, ErrRouteSessionIdempotency) {
		t.Fatalf("session idempotency: %v", err)
	}
	changed.IdempotencyKey, changed.ExpectedMutationRevision = "second", 2
	if _, err := database.CreateRouteSession(t.Context(), changed, now, 30*time.Second, time.Minute); !errors.Is(err, ErrRouteSessionConflict) {
		t.Fatalf("live session conflict: %v", err)
	}
	changed.PolicyRevision = 2
	if _, err := database.CreateRouteSession(t.Context(), changed, now, 30*time.Second, time.Minute); !errors.Is(err, ErrRouteAuthority) {
		t.Fatalf("stale authority: %v", err)
	}
	if _, err := database.UpdateAuthorizedRoute(t.Context(), AuthorizedRouteUpdateRequest{
		RouteID: request.RouteID, TeamID: request.TeamID, ActingIdentityID: request.ActingIdentityID,
		Target: "http://127.0.0.1:4000", AllowedIPPrefixes: []string{"192.0.2.0/24"}, PolicyRevision: 1, ExpectedMutationRevision: 2,
	}, now); !errors.Is(err, ErrRouteAttached) {
		t.Fatalf("attached route update: %v", err)
	}
	route, err := database.GetRoute(t.Context(), request.ActingIdentityID, request.RouteID)
	if err != nil || len(route.AllowedIPPrefixes) != 0 {
		t.Fatalf("failed mutations changed route policy = %#v, %v", route, err)
	}
}

func TestIntegrationRouteSessionExpiryAndGatedReplay(t *testing.T) {
	f := newRouteSessionFixture(t)
	database, now, setup, request := f.database, f.now, f.setup, f.request
	closedAt := now.Add(5 * time.Second)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.route_sessions SET publisher_expires_at = $2 WHERE id = $1`, setup.RouteSessionID, closedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.maintenance_controls SET enabled = false, revision = revision + 1, updated_at = $1, updated_by = 'test' WHERE control_name = 'route_session_creation'`, now); err != nil {
		t.Fatal(err)
	}
	retry, err := database.CreateRouteSession(t.Context(), request, now.Add(7*time.Second), 30*time.Second, time.Minute)
	if err != nil || retry.ClosedAt == nil || !retry.ClosedAt.Equal(closedAt) || !retry.ExpiresAt.Equal(closedAt) {
		t.Fatalf("gated replay expiry = %#v, %v", retry, err)
	}
	expected := setup
	expected.State, expected.ExpiresAt, expected.ClosedAt = "expired", closedAt, &closedAt
	for index := range expected.PublisherConnections {
		expected.PublisherConnections[index].State = PublisherConnectionClosed
	}
	if !reflect.DeepEqual(retry, expected) {
		t.Fatalf("gated replay changed setup: got %#v, want %#v", retry, expected)
	}
	var reason string
	if err := database.pool.QueryRow(t.Context(), `SELECT close_reason FROM control.route_sessions WHERE id = $1`, setup.RouteSessionID).Scan(&reason); err != nil || reason != "publisher_expired" {
		t.Fatalf("close reason = %q, %v", reason, err)
	}
	request.IdempotencyKey, request.RequestDigest, request.ExpectedMutationRevision = "replacement", sha256.Sum256([]byte("replacement")), 2
	if _, err := database.CreateRouteSession(t.Context(), request, now.Add(8*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrRouteSessionCreationGated) {
		t.Fatalf("gated creation: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.maintenance_controls SET enabled = true, revision = revision + 1, updated_at = $1, updated_by = 'test' WHERE control_name = 'route_session_creation'`, now); err != nil {
		t.Fatal(err)
	}
	replacement, err := database.CreateRouteSession(t.Context(), request, now.Add(9*time.Second), 30*time.Second, time.Minute)
	if err != nil || replacement.RouteVersion != 2 || replacement.RouteSessionID == setup.RouteSessionID || replacement.RouteSessionToken == setup.RouteSessionToken {
		t.Fatalf("replacement session = %#v, %v", replacement, err)
	}
	route, err := database.GetRoute(t.Context(), request.ActingIdentityID, request.RouteID)
	if err != nil || len(route.AllowedIPPrefixes) != 0 {
		t.Fatalf("replacement changed route policy: %#v, %v", route, err)
	}
}

func TestIntegrationRouteSessionPlacementRequiresAvailableServices(t *testing.T) {
	database, now, request, _ := newRouteSessionPrerequisites(t)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET draining = true, drain_deadline = $1`, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRouteSession(t.Context(), request, now, time.Minute, time.Minute); !errors.Is(err, ErrInsufficientRelayServices) {
		t.Fatalf("draining placement: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET draining = false, drain_deadline = NULL`); err != nil {
		t.Fatal(err)
	}
	setup, err := database.CreateRouteSession(t.Context(), request, now, time.Minute, time.Minute)
	if err != nil || setup.RouteVersion != 1 {
		t.Fatalf("failed placement consumed route version: %#v, %v", setup, err)
	}
}

func TestIntegrationRouteSessionReadiness(t *testing.T) {
	f := newRouteSessionFixture(t)
	database, now, authentication := f.database, f.now, f.authentication()
	claimTestConnection(t, f, 0, now)
	work := createPlanIssuanceWork(t, database, now, authentication, f.certificatePlan(), true, nil)
	lifecycle, err := database.MarkRouteCertificateInstalled(t.Context(), authentication, work.ID, *work.NotAfter, now)
	if err != nil || lifecycle.State != "starting" || lifecycle.CertificateAt == nil || lifecycle.ReadyAt != nil || lifecycle.Routable || lifecycle.ReadyPublisherConnectionCount != 1 {
		t.Fatalf("certificate with one connection = %#v, %v", lifecycle, err)
	}
	if _, err := database.MarkRouteSessionReady(t.Context(), authentication, now); !errors.Is(err, ErrRouteSessionNotReady) {
		t.Fatalf("early readiness: %v", err)
	}
	issuance, err := database.GetCertificateIssuance(t.Context(), work.ID, authentication.RouteSessionToken, now)
	if err != nil || issuance.State != "installed" {
		t.Fatalf("installed issuance = %#v, %v", issuance, err)
	}
	if _, err := database.MarkRouteCertificateInstalled(t.Context(), authentication, "issuance_other", *work.NotAfter, now); !errors.Is(err, ErrRouteCertificate) {
		t.Fatalf("wrong issuance acknowledgement: %v", err)
	}
	claimTestConnection(t, f, 1, now.Add(time.Second))
	lifecycle, err = database.MarkRouteSessionReady(t.Context(), authentication, now.Add(2*time.Second))
	if err != nil || lifecycle.ReadyAt == nil || !lifecycle.Routable || lifecycle.ReadyPublisherConnectionCount != 2 {
		t.Fatalf("ready lifecycle = %#v, %v", lifecycle, err)
	}
	repeated, err := database.MarkRouteCertificateInstalled(t.Context(), authentication, work.ID, *work.NotAfter, now.Add(3*time.Second))
	if err != nil || !repeated.Routable || repeated.ReadyAt == nil || !repeated.ReadyAt.Equal(*lifecycle.ReadyAt) {
		t.Fatalf("certificate replay changed readiness = %#v, %v", repeated, err)
	}
}

func TestIntegrationRouteSessionHeartbeatPreservesConnectionsAndExpiry(t *testing.T) {
	f := newRouteSessionFixture(t)
	database, now := f.database, f.now
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.routes SET ephemeral = true, expires_at = $2 WHERE id = $1`, f.setup.RouteID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if count, err := database.DeleteExpiredEphemeralRoutes(t.Context(), now.Add(2*time.Second)); err != nil || count != 0 {
		t.Fatalf("active ephemeral cleanup = %d, %v", count, err)
	}
	for slot := range f.setup.PublisherConnections {
		claimTestConnection(t, f, slot, now)
	}
	heartbeatAt := now.Add(3 * time.Second)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.route_session_connections SET publisher_connection_credential_expires_at = $2 WHERE route_session_id = $1`, f.setup.RouteSessionID, heartbeatAt.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	lease := registerTestIngress(t, database, now)
	bucket := heartbeatAt.Truncate(time.Minute)
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, IngressUsageBatch{Reports: []IngressUsageReport{{
		RouteID: f.setup.RouteID, RouteVersion: f.setup.RouteVersion, BucketStart: bucket, BucketEnd: bucket.Add(time.Minute), ObservedThrough: heartbeatAt,
		ReportRevision: 1, ConnectionAttempts: 3, PolicyDenials: 3, HistogramData: (routeusage.Checkpoint{}).MarshalBinary(),
	}}}, heartbeatAt); err != nil {
		t.Fatal(err)
	}
	heartbeat, err := database.HeartbeatRouteSession(t.Context(), f.authentication(), heartbeatAt, 30*time.Second, time.Minute)
	if err != nil || !heartbeat.ExpiresAt.Equal(heartbeatAt.Add(30*time.Second)) || heartbeat.RouteVersion != f.setup.RouteVersion || heartbeat.PolicyDenials != 3 {
		t.Fatalf("heartbeat = %#v, %v", heartbeat, err)
	}
	route, err := database.GetRoute(t.Context(), f.request.ActingIdentityID, f.setup.RouteID)
	if err != nil || route.ExpiresAt == nil || !route.ExpiresAt.Equal(heartbeatAt.Add(ephemeralRouteGracePeriod)) {
		t.Fatalf("renewed ephemeral route = %#v, %v", route, err)
	}
	earlier, err := database.HeartbeatRouteSession(t.Context(), f.authentication(), heartbeatAt.Add(-time.Second), 10*time.Second, time.Minute)
	if err != nil || !earlier.ExpiresAt.Equal(heartbeat.ExpiresAt) {
		t.Fatalf("nonmonotonic heartbeat = %#v, %v", earlier, err)
	}
	monotonic, err := database.GetRoute(t.Context(), f.request.ActingIdentityID, f.setup.RouteID)
	if err != nil || monotonic.ExpiresAt == nil || !monotonic.ExpiresAt.Equal(*route.ExpiresAt) {
		t.Fatalf("nonmonotonic route expiry = %#v, %v", monotonic, err)
	}
	for slot, connection := range heartbeat.PublisherConnections {
		previous := f.setup.PublisherConnections[slot]
		if connection.PublisherConnectionID != previous.PublisherConnectionID || connection.ConnectionAssignmentRevision != previous.ConnectionAssignmentRevision || connection.State != PublisherConnectionReady {
			t.Fatalf("expired credential replaced connected slot %d: %#v", slot, connection)
		}
	}
}

type routeSessionFixture struct {
	database *Database
	now      time.Time
	request  RouteSessionRequest
	setup    RouteSessionSetup
	leases   map[string]RelayLease
}

func newRouteSessionPrerequisites(t *testing.T) (*Database, time.Time, RouteSessionRequest, map[string]RelayLease) {
	t.Helper()
	database, now := newControlStateIntegrationDatabase(t, "route_session")
	seedControlRoute(t, database, now, "session")
	leases := make(map[string]RelayLease)
	for slot := range routeSessionConnectionCount {
		registration := relayLifecycleRegistration(fmt.Sprintf("placement-%d", slot))
		registration.ConnectionCapacity = 10
		lease, err := database.RegisterRelay(t.Context(), registration, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[lease.RelayServiceID] = lease
	}
	return database, now, RouteSessionRequest{RouteID: "route_session", TeamID: "team_session", ActingIdentityID: "identity_session", MembershipID: "membership_session",
		RequireLocalAuthority: true, RetrySecret: bytes.Repeat([]byte{7}, 32), IdempotencyKey: "session", RequestDigest: sha256.Sum256([]byte("session")), PolicyRevision: 1,
		CertificateCacheKey: "certificate_session", CertificateScope: "route", CertificateIdentifiers: []string{"route-session.example.test"}, CertificateChallenge: "tls-alpn-01", ExpectedMutationRevision: 1}, leases
}

func newRouteSessionFixture(t *testing.T) routeSessionFixture {
	t.Helper()
	database, now, request, leases := newRouteSessionPrerequisites(t)
	setup, err := database.CreateRouteSession(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return routeSessionFixture{database, now, request, setup, leases}
}

func (f routeSessionFixture) authentication() RouteSessionAuthentication {
	return RouteSessionAuthentication{RouteSessionID: f.setup.RouteSessionID, RouteID: f.setup.RouteID, RouteVersion: f.setup.RouteVersion, RouteSessionToken: f.setup.RouteSessionToken}
}

func (f routeSessionFixture) certificatePlan() CertificatePlan {
	return CertificatePlan{CacheKey: f.request.CertificateCacheKey, Scope: f.request.CertificateScope, Identifiers: f.request.CertificateIdentifiers, ChallengeMethod: f.request.CertificateChallenge}
}

func claimTestConnection(t *testing.T, f routeSessionFixture, slot int, now time.Time) PublisherConnectionClaimRequest {
	t.Helper()
	plan := f.setup.PublisherConnections[slot]
	digest, err := credentials.ParsePublisherConnectionCredential(plan.PublisherConnectionCredential)
	if err != nil {
		t.Fatal(err)
	}
	claim := PublisherConnectionClaimRequest{ConnectionAssignmentIdentity: plan.ConnectionAssignmentIdentity,
		RelayLeaseIdentity: f.leases[plan.RelayServiceID].RelayLeaseIdentity, ClaimID: fmt.Sprintf("claim-%d", slot), CredentialDigest: [32]byte(digest)}
	if _, err := f.database.ClaimPublisherConnection(t.Context(), claim, now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.MarkPublisherConnectionReady(t.Context(), claim, now); err != nil {
		t.Fatal(err)
	}
	return claim
}

func readyTestSession(t *testing.T, f routeSessionFixture) []PublisherConnectionClaimRequest {
	t.Helper()
	work := createPlanIssuanceWork(t, f.database, f.now, f.authentication(), f.certificatePlan(), true, nil)
	if _, err := f.database.MarkRouteCertificateInstalled(t.Context(), f.authentication(), work.ID, *work.NotAfter, f.now); err != nil {
		t.Fatal(err)
	}
	var claims []PublisherConnectionClaimRequest
	for slot := range f.setup.PublisherConnections {
		claims = append(claims, claimTestConnection(t, f, slot, f.now))
	}
	if _, err := f.database.MarkRouteSessionReady(t.Context(), f.authentication(), f.now); err != nil {
		t.Fatal(err)
	}
	return claims
}

func registerTestIngress(t *testing.T, database *Database, now time.Time) IngressLease {
	t.Helper()
	lease, err := database.RegisterIngress(t.Context(), IngressRegistration{IngressID: "ingress_test", IngressRunID: "run_test", ProtocolVersion: 1, ConnectionCapacity: 100}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}
