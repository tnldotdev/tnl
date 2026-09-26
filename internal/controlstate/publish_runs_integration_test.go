package controlstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/publicurlusage"
)

func TestIntegrationPublishRunCreation(t *testing.T) {
	database, now, request, _ := newPublishRunPrerequisites(t)
	setup, err := database.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if setup.PublicURLID != request.PublicURLID || setup.PublishRunNumber != 1 || setup.State != "starting" || setup.PublishRunToken == "" {
		t.Fatalf("session setup = %#v", setup)
	}
	services := make(map[string]bool)
	for slot, connection := range setup.PublisherConnections {
		if connection.ConnectionSlot != slot || connection.PublishRunID != setup.PublishRunID || connection.PublicURLID != setup.PublicURLID || connection.PublishRunNumber != setup.PublishRunNumber || connection.ConnectionAssignmentRevision != 1 {
			t.Fatalf("connection slot %d = %#v", slot, connection)
		}
		if _, err := credentials.ParsePublisherConnectionCredential(connection.PublisherConnectionCredential); err != nil {
			t.Fatalf("slot %d credential: %v", slot, err)
		}
		services[connection.RelayServiceID] = true
	}
	if len(services) != publishRunConnectionCount {
		t.Fatalf("assigned services = %v", services)
	}
	repeated, err := database.CreatePublishRun(t.Context(), request, now.Add(time.Second), 30*time.Second, time.Minute)
	if err != nil || !reflect.DeepEqual(repeated, setup) {
		t.Fatalf("session replay = %#v, %v", repeated, err)
	}
	changed := request
	changed.RequestDigest = sha256.Sum256([]byte("changed"))
	if _, err := database.CreatePublishRun(t.Context(), changed, now, 30*time.Second, time.Minute); !errors.Is(err, ErrPublishRunIdempotency) {
		t.Fatalf("session idempotency: %v", err)
	}
	changed.IdempotencyKey, changed.ExpectedMutationRevision = "second", 2
	if _, err := database.CreatePublishRun(t.Context(), changed, now, 30*time.Second, time.Minute); !errors.Is(err, ErrPublishRunConflict) {
		t.Fatalf("live session conflict: %v", err)
	}
	changed.PolicyRevision = 2
	if _, err := database.CreatePublishRun(t.Context(), changed, now, 30*time.Second, time.Minute); !errors.Is(err, ErrPublicURLAuthority) {
		t.Fatalf("stale authority: %v", err)
	}
	if _, err := database.UpdateAuthorizedPublicURL(t.Context(), AuthorizedRouteUpdateRequest{
		PublicURLID: request.PublicURLID, TeamID: request.TeamID, ActingIdentityID: request.ActingIdentityID,
		Target: "http://127.0.0.1:4000", AllowedIPPrefixes: []string{"192.0.2.0/24"}, PolicyRevision: 1, ExpectedMutationRevision: 2,
	}, now); !errors.Is(err, ErrPublishRunOpen) {
		t.Fatalf("attached route update: %v", err)
	}
	route, err := database.GetPublicURL(t.Context(), request.ActingIdentityID, request.PublicURLID)
	if err != nil || len(route.AllowedIPPrefixes) != 0 {
		t.Fatalf("failed mutations changed route policy = %#v, %v", route, err)
	}
}

func TestIntegrationPublishRunExpiryAndGatedReplay(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now, setup, request := f.database, f.now, f.setup, f.request
	closedAt := setup.CreatedAt.Add(5 * time.Second)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET state = 'ready', ready_at = $2, publisher_expires_at = $3 WHERE id = $1`, setup.PublishRunID, now, closedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.maintenance_controls SET allowed = false, revision = revision + 1, updated_at = $1, updated_by = 'test' WHERE control_name = 'publish_run_creation'`, now); err != nil {
		t.Fatal(err)
	}
	retry, err := database.CreatePublishRun(t.Context(), request, now.Add(7*time.Second), 30*time.Second, time.Minute)
	if err != nil || retry.ReadyAt == nil || !retry.ReadyAt.Equal(now) || retry.ClosedAt == nil || !retry.ClosedAt.Equal(closedAt) || !retry.ExpiresAt.Equal(closedAt) {
		t.Fatalf("gated replay expiry = %#v, %v", retry, err)
	}
	expected := setup
	expected.State, expected.ExpiresAt, expected.ReadyAt, expected.ClosedAt = "expired", closedAt, retry.ReadyAt, &closedAt
	for index := range expected.PublisherConnections {
		expected.PublisherConnections[index].State = PublisherConnectionClosed
	}
	if !reflect.DeepEqual(retry, expected) {
		t.Fatalf("gated replay changed setup: got %#v, want %#v", retry, expected)
	}
	var reason string
	if err := database.pool.QueryRow(t.Context(), `SELECT close_reason FROM control.publish_runs WHERE id = $1`, setup.PublishRunID).Scan(&reason); err != nil || reason != "publisher_expired" {
		t.Fatalf("close reason = %q, %v", reason, err)
	}
	var eventKind string
	if err := database.pool.QueryRow(t.Context(), `SELECT event_kind FROM control.ingress_routing_table_events WHERE public_url_id = $1 AND publish_run_number = $2`, setup.PublicURLID, setup.PublishRunNumber).Scan(&eventKind); err != nil || eventKind != string(IngressPublicURLTombstone) {
		t.Fatalf("gated replay routing event = %q, %v", eventKind, err)
	}
	request.IdempotencyKey, request.RequestDigest, request.ExpectedMutationRevision = "replacement", sha256.Sum256([]byte("replacement")), 2
	if _, err := database.CreatePublishRun(t.Context(), request, now.Add(8*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrPublishRunCreationGated) {
		t.Fatalf("gated creation: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.maintenance_controls SET allowed = true, revision = revision + 1, updated_at = $1, updated_by = 'test' WHERE control_name = 'publish_run_creation'`, now); err != nil {
		t.Fatal(err)
	}
	replacement, err := database.CreatePublishRun(t.Context(), request, now.Add(9*time.Second), 30*time.Second, time.Minute)
	if err != nil || replacement.PublishRunNumber != 2 || replacement.PublishRunID == setup.PublishRunID || replacement.PublishRunToken == setup.PublishRunToken {
		t.Fatalf("replacement session = %#v, %v", replacement, err)
	}
	route, err := database.GetPublicURL(t.Context(), request.ActingIdentityID, request.PublicURLID)
	if err != nil || len(route.AllowedIPPrefixes) != 0 {
		t.Fatalf("replacement changed route policy: %#v, %v", route, err)
	}
}

func TestIntegrationPublishRunPlacementRequiresAvailableServices(t *testing.T) {
	database, now, request, _ := newPublishRunPrerequisites(t)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET draining = true, drain_deadline = $1`, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreatePublishRun(t.Context(), request, now, time.Minute, time.Minute); !errors.Is(err, ErrInsufficientRelayServices) {
		t.Fatalf("draining placement: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET draining = false, drain_deadline = NULL`); err != nil {
		t.Fatal(err)
	}
	setup, err := database.CreatePublishRun(t.Context(), request, now, time.Minute, time.Minute)
	if err != nil || setup.PublishRunNumber != 1 {
		t.Fatalf("failed placement consumed publish run number: %#v, %v", setup, err)
	}
}

func TestIntegrationPublishRunReplacesExpiredSession(t *testing.T) {
	f := newPublishRunFixture(t)
	request := f.request
	request.IdempotencyKey, request.RequestDigest, request.ExpectedMutationRevision = "replacement", sha256.Sum256([]byte("replacement")), 2
	setup, err := f.database.CreatePublishRun(t.Context(), request, f.now.Add(time.Minute), time.Hour, time.Hour)
	if err != nil || setup.PublishRunNumber != 2 || setup.PublishRunID == f.setup.PublishRunID {
		t.Fatalf("replace expired session = %#v, %v", setup, err)
	}
	var closed bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT state = 'expired' AND closed_at = publisher_expires_at FROM control.publish_runs WHERE id = $1`, f.setup.PublishRunID).Scan(&closed); err != nil || !closed {
		t.Fatalf("old session expiry = %t, %v", closed, err)
	}
}

func TestIntegrationPublishRunCreationRollsBackBothAssignmentsAndVersion(t *testing.T) {
	database, now, request, leases := newPublishRunPrerequisites(t)
	if _, err := database.pool.Exec(t.Context(), `ALTER TABLE control.publish_run_connections ADD CONSTRAINT reject_second_slot CHECK (connection_slot <> 1)`); err != nil {
		t.Fatal(err)
	}
	_, err := database.CreatePublishRun(t.Context(), request, now, time.Hour, time.Hour)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "reject_second_slot" {
		t.Fatalf("second assignment failure = %v", err)
	}
	var version, revision, sessions, connections, audits int64
	err = database.pool.QueryRow(t.Context(), `SELECT next_publish_run_number, mutation_revision,
		(SELECT count(*) FROM control.publish_runs),
		(SELECT count(*) FROM control.publish_run_connections),
		(SELECT count(*) FROM control.admin_audit_events WHERE operation = 'publish_run.create')
		FROM control.public_urls WHERE id = $1`, request.PublicURLID).Scan(&version, &revision, &sessions, &connections, &audits)
	if err != nil || version != 1 || revision != 1 || sessions != 0 || connections != 0 || audits != 0 {
		t.Fatalf("failed creation left version/revision/sessions/connections/audits = %d/%d/%d/%d/%d, %v", version, revision, sessions, connections, audits, err)
	}
	if _, err := database.pool.Exec(t.Context(), `ALTER TABLE control.publish_run_connections DROP CONSTRAINT reject_second_slot`); err != nil {
		t.Fatal(err)
	}
	setup, err := database.CreatePublishRun(t.Context(), request, now, time.Hour, time.Hour)
	if err != nil || setup.PublishRunNumber != 1 {
		t.Fatalf("retry after rollback = %#v, %v", setup, err)
	}
	f := publishRunFixture{database: database, now: now, request: request, setup: setup, leases: leases}
	for slot, connection := range setup.PublisherConnections {
		lease := leases[connection.RelayServiceID]
		if connection.RelayAddress != lease.RelayAddress || connection.TLSServerName != lease.TLSServerName {
			t.Fatalf("slot %d has the wrong assigned relay address", slot)
		}
		claimTestConnection(t, f, slot, now)
	}
}

func TestIntegrationPublishRunCreationRejectsExhaustedCounters(t *testing.T) {
	for _, counter := range []string{"publish_run_number", "mutation_revision"} {
		t.Run(counter, func(t *testing.T) {
			database, now, request, _ := newPublishRunPrerequisites(t)
			version, revision := int64(1), int64(1)
			if counter == "publish_run_number" {
				version = math.MaxInt64
			} else {
				revision = math.MaxInt64
			}
			if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls SET next_publish_run_number = $2, mutation_revision = $3 WHERE id = $1`, request.PublicURLID, version, revision); err != nil {
				t.Fatal(err)
			}
			request.ExpectedMutationRevision = uint64(revision)
			if _, err := database.CreatePublishRun(t.Context(), request, now, time.Hour, time.Hour); err == nil || !strings.Contains(err.Error(), "exhausted") {
				t.Fatalf("exhausted %s: %v", counter, err)
			}
			var unchanged bool
			if err := database.pool.QueryRow(t.Context(), `SELECT next_publish_run_number = $2 AND mutation_revision = $3 AND NOT EXISTS (SELECT FROM control.publish_runs) FROM control.public_urls WHERE id = $1`, request.PublicURLID, version, revision).Scan(&unchanged); err != nil || !unchanged {
				t.Fatalf("exhausted creation changed state: %t, %v", unchanged, err)
			}
		})
	}
}

func TestIntegrationPublishRunReadiness(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now, authentication := f.database, f.now, f.authentication()
	if _, err := database.MarkPublishRunReady(t.Context(), authentication, now); !errors.Is(err, ErrPublishRunNotReady) {
		t.Fatalf("early readiness: %v", err)
	} else {
		var blocked *PublishRunNotReadyError
		if !errors.As(err, &blocked) || blocked.Reason() != "certificate_and_connections_missing" || blocked.ReadyPublisherConnectionCount != 0 {
			t.Fatalf("missing readiness prerequisites = %+v, %v", blocked, err)
		}
	}
	claimTestConnection(t, f, 0, now)
	work := createPlanIssuanceWork(t, database, now, authentication, f.certificatePlan(), true, nil)
	lifecycle, err := database.MarkPublicURLCertificateInstalled(t.Context(), authentication, work.ID, *work.NotAfter, now)
	if err != nil || lifecycle.State != "starting" || lifecycle.CertificateAt == nil || lifecycle.ReadyAt != nil || lifecycle.Routable || lifecycle.ReadyPublisherConnectionCount != 1 {
		t.Fatalf("certificate with one connection = %#v, %v", lifecycle, err)
	}
	if _, err := database.MarkPublishRunReady(t.Context(), authentication, now); !errors.Is(err, ErrPublishRunNotReady) {
		t.Fatalf("early readiness: %v", err)
	} else {
		var blocked *PublishRunNotReadyError
		if !errors.As(err, &blocked) || blocked.Reason() != "connections_missing" || blocked.ReadyPublisherConnectionCount != 1 || !blocked.CertificateInstalled {
			t.Fatalf("missing second ready connection = %+v, %v", blocked, err)
		}
	}
	issuance, err := database.GetCertificateIssuance(t.Context(), work.ID, authentication.PublishRunToken, now)
	if err != nil || issuance.State != "installed" {
		t.Fatalf("installed issuance = %#v, %v", issuance, err)
	}
	if _, err := database.MarkPublicURLCertificateInstalled(t.Context(), authentication, "issuance_other", *work.NotAfter, now); !errors.Is(err, ErrPublicURLCertificate) {
		t.Fatalf("wrong issuance acknowledgement: %v", err)
	}
	claimTestConnection(t, f, 1, now.Add(time.Second))
	lifecycle, err = database.MarkPublishRunReady(t.Context(), authentication, now.Add(2*time.Second))
	if err != nil || lifecycle.ReadyAt == nil || !lifecycle.Routable || lifecycle.ReadyPublisherConnectionCount != 2 {
		t.Fatalf("ready lifecycle = %#v, %v", lifecycle, err)
	}
	repeated, err := database.MarkPublicURLCertificateInstalled(t.Context(), authentication, work.ID, *work.NotAfter, now.Add(3*time.Second))
	if err != nil || !repeated.Routable || repeated.ReadyAt == nil || !repeated.ReadyAt.Equal(*lifecycle.ReadyAt) {
		t.Fatalf("certificate replay changed readiness = %#v, %v", repeated, err)
	}
}

func TestIntegrationPublishRunHeartbeatPreservesConnectionsAndExpiry(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls SET ephemeral = true, expires_at = $2 WHERE id = $1`, f.setup.PublicURLID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if count, err := database.DeleteExpiredEphemeralPublicURLs(t.Context(), now.Add(2*time.Second)); err != nil || count != 0 {
		t.Fatalf("active ephemeral cleanup = %d, %v", count, err)
	}
	for slot := range f.setup.PublisherConnections {
		claimTestConnection(t, f, slot, now)
	}
	heartbeatAt := now.Add(3 * time.Second)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_run_connections SET publisher_connection_credential_expires_at = $2 WHERE publish_run_id = $1`, f.setup.PublishRunID, heartbeatAt.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	lease := registerTestIngress(t, database, now)
	bucket := heartbeatAt.Truncate(time.Minute)
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, IngressUsageBatch{Reports: []IngressUsageReport{{
		PublicURLID: f.setup.PublicURLID, PublishRunNumber: f.setup.PublishRunNumber, BucketStart: bucket, BucketEnd: bucket.Add(time.Minute), ObservedThrough: heartbeatAt,
		ReportRevision: 1, ConnectionAttempts: 3, PolicyDenials: 3, HistogramData: (publicurlusage.Checkpoint{}).MarshalBinary(),
	}}}, heartbeatAt); err != nil {
		t.Fatal(err)
	}
	heartbeat, err := database.HeartbeatPublishRun(t.Context(), f.authentication(), heartbeatAt, 30*time.Second, time.Minute)
	if err != nil || !heartbeat.ExpiresAt.Equal(heartbeatAt.Add(30*time.Second)) || heartbeat.PublishRunNumber != f.setup.PublishRunNumber || heartbeat.PolicyDenials != 3 {
		t.Fatalf("heartbeat = %#v, %v", heartbeat, err)
	}
	route, err := database.GetPublicURL(t.Context(), f.request.ActingIdentityID, f.setup.PublicURLID)
	if err != nil || route.ExpiresAt == nil || !route.ExpiresAt.Equal(heartbeatAt.Add(ephemeralRouteGracePeriod)) {
		t.Fatalf("renewed ephemeral route = %#v, %v", route, err)
	}
	earlier, err := database.HeartbeatPublishRun(t.Context(), f.authentication(), heartbeatAt.Add(-time.Second), 10*time.Second, time.Minute)
	if err != nil || !earlier.ExpiresAt.Equal(heartbeat.ExpiresAt) {
		t.Fatalf("nonmonotonic heartbeat = %#v, %v", earlier, err)
	}
	monotonic, err := database.GetPublicURL(t.Context(), f.request.ActingIdentityID, f.setup.PublicURLID)
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

func TestIntegrationHealthyPublishRunHeartbeatSkipsUnrelatedPlacementLock(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	readyTestSession(t, f)
	if _, err := database.RegisterRelay(t.Context(), relayLifecycleRegistration("placement-unrelated"), now, time.Hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	gate, err := database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT relay_service_id FROM control.relay_services WHERE relay_service_id = 'placement-unrelated' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	workers := newIntegrationWorkers(t, cancel)
	workers.Go(func() {
		setup, err := database.HeartbeatPublishRun(ctx, f.authentication(), now.Add(time.Second), time.Hour, time.Minute)
		if err == nil {
			for slot, connection := range setup.PublisherConnections {
				previous := f.setup.PublisherConnections[slot]
				if connection.PublisherConnectionID != previous.PublisherConnectionID ||
					connection.ConnectionAssignmentRevision != previous.ConnectionAssignmentRevision ||
					connection.State != PublisherConnectionReady {
					err = errors.New("healthy heartbeat replaced publisher connections")
					break
				}
			}
		}
		done <- err
	})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("healthy heartbeat waited for an unrelated relay-service lock")
	}
}

type publishRunFixture struct {
	database *Database
	now      time.Time
	request  PublishRunRequest
	setup    PublishRunSetup
	leases   map[string]RelayLease
}

func newPublishRunPrerequisites(t *testing.T) (*Database, time.Time, PublishRunRequest, map[string]RelayLease) {
	t.Helper()
	database, now := newControlStateIntegrationDatabase(t, "publish_run")
	seedControlPublicURL(t, database, now, "session")
	leases := make(map[string]RelayLease)
	for slot := range publishRunConnectionCount {
		registration := relayLifecycleRegistration(fmt.Sprintf("placement-%d", slot))
		registration.ConnectionCapacity = 10
		lease, err := database.RegisterRelay(t.Context(), registration, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[lease.RelayServiceID] = lease
	}
	return database, now, PublishRunRequest{PublicURLID: "public_url_session", TeamID: "team_session", ActingIdentityID: "identity_session", MembershipID: "membership_session",
		RequireLocalAuthority: true, RetrySecret: bytes.Repeat([]byte{7}, 32), IdempotencyKey: "session", RequestDigest: sha256.Sum256([]byte("session")), PolicyRevision: 1,
		CertificateCacheKey: "certificate_session", CertificateScope: "public-url", CertificateIdentifiers: []string{"route-session.example.test"}, CertificateChallenge: "tls-alpn-01", ExpectedMutationRevision: 1}, leases
}

func newPublishRunFixture(t *testing.T) publishRunFixture {
	t.Helper()
	database, now, request, leases := newPublishRunPrerequisites(t)
	setup, err := database.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return publishRunFixture{database, now, request, setup, leases}
}

func (f publishRunFixture) authentication() PublishRunAuthentication {
	return PublishRunAuthentication{PublishRunID: f.setup.PublishRunID, PublicURLID: f.setup.PublicURLID, PublishRunNumber: f.setup.PublishRunNumber, PublishRunToken: f.setup.PublishRunToken}
}

func (f publishRunFixture) certificatePlan() CertificatePlan {
	return CertificatePlan{CacheKey: f.request.CertificateCacheKey, Scope: f.request.CertificateScope, Identifiers: f.request.CertificateIdentifiers, ChallengeMethod: f.request.CertificateChallenge}
}

func claimTestConnection(t *testing.T, f publishRunFixture, slot int, now time.Time) PublisherConnectionClaimRequest {
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

func readyTestSession(t *testing.T, f publishRunFixture) []PublisherConnectionClaimRequest {
	t.Helper()
	work := createPlanIssuanceWork(t, f.database, f.now, f.authentication(), f.certificatePlan(), true, nil)
	if _, err := f.database.MarkPublicURLCertificateInstalled(t.Context(), f.authentication(), work.ID, *work.NotAfter, f.now); err != nil {
		t.Fatal(err)
	}
	var claims []PublisherConnectionClaimRequest
	for slot := range f.setup.PublisherConnections {
		claims = append(claims, claimTestConnection(t, f, slot, f.now))
	}
	if _, err := f.database.MarkPublishRunReady(t.Context(), f.authentication(), f.now); err != nil {
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
