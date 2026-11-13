package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func deploymentPublisherRequest(t *testing.T, d *Database, now time.Time) (ApplyProjectConfigurationRequest, CreateDeploymentPublisherEnrollmentRequest) {
	t.Helper()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}, "staging": {}}, Services: map[string]ProjectServiceConfiguration{
		"db":    {PublisherGroup: "production", Protocol: "postgres", Target: "database.internal:5432"},
		"web":   {PublisherGroup: "production", Target: "web.internal:3000"},
		"stage": {PublisherGroup: "staging", Protocol: "postgres", Target: "stage.internal:5432"},
	}}
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	return r, CreateDeploymentPublisherEnrollmentRequest{DeploymentScope: DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}, Selector: "production", IdempotencyKey: "setup", Services: []string{"db"}, MaxMembers: 2, Lifetime: time.Hour, Now: now.Add(123456789 * time.Nanosecond)}
}

func TestIntegrationDeploymentPublisherScopeRecoveryAndRevocation(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r, request := deploymentPublisherRequest(t, d, now)
	enrollment, err := d.CreateDeploymentPublisherEnrollment(ctx, request)
	if err != nil || !reflect.DeepEqual(enrollment.Services, map[string]string{"db": "postgres"}) {
		t.Fatal("scoped setup did not capture the selected protocol", err)
	}
	request.Selector = enrollment.GroupID
	recovered, err := d.CreateDeploymentPublisherEnrollment(ctx, request)
	if err != nil || !reflect.DeepEqual(recovered, enrollment) {
		t.Fatal("lost setup reply changed its secret, scope, or fixed deadline", err)
	}
	for _, names := range [][]string{{"web"}, {"db", "web"}} {
		other := request
		other.Services = names
		if _, err = d.CreateDeploymentPublisherEnrollment(ctx, other); !errors.Is(err, ErrServiceConflict) {
			t.Fatal("original key accepted different service intent", err)
		}
	}
	for _, names := range [][]string{nil, {"missing"}, {"db", "db"}, {"stage"}} {
		other := request
		other.IdempotencyKey, other.Services = "invalid", names
		if _, err = d.CreateDeploymentPublisherEnrollment(ctx, other); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("invalid or foreign binding admitted", names, err)
		}
	}
	a := enrollAppliedGroup(t, d, r, enrollment.PublisherGroupEnrollment, now)
	b := enrollAppliedGroup(t, d, r, enrollment.PublisherGroupEnrollment, now)
	if len(a.assignments.Services) != 1 || a.assignments.Services[0].Service != "db" || len(b.assignments.Services) != 1 {
		t.Fatal("scoped enrollment granted unrelated targets")
	}
	// replay with a new key cannot recover a member from another enrollment in
	// the same group, nor turn its original installation key into wider authority.
	wider := request
	wider.IdempotencyKey, wider.Services = "wider", []string{"db", "web"}
	widerEnrollment, err := d.CreateDeploymentPublisherEnrollment(ctx, wider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RedeemPublisherGroupEnrollment(ctx, widerEnrollment.Key, a.private.Public().(ed25519.PublicKey), now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("same public key recovered through another enrollment", err)
	}
	if _, err = d.CreateDeploymentPublisherEnrollment(ctx, request); !errors.Is(err, ErrPublisherEnrollment) {
		t.Fatal("exhausted setup was replaced or recovered as fresh authority", err)
	}
	// target changes replace exact grants, but neither add service names nor
	// change the captured protocol approval.
	r.ExpectedRevision = 1
	r.Configuration.Services["cache"] = ProjectServiceConfiguration{PublisherGroup: "production", Protocol: "tcp", Target: "cache.internal:6379"}
	db := r.Configuration.Services["db"]
	db.Target = "replacement.internal:5432"
	r.Configuration.Services["db"] = db
	if _, err = d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	assignments, err := d.GetPublisherGroupAssignments(ctx, a.lease.AccessToken, now)
	if err != nil || len(assignments.Services) != 1 || assignments.Services[0].Service != "db" || assignments.Services[0].Configuration.Target != db.Target {
		t.Fatal("apply expanded setup scope or lost its approved target update", err)
	}
	assignment := assignments.Services[0]
	access := groupAssignmentAccess(t, d, a, assignment, now)
	prepared, err := d.PrepareServiceRun(ctx, assignment.ServiceID, access.PublisherIdentity, "scoped", now, ServiceMetadata{Protocol: "postgres", PublisherPool: true, TrustRevision: assignment.TrustRevision})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := PublisherRuntimeRequest{PublisherIdentityID: a.member.PublisherIdentityID, ScopeID: a.member.GroupID, ProcessRunID: strings.Repeat("a", 32), Action: "start", Audience: "https://control.example/v1/publisher-runtime", SourceIP: "8.8.8.8", Now: now}
	runtime.Assertion, err = publisherproof.Sign(a.member.PublisherIdentityID, a.member.KeyID, publisherproof.RuntimeScope(runtime.ScopeID, runtime.Action, runtime.ProcessRunID, 0, ""), runtime.Audience, a.private, now)
	if err != nil {
		t.Fatal(err)
	}
	started, err := d.PublisherRuntime(ctx, runtime)
	if err != nil || started.GroupLease == nil {
		t.Fatal("scoped publisher could not report its runtime", err)
	}
	if err = d.AcknowledgePublisherGroupConfiguration(ctx, started.GroupLease.AccessToken, assignments.Revision, assignments.ConfigurationHash, true, now); err != nil {
		t.Fatal(err)
	}
	status, err := d.GetDeploymentPublisher(ctx, request.DeploymentScope, "production", a.member.PublisherIdentityID)
	if err != nil || !status.Healthy || status.Runtime == nil || !status.Runtime.Active || status.Runtime.Address != "8.8.8.8" || !reflect.DeepEqual(status.Services, enrollment.Services) {
		t.Fatal("scoped read lost the real publisher observation", status, err)
	}
	page, err := d.ListDeploymentPublishers(ctx, request.DeploymentScope, "production", "", 1)
	if err != nil || len(page) != 1 {
		t.Fatal("publisher page unavailable", err)
	}
	next, err := d.ListDeploymentPublishers(ctx, request.DeploymentScope, enrollment.GroupID, page[0].PublisherIdentityID, 1)
	if err != nil || len(next) != 1 || next[0].PublisherIdentityID == page[0].PublisherIdentityID {
		t.Fatal("publisher pagination repeated or lost an identity", err)
	}
	if _, err = d.GetDeploymentPublisher(ctx, request.DeploymentScope, "staging", a.member.PublisherIdentityID); !errors.Is(err, ErrDeploymentPublisherNotFound) {
		t.Fatal("publisher observation crossed deployments", err)
	}
	if err = d.RevokeDeploymentPublisher(ctx, request.DeploymentScope, "staging", a.member.PublisherIdentityID, now); !errors.Is(err, ErrDeploymentPublisherNotFound) {
		t.Fatal("publisher revocation crossed deployments", err)
	}
	for range 2 {
		if err = d.RevokeDeploymentPublisher(ctx, request.DeploymentScope, enrollment.GroupID, a.member.PublisherIdentityID, now); err != nil {
			t.Fatal("exact publisher revocation was not repeatable", err)
		}
	}
	if _, err = d.GetPublisherGroupAssignments(ctx, started.GroupLease.AccessToken, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("revocation retained the group lease", err)
	}
	if _, err = d.AuthenticatePublisherAccess(ctx, access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("revocation retained exact-service access", err)
	}
	var closed bool
	if err = d.pool.QueryRow(ctx, `SELECT closed_at IS NOT NULL FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatal("revocation left the publisher's run open", err)
	}
	if _, err = d.GetPublisherGroupAssignments(ctx, b.lease.AccessToken, now); err != nil {
		t.Fatal("revoking one publisher disturbed its sibling", err)
	}
	status, err = d.GetDeploymentPublisher(ctx, request.DeploymentScope, "production", a.member.PublisherIdentityID)
	if err != nil || status.RevokedAt == nil || status.Healthy || status.Runtime == nil || status.Runtime.Active || status.Runtime.Address != "8.8.8.8" {
		t.Fatal("revocation lost the observation or retained healthy status", status, err)
	}
	wire, err := json.Marshal(status)
	if err != nil || bytes.Contains(wire, []byte("enrollment_key")) || bytes.Contains(wire, []byte("access_token")) || bytes.Contains(wire, []byte("target")) || bytes.Contains(wire, []byte(enrollment.Key)) {
		t.Fatal("publisher read exposed setup secrets or targets", err)
	}
	r.ExpectedRevision = 2
	db.Target = "third.internal:5432"
	r.Configuration.Services["db"] = db
	if _, err = d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RedeemPublisherGroupEnrollment(ctx, enrollment.Key, a.private.Public().(ed25519.PublicKey), now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("apply or enrollment replay restored a revoked identity", err)
	}
}

func TestIntegrationDeploymentPublisherApprovalCannotFollowReusedBindings(t *testing.T) {
	for _, mutation := range []string{"protocol", "remove"} {
		t.Run(mutation, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "publisher_approval_"+mutation)
			r, request := deploymentPublisherRequest(t, d, now)
			enrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			replica := enrollAppliedGroup(t, d, r, enrollment.PublisherGroupEnrollment, now)
			r.ExpectedRevision = 1
			db := r.Configuration.Services["db"]
			if mutation == "protocol" {
				changed := db
				changed.Protocol = "mysql"
				r.Configuration.Services["db"] = changed
			} else {
				delete(r.Configuration.Services, "db")
			}
			if _, err = d.ApplyProjectConfiguration(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			if _, err = d.CreateDeploymentPublisherEnrollment(t.Context(), request); !errors.Is(err, ErrPublisherEnrollment) {
				t.Fatal("recovery followed changed service approval", err)
			}
			r.ExpectedRevision = 2
			r.Configuration.Services["db"] = db
			if _, err = d.ApplyProjectConfiguration(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			assignments, err := d.GetPublisherGroupAssignments(t.Context(), replica.lease.AccessToken, now)
			if err != nil || len(assignments.Services) != 0 {
				t.Fatal("rollback or a reused name restored retired approval", err)
			}
			public, _, _ := ed25519.GenerateKey(rand.Reader)
			if _, err = d.RedeemPublisherGroupEnrollment(t.Context(), enrollment.Key, public, now); !errors.Is(err, ErrPublisherGroup) {
				t.Fatal("old enrollment admitted a new publisher after binding reuse", err)
			}
			request.IdempotencyKey = "new-approval"
			if _, err = d.CreateDeploymentPublisherEnrollment(t.Context(), request); err != nil {
				t.Fatal("current manager could not explicitly approve the current binding", err)
			}
		})
	}
}

func TestIntegrationDeploymentPublisherRecoverySurvivesStorageRotation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_enrollment_rotation")
	_, request := deploymentPublisherRequest(t, d, now)
	original, err := d.CreateDeploymentPublisherEnrollment(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err = d.pool.QueryRow(t.Context(), `SELECT secret_ciphertext FROM control.publisher_group_enrollments WHERE id=$1`, original.ID).Scan(&sealed); err != nil || len(sealed) == 0 || bytes.Contains(sealed, []byte(original.Key)) {
		t.Fatal("recoverable setup secret was not encrypted", err)
	}
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	rotated, err := Open(t.Context(), d.pool.Config().ConnString(), key, testStorageKey, d.managedURLMode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotated.Close)
	if err = rotated.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	current, err := Open(t.Context(), d.pool.Config().ConnString(), key, "", d.managedURLMode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(current.Close)
	recovered, err := current.CreateDeploymentPublisherEnrollment(t.Context(), request)
	if err != nil || !reflect.DeepEqual(recovered, original) {
		t.Fatal("storage rotation changed setup recovery", err)
	}
}

func TestIntegrationDeploymentPublisherManagerRevocationDuringLockWait(t *testing.T) {
	for _, operation := range []string{"create", "recover", "get", "list", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "publisher_manager_"+operation)
			r, request := deploymentPublisherRequest(t, d, now)
			enrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			replica := enrollAppliedGroup(t, d, r, enrollment.PublisherGroupEnrollment, now)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err = controlstatedb.New(gate).LockProjectPublisherGroup(ctx, enrollment.GroupID); err != nil {
				t.Fatal(err)
			}
			if operation == "create" {
				request.IdempotencyKey = "new-setup"
			}
			done := make(chan error, 1)
			workers.Go(func() {
				var err error
				switch operation {
				case "create", "recover":
					_, err = d.CreateDeploymentPublisherEnrollment(ctx, request)
				case "get":
					_, err = d.GetDeploymentPublisher(ctx, request.DeploymentScope, enrollment.GroupID, replica.member.PublisherIdentityID)
				case "list":
					_, err = d.ListDeploymentPublishers(ctx, request.DeploymentScope, enrollment.GroupID, "", 100)
				case "revoke":
					err = d.RevokeDeploymentPublisher(ctx, request.DeploymentScope, enrollment.GroupID, replica.member.PublisherIdentityID, now)
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			if _, err = gate.Exec(ctx, `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, r.ActorID, now); err != nil {
				t.Fatal(err)
			}
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("publisher management escaped revocation during a lock wait", err)
			}
			var count int
			var revoked bool
			if err = d.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.publisher_group_enrollments WHERE group_id=$1),revoked_at IS NOT NULL FROM control.publisher_identities WHERE id=$2`, enrollment.GroupID, replica.member.PublisherIdentityID).Scan(&count, &revoked); err != nil || count != 1 || revoked {
				t.Fatal("denied publisher management committed state", count, revoked, err)
			}
		})
	}
}

func TestIntegrationDeploymentPublisherEnrollmentExpiryDuringLockWait(t *testing.T) {
	for _, operation := range []string{"recover", "redeem"} {
		t.Run(operation, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "publisher_deadline_"+operation)
			_, request := deploymentPublisherRequest(t, d, now)
			enrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err = controlstatedb.New(gate).LockPublisherGroupEnrollment(ctx, enrollment.ID); err != nil {
				t.Fatal(err)
			}
			public, _, _ := ed25519.GenerateKey(rand.Reader)
			done, entered := make(chan error, 1), make(chan time.Time, 1)
			request.Now = enrollment.ExpiresAt.Add(-time.Second)
			workers.Go(func() {
				entered <- time.Now()
				var err error
				if operation == "recover" {
					_, err = d.CreateDeploymentPublisherEnrollment(ctx, request)
				} else {
					_, err = d.RedeemPublisherGroupEnrollment(ctx, enrollment.Key, public, request.Now)
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			started := awaitIntegrationResult(t, ctx, entered)
			timer := time.NewTimer(time.Until(started.Add(time.Second + 50*time.Millisecond)))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = awaitIntegrationResult(t, ctx, done)
			want := ErrPublisherEnrollment
			if operation == "redeem" {
				want = ErrPublisherGroup
			}
			if !errors.Is(err, want) {
				t.Fatal("lock wait renewed or admitted expired setup authority", err)
			}
			var members int
			if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_group_members WHERE enrollment_id=$1`, enrollment.ID).Scan(&members); err != nil || members != 0 {
				t.Fatal("expired enrollment committed a publisher", members, err)
			}
		})
	}
}
