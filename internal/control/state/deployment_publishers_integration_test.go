package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func deploymentPublisherRequest(t *testing.T, d *Database, now time.Time) (ApplyProjectConfigurationRequest, CreateDeploymentPublisherEnrollmentRequest) {
	t.Helper()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"db":    {Protocol: "postgres", Target: "database.internal:5432"},
		"web":   {Target: "web.internal:3000"},
		"stage": {Protocol: "postgres", Target: "stage.internal:5432"},
	}}
	production := projectServiceSelection(r, "production", "db", "web")
	first, err := d.ApplyProjectConfiguration(t.Context(), production)
	if err != nil {
		t.Fatal(err)
	}
	staging := projectServiceSelection(r, "staging", "stage")
	staging.ExpectedRevision = first.Revision
	second, err := d.ApplyProjectConfiguration(t.Context(), staging)
	if err != nil {
		t.Fatal(err)
	}
	production.ExpectedRevision = second.Revision
	return production, CreateDeploymentPublisherEnrollmentRequest{DeploymentScope: DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}, Selector: "production", IdempotencyKey: "setup", Services: []string{"db"}, MaxMembers: 2, Lifetime: time.Hour, Now: now.Add(123456789 * time.Nanosecond)}
}

func TestIntegrationDeploymentPublisherScopeRecoveryAndRevocation(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r, request := deploymentPublisherRequest(t, d, now)
	enrollment, err := d.CreateDeploymentPublisherEnrollment(ctx, request)
	if err != nil || !reflect.DeepEqual(enrollment.Services, map[string]string{"db": "postgres"}) {
		t.Fatal("scoped setup did not capture the selected protocol", err)
	}
	request.Selector = enrollment.DeploymentID
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
	a := enrollAppliedDeployment(t, d, r, enrollment, now)
	b := enrollAppliedDeployment(t, d, r, enrollment, now)
	if len(a.assignments.Services) != 1 || a.assignments.Services[0].Service != "db" || len(b.assignments.Services) != 1 {
		t.Fatal("scoped enrollment granted unrelated targets")
	}
	// replay with a new key cannot recover a member from another enrollment in
	// the same deployment, nor turn its original installation key into wider authority.
	wider := request
	wider.IdempotencyKey, wider.Services = "wider", []string{"db", "web"}
	widerEnrollment, err := d.CreateDeploymentPublisherEnrollment(ctx, wider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RedeemDeploymentPublisherEnrollment(ctx, widerEnrollment.Key, a.private.Public().(ed25519.PublicKey), now); !errors.Is(err, ErrDeploymentPublisher) {
		t.Fatal("same public key recovered through another enrollment", err)
	}
	if _, err = d.CreateDeploymentPublisherEnrollment(ctx, request); !errors.Is(err, ErrPublisherEnrollment) {
		t.Fatal("exhausted setup was replaced or recovered as fresh authority", err)
	}
	// target changes replace exact grants, but neither add service names nor
	// change the captured protocol approval.
	r.Configuration.Services["cache"] = ProjectServiceConfiguration{Protocol: "tcp", Target: "cache.internal:6379"}
	r.ServiceDeclarations["cache"] = "tcp"
	db := r.Configuration.Services["db"]
	db.Target = "replacement.internal:5432"
	r.Configuration.Services["db"] = db
	updated, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := d.GetDeploymentPublisherAssignments(ctx, a.lease.AccessToken, now)
	if err != nil || len(assignments.Services) != 1 || assignments.Services[0].Service != "db" || assignments.Services[0].Configuration.Target != db.Target {
		t.Fatal("apply expanded setup scope or lost its approved target update", err)
	}
	assignment := assignments.Services[0]
	access := deploymentAssignmentAccess(t, d, a, assignment, now)
	prepared, err := d.PrepareServiceRun(ctx, assignment.ServiceID, access.PublisherIdentity, "scoped", now, ServiceRunRequest{Metadata: ServiceMetadata{Protocol: "postgres", PublisherPool: true, TrustRevision: assignment.TrustRevision}})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := PublisherRuntimeRequest{PublisherIdentityID: a.member.PublisherIdentityID, ScopeID: a.member.DeploymentID, ProcessRunID: strings.Repeat("a", 32), Action: "start", Audience: "https://control.example/v1/publisher-runtime", SourceIP: "8.8.8.8", Now: now}
	runtime.Assertion, err = publisherproof.Sign(a.member.PublisherIdentityID, a.member.KeyID, publisherproof.RuntimeScope(runtime.ScopeID, runtime.Action, runtime.ProcessRunID, 0, ""), runtime.Audience, a.private, now)
	if err != nil {
		t.Fatal(err)
	}
	started, err := d.PublisherRuntime(ctx, runtime)
	if err != nil || started.DeploymentLease == nil {
		t.Fatal("scoped publisher could not report its runtime", err)
	}
	if err = d.AcknowledgeDeploymentPublisherConfiguration(ctx, started.DeploymentLease.AccessToken, assignments.Revision, assignments.ConfigurationHash, true, now); err != nil {
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
	next, err := d.ListDeploymentPublishers(ctx, request.DeploymentScope, enrollment.DeploymentID, page[0].PublisherIdentityID, 1)
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
		if err = d.RevokeDeploymentPublisher(ctx, request.DeploymentScope, enrollment.DeploymentID, a.member.PublisherIdentityID, now); err != nil {
			t.Fatal("exact publisher revocation was not repeatable", err)
		}
	}
	if _, err = d.GetDeploymentPublisherAssignments(ctx, started.DeploymentLease.AccessToken, now); !errors.Is(err, ErrDeploymentPublisher) {
		t.Fatal("revocation retained the deployment lease", err)
	}
	if _, err = d.AuthenticatePublisherAccess(ctx, access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("revocation retained exact-service access", err)
	}
	var closed bool
	if err = d.pool.QueryRow(ctx, `SELECT closed_at IS NOT NULL FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatal("revocation left the publisher's run open", err)
	}
	if _, err = d.GetDeploymentPublisherAssignments(ctx, b.lease.AccessToken, now); err != nil {
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
	r.ExpectedRevision = updated.Revision
	db.Target = "third.internal:5432"
	r.Configuration.Services["db"] = db
	if _, err = d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RedeemDeploymentPublisherEnrollment(ctx, enrollment.Key, a.private.Public().(ed25519.PublicKey), now); !errors.Is(err, ErrDeploymentPublisher) {
		t.Fatal("apply or enrollment replay restored a revoked identity", err)
	}
}

func TestIntegrationDeploymentHTTPReplicasKeepExactGrantsAfterBootstrapExpiry(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	web := ProjectServiceConfiguration{Target: "https://web.internal:8443", Public: new(false), TargetTLS: appliedTargetTrust(t, "web.internal"), RequirePostQuantum: new(true),
		HTTP:    &config.HTTPService{Access: &config.Access{Mode: "anonymous", IP: []string{"192.0.2.0/24"}}, Limits: &config.WorkLimits{Total: new(7)}},
		Traffic: &trafficlimits.Selection{Connections: new(4), Rate: new(2), RatePer: new("1m")}}
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"web": web, "app": {Target: "app"}, "db": {Protocol: "postgres", Target: "db.internal:5432"},
	}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.CreateDeploymentPublisherEnrollment(ctx, CreateDeploymentPublisherEnrollmentRequest{
		DeploymentScope: DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}, Selector: "production",
		Services: []string{"web", "app"}, MaxMembers: 3, Lifetime: time.Minute, IdempotencyKey: "http-replicas", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := enrollAppliedDeployment(t, d, r, enrollment, now)
	second := enrollAppliedDeployment(t, d, r, enrollment, now)
	if len(first.assignments.Services) != 1 || len(second.assignments.Services) != 1 {
		t.Fatal("replica included app-owned or unapproved listeners")
	}
	a, b := first.assignments.Services[0], second.assignments.Services[0]
	// target TLS is a separate declaration, and duration values are canonical.
	// public reachability remains control's endpoint fact, not publisher intent.
	wantTraffic := *web.Traffic
	wantTraffic.RatePer = new("1m0s")
	if a.Service != "web" || !opaqueid.Valid(a.ServiceID, opaqueid.ServicePrefix) || a.ServiceID != b.ServiceID || a.TrustRevision < 1 || a.GrantID == b.GrantID ||
		first.member.PublisherIdentityID == second.member.PublisherIdentityID || a.Configuration.Public != nil || a.Configuration.Target != "web.internal:8443" ||
		a.Configuration.TargetTLS == nil || a.Configuration.HTTP == nil || a.Configuration.HTTP.Limits == nil || *a.Configuration.HTTP.Limits.Total != 7 ||
		a.Configuration.RequirePostQuantum == nil || !*a.Configuration.RequirePostQuantum || !reflect.DeepEqual(a.Configuration.Traffic, &wantTraffic) {
		t.Fatalf("HTTP assignment lost exact service identity, independent grants, or saved declaration: first=%+v second=%+v configuration=%+v traffic=%+v want traffic=%+v",
			a, b, a.Configuration, a.Configuration.Traffic, web.Traffic)
	}
	wire, err := json.Marshal(a)
	if err != nil || bytes.Contains(wire, []byte(`"service_kind"`)) || !bytes.Contains(wire, []byte(`"trust_revision":"`)) {
		t.Fatal("HTTP assignment retained a separate publication contract", err)
	}
	q := controlstatedb.New(d.pool)
	captured, err := q.ListDeploymentPublisherEnrollmentServices(ctx, enrollment.ID)
	if err != nil || len(captured) != 2 {
		t.Fatal("enrollment did not retain exact ordinary service bindings", err)
	}
	for _, captured := range captured {
		if !opaqueid.Valid(captured.ServiceID, opaqueid.ServicePrefix) || captured.Protocol != "http" || captured.RevokedAt.Valid {
			t.Fatal("enrollment captured a non-service binding")
		}
	}
	// an endpoint-only change retains each replica's exact grant. the renewed
	// assignments below must keep those same grants beyond bootstrap expiry.
	r.ExpectedRevision = applied.Revision
	web.Public = new(true)
	r.Configuration.Services["web"] = web
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	later := enrollment.ExpiresAt.Add(time.Hour)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RedeemDeploymentPublisherEnrollment(ctx, enrollment.Key, public, later); !errors.Is(err, ErrDeploymentPublisher) {
		t.Fatal("expired bootstrap admitted a new replica", err)
	}
	leases := map[string]DeploymentPublisherLease{}
	for _, replica := range []enrolledDeploymentReplica{first, second} {
		const audience = "https://control.example/v1/publisher/deployments/lease"
		assertion, err := publisherproof.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, replica.member.DeploymentID, audience, replica.private, later)
		if err != nil {
			t.Fatal(err)
		}
		lease, err := d.AcquireDeploymentPublisherLease(ctx, replica.member.PublisherIdentityID, replica.member.DeploymentID, assertion, audience, later)
		if err != nil {
			t.Fatal("bootstrap expiry expired an enrolled replica's signing key", err)
		}
		leases[replica.member.PublisherIdentityID] = lease
		assignments, err := d.GetDeploymentPublisherAssignments(ctx, lease.AccessToken, later)
		if err != nil || len(assignments.Services) != 1 || assignments.Member != replica.member ||
			assignments.Services[0].GrantID != replica.assignments.Services[0].GrantID || assignments.Services[0].ServiceID != a.ServiceID {
			t.Fatal("bootstrap expiry replaced or removed the original exact grant", err)
		}
		assignment := assignments.Services[0]
		access := deploymentAssignmentAccess(t, d, replica, assignment, later)
		if access.Scope.Kind != "service" || access.Scope.ServiceID != a.ServiceID || access.KeyID != replica.member.KeyID {
			t.Fatal("replica lost its real exact-service grant or original signing key")
		}
		var permanent bool
		if err := d.pool.QueryRow(ctx, `SELECT kind='service' AND service_id=$2 AND publisher_identity_id=$3 AND expires_at IS NULL AND revoked_at IS NULL FROM control.publisher_grants WHERE id=$1`,
			assignment.GrantID, a.ServiceID, replica.member.PublisherIdentityID).Scan(&permanent); err != nil || !permanent {
			t.Fatal("replica grant was manufactured from or expired with bootstrap", err)
		}
		saved, err := d.GetServiceForPublisher(ctx, a.ServiceID, access.PublisherIdentity, later)
		if err != nil || !saved.RequirePostQuantum || saved.HTTPLimits == nil || *saved.HTTPLimits.Total != 7 || saved.TLS == nil {
			t.Fatal("service worker lost saved target TLS, PQ, or HTTP request limits", err)
		}
		request := ServiceRunRequest{Metadata: saved.ServiceMetadata, TrafficSelection: assignment.Configuration.Traffic}
		prepared, err := d.PrepareServiceRun(ctx, a.ServiceID, access.PublisherIdentity, "http-replica", later, request)
		if err != nil || prepared.Traffic.Connections != 4 || prepared.Traffic.Rate != 2 || prepared.Traffic.RatePer != time.Minute {
			t.Fatal("ordinary HTTP service run lost saved traffic settings", err)
		}
	}
	mode, err := d.serviceHTTPSourcePolicy(ctx, q, a.ServiceID, netip.MustParseAddr("192.0.2.10"))
	if err != nil || mode != VisitorAccessAnonymous {
		t.Fatal("saved HTTP access policy was not available to the ordinary service", err)
	}
	if _, err := d.serviceHTTPSourcePolicy(ctx, q, a.ServiceID, netip.MustParseAddr("198.51.100.10")); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("saved HTTP IP restriction was lost", err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}
	if err := d.RevokeDeploymentPublisher(ctx, scope, "production", first.member.PublisherIdentityID, later); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetDeploymentPublisherAssignments(ctx, leases[first.member.PublisherIdentityID].AccessToken, later); !errors.Is(err, ErrDeploymentPublisher) {
		t.Fatal("revoked HTTP replica retained its renewed lease", err)
	}
	sibling, err := d.GetDeploymentPublisherAssignments(ctx, leases[second.member.PublisherIdentityID].AccessToken, later)
	if err != nil || len(sibling.Services) != 1 || sibling.Services[0].GrantID != b.GrantID {
		t.Fatal("revoking one HTTP replica disturbed its sibling's exact service grant", err)
	}
}

func TestIntegrationDeploymentPublisherAssignmentsRejectUnavailableServices(t *testing.T) {
	for _, unavailable := range []string{"disabled", "expired", "revoked-grant", "expired-grant"} {
		t.Run(unavailable, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "publisher_unavailable")
			r, request := deploymentPublisherRequest(t, d, now)
			request.Services = []string{"web"}
			enrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			replica := enrollAppliedDeployment(t, d, r, enrollment, now)
			assignment := replica.assignments.Services[0]
			switch unavailable {
			case "disabled":
				_, err = d.pool.Exec(t.Context(), `UPDATE control.services SET enabled=false WHERE id=$1`, assignment.ServiceID)
			case "expired":
				_, err = d.pool.Exec(t.Context(), `UPDATE control.services SET expires_at=$2 WHERE id=$1`, assignment.ServiceID, now.Add(time.Second))
			case "revoked-grant":
				_, err = d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, assignment.GrantID, now)
			case "expired-grant":
				_, err = d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, assignment.GrantID, now.Add(time.Second))
			}
			if err != nil {
				t.Fatal(err)
			}
			after, err := d.GetDeploymentPublisherAssignments(t.Context(), replica.lease.AccessToken, now.Add(time.Second))
			if unavailable == "disabled" || unavailable == "expired" {
				if !errors.Is(err, ErrDeploymentPublisher) {
					t.Fatal("unavailable service retained an assignment", err)
				}
			} else if err != nil || len(after.Services) != 0 {
				t.Fatal("unavailable exact grant retained an assignment", err)
			}
		})
	}
}

func TestIntegrationDeploymentPublisherApprovalCannotFollowReusedBindings(t *testing.T) {
	for _, test := range []struct{ protocol, mutation string }{
		{"postgres", "protocol"}, {"postgres", "remove"}, {"http", "protocol"}, {"http", "remove"},
	} {
		t.Run(test.protocol+"/"+test.mutation, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "publisher_approval_"+test.mutation)
			r, request := deploymentPublisherRequest(t, d, now)
			if test.protocol == "http" {
				service := r.Configuration.Services["db"]
				service.Protocol, service.Public = test.protocol, new(false)
				r.Configuration.Services["db"] = service
				r.ServiceDeclarations["db"] = test.protocol
				applied, err := d.ApplyProjectConfiguration(t.Context(), r)
				if err != nil {
					t.Fatal(err)
				}
				r.ExpectedRevision = applied.Revision
			}
			enrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			replica := enrollAppliedDeployment(t, d, r, enrollment, now)
			db := r.Configuration.Services["db"]
			if test.mutation == "protocol" {
				changed := db
				changed.Protocol = "mysql"
				r.Configuration.Services["db"] = changed
				r.ServiceDeclarations["db"] = changed.Protocol
			} else {
				delete(r.Configuration.Services, "db")
			}
			updated, err := d.ApplyProjectConfiguration(t.Context(), r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = d.CreateDeploymentPublisherEnrollment(t.Context(), request); !errors.Is(err, ErrPublisherEnrollment) {
				t.Fatal("recovery followed changed service approval", err)
			}
			r.ExpectedRevision = updated.Revision
			r.Configuration.Services["db"] = db
			r.ServiceDeclarations["db"] = db.Protocol
			if _, err = d.ApplyProjectConfiguration(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			assignments, err := d.GetDeploymentPublisherAssignments(t.Context(), replica.lease.AccessToken, now)
			if err != nil || len(assignments.Services) != 0 {
				t.Fatal("rollback or a reused name restored retired approval", err)
			}
			public, _, _ := ed25519.GenerateKey(rand.Reader)
			if _, err = d.RedeemDeploymentPublisherEnrollment(t.Context(), enrollment.Key, public, now); !errors.Is(err, ErrDeploymentPublisher) {
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
	if err = d.pool.QueryRow(t.Context(), `SELECT secret_ciphertext FROM control.deployment_publisher_enrollments WHERE id=$1`, original.ID).Scan(&sealed); err != nil || len(sealed) == 0 || bytes.Contains(sealed, []byte(original.Key)) {
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
			replica := enrollAppliedDeployment(t, d, r, enrollment, now)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err = controlstatedb.New(gate).LockDeploymentByID(ctx, enrollment.DeploymentID); err != nil {
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
					_, err = d.GetDeploymentPublisher(ctx, request.DeploymentScope, enrollment.DeploymentID, replica.member.PublisherIdentityID)
				case "list":
					_, err = d.ListDeploymentPublishers(ctx, request.DeploymentScope, enrollment.DeploymentID, "", 100)
				case "revoke":
					err = d.RevokeDeploymentPublisher(ctx, request.DeploymentScope, enrollment.DeploymentID, replica.member.PublisherIdentityID, now)
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
			if err = d.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.deployment_publisher_enrollments WHERE deployment_id=$1),revoked_at IS NOT NULL FROM control.publisher_identities WHERE id=$2`, enrollment.DeploymentID, replica.member.PublisherIdentityID).Scan(&count, &revoked); err != nil || count != 1 || revoked {
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
			if _, err = controlstatedb.New(gate).LockDeploymentPublisherEnrollment(ctx, enrollment.ID); err != nil {
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
					_, err = d.RedeemDeploymentPublisherEnrollment(ctx, enrollment.Key, public, request.Now)
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
				want = ErrDeploymentPublisher
			}
			if !errors.Is(err, want) {
				t.Fatal("lock wait renewed or admitted expired setup authority", err)
			}
			var members int
			if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.deployment_publisher_members WHERE enrollment_id=$1`, enrollment.ID).Scan(&members); err != nil || members != 0 {
				t.Fatal("expired enrollment committed a publisher", members, err)
			}
		})
	}
}
