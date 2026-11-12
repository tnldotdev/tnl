package state

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type environmentPublisherGrantFixture struct {
	d           *Database
	now         time.Time
	session     ControlSession
	r           environmentPublisherTestProject
	environment Environment
	creation    CreateEnvironmentRequest
	publisher   environmentPublisherReplica
	mutation    EnvironmentPublisherGrantMutation
	definition  ServiceDefinitionRevision
	metrics     EnvironmentService
}

func newEnvironmentPublisherGrantFixture(t *testing.T) *environmentPublisherGrantFixture {
	t.Helper()
	d, now, _, _ := newPublishRunPrerequisites(t)
	session := newOIDCSession(t, d, now)
	team, err := d.CreateTeam(t.Context(), authorityTeamRequest(session.Identity.Identity.ID), now)
	if err != nil {
		t.Fatal(err)
	}
	r := environmentPublisherTestProject{TeamID: team.ID, ProjectKey: "publisher-grants", ActorID: session.Identity.Identity.ID, SourceFingerprint: strings.Repeat("a", 64), AccessToken: session.AccessToken, Now: now}
	definition := environmentPublisherDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	environment, creation := createPublisherTestEnvironment(t, d, r, "production", definition.Revision, EnvironmentTargets{"api": {Address: "api.internal:3000"}})
	publisher := enrollEnvironmentPublisher(t, d, r, environment)
	return &environmentPublisherGrantFixture{d: d, now: now, session: session, r: r, environment: environment, creation: creation, publisher: publisher}
}

func (f *environmentPublisherGrantFixture) grow(t *testing.T) {
	t.Helper()
	f.definition = environmentPublisherDefinition(t, f.d, f.r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "metrics": {Protocol: "http"}})
	updated, err := f.d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, ActorID: f.r.ActorID, Now: f.now,
		EnvironmentApplication: EnvironmentApplication{EnvironmentID: f.environment.ID, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: f.definition.Revision,
			Targets: EnvironmentTargets{"api": {Address: "api.internal:3000"}, "metrics": {Address: "metrics.internal:9090"}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range updated.Services {
		if service.Service == "metrics" {
			f.metrics = service
		} else if service.Service == "api" && (service.ServiceID != f.environment.Services[0].ServiceID || service.Hostname != f.environment.Services[0].Hostname || service.Port != f.environment.Services[0].Port) {
			t.Fatal("growth replaced the retained api endpoint")
		}
	}
	if f.metrics.ServiceID == "" || f.metrics.Hostname == "" || f.metrics.Port == 0 {
		t.Fatal("growth did not allocate the metrics endpoint")
	}
	f.environment = updated
	manager, err := f.d.AuthenticateEnvironmentPublisherManager(t.Context(), f.session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	f.mutation = EnvironmentPublisherGrantMutation{InspectEnvironmentPublisherGrantRequest: InspectEnvironmentPublisherGrantRequest{
		EnvironmentPublisherGrantSelection: EnvironmentPublisherGrantSelection{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, EnvironmentID: updated.ID, PublisherIdentityID: f.publisher.member.PublisherIdentityID, ServiceID: f.metrics.ServiceID}, Manager: manager},
		ExpectedRevision: updated.MutationRevision, ExpectedConfigurationHash: updated.ConfigurationHash}
}

func (f *environmentPublisherGrantFixture) request(key string) AuthorizeEnvironmentPublisherServiceRequest {
	return AuthorizeEnvironmentPublisherServiceRequest{EnvironmentPublisherGrantMutation: f.mutation, ExpectedPreviousGrantID: ExpectNoEnvironmentPublisherGrant(), IdempotencyKey: key}
}

func environmentPublisherGrantExpected(t *testing.T, id string) EnvironmentPublisherGrantExpectation {
	t.Helper()
	expectation, err := ExpectEnvironmentPublisherGrant(id)
	if err != nil {
		t.Fatal(err)
	}
	return expectation
}

func (f *environmentPublisherGrantFixture) assignments(t *testing.T, member environmentPublisherReplica) EnvironmentPublisherAssignments {
	t.Helper()
	assignments, err := f.d.GetEnvironmentPublisherAssignments(t.Context(), member.lease.AccessToken, f.now)
	if err != nil || assignments.Publisher != member.member {
		t.Fatal("publisher poll changed the installed identity or key", err)
	}
	return assignments
}

func (f *environmentPublisherGrantFixture) acknowledge(t *testing.T, member environmentPublisherReplica) {
	t.Helper()
	a := f.assignments(t, member)
	if err := f.d.AcknowledgeEnvironmentPublisher(t.Context(), member.lease.AccessToken, a.Environment, true, f.now); err != nil {
		t.Fatal(err)
	}
}

func (f *environmentPublisherGrantFixture) healthy(t *testing.T, member environmentPublisherReplica) bool {
	t.Helper()
	var healthy bool
	if err := f.d.pool.QueryRow(t.Context(), `SELECT healthy FROM control.publisher_group_members WHERE publisher_identity_id=$1`, member.member.PublisherIdentityID).Scan(&healthy); err != nil {
		t.Fatal(err)
	}
	return healthy
}

func (f *environmentPublisherGrantFixture) start(t *testing.T, member environmentPublisherReplica, name, key string) (ServiceRunState, PublisherAccess) {
	t.Helper()
	assignments := f.assignments(t, member)
	for _, assignment := range assignments.Services {
		if assignment.Service != name {
			continue
		}
		access := environmentAssignmentAccess(t, f.d, member, assignment, f.now)
		prepared, err := f.d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, key, f.now,
			ServiceMetadata{Protocol: "http", PublisherPool: true, TrustRevision: assignment.TrustRevision}, &assignments.Environment)
		if err != nil {
			t.Fatal(err)
		}
		run, err := f.d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, f.now)
		if err != nil {
			t.Fatal(err)
		}
		return run, access
	}
	t.Fatal("missing assigned service", name)
	return ServiceRunState{}, PublisherAccess{}
}

func (f *environmentPublisherGrantFixture) assertNoMetricsAuthority(t *testing.T) {
	t.Helper()
	var grants, mappings, receipts int
	err := f.d.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1 AND service_id=$2),
		(SELECT count(*) FROM control.publisher_group_service_grants mapping JOIN control.applied_project_services binding USING(team_id,project_key,service) WHERE mapping.publisher_identity_id=$1 AND binding.service_id=$2),
		(SELECT count(*) FROM control.environment_publisher_grant_requests WHERE environment_id=$3)`, f.publisher.member.PublisherIdentityID, f.metrics.ServiceID, f.environment.ID).Scan(&grants, &mappings, &receipts)
	if err != nil || grants != 0 || mappings != 0 || receipts != 0 {
		t.Fatal("denied or implicit authorization saved authority or intent", grants, mappings, receipts, err)
	}
}

func TestIntegrationEnvironmentPublisherGrantsSameInstalledPublisher(t *testing.T) {
	f := newEnvironmentPublisherGrantFixture(t)
	sibling := enrollEnvironmentPublisher(t, f.d, f.r, f.environment)
	f.grow(t)
	f.assertNoMetricsAuthority(t)
	before, err := f.d.GetEnvironmentPublisherGrant(t.Context(), f.mutation.InspectEnvironmentPublisherGrantRequest)
	if err != nil || before.Grant != nil || before.MutationRevision != f.environment.MutationRevision || before.ConfigurationHash != f.environment.ConfigurationHash {
		t.Fatal("inspect must distinguish an absent mapping", before, err)
	}
	api, _ := f.start(t, f.publisher, "api", "publisher-api")
	siblingAPI, _ := f.start(t, sibling, "api", "sibling-api")
	f.acknowledge(t, f.publisher)
	f.acknowledge(t, sibling)
	request := f.request("approve-metrics-1")
	created, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request)
	if err != nil || !created.Created || created.Grant == nil || !opaqueid.Valid(created.Grant.ID, opaqueid.PublisherGrantPrefix) || created.Grant.CreatedByIdentityID != f.r.ActorID {
		t.Fatal("explicit authorization did not create an exact grant", created, err)
	}
	if f.healthy(t, f.publisher) || !f.healthy(t, sibling) {
		t.Fatal("authorization invalidated the wrong member")
	}
	assignments := f.assignments(t, f.publisher)
	if len(assignments.Services) != 2 || assignments.Environment != environmentPublicationForTest(f.environment) || len(f.assignments(t, sibling).Services) != 1 {
		t.Fatal("authorization changed the environment fence, identity, or another publisher's scope")
	}
	metrics, access := f.start(t, f.publisher, "metrics", "metrics-first-grant")
	siblingIntent := f.request("approve-sibling-metrics")
	siblingIntent.PublisherIdentityID = sibling.member.PublisherIdentityID
	if _, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), siblingIntent); err != nil {
		t.Fatal(err)
	}
	siblingMetrics, _ := f.start(t, sibling, "metrics", "sibling-metrics")
	f.acknowledge(t, sibling)
	revoke := RevokeEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantMutation: f.mutation, GrantID: created.Grant.ID}
	if err := f.d.RevokeEnvironmentPublisherGrant(t.Context(), revoke); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.AuthenticatePublisherAccess(t.Context(), access.Token, "", f.now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("revocation left the old access credential usable", err)
	}
	if _, err := f.d.HeartbeatServiceRun(t.Context(), metrics.ServiceID, metrics.RunID, metrics.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revocation left the exact metrics run alive", err)
	}
	for _, run := range []ServiceRunState{api, siblingAPI, siblingMetrics} {
		if _, err := f.d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
			t.Fatal("metrics revocation closed unrelated publication", err)
		}
	}
	if !f.healthy(t, sibling) {
		t.Fatal("revoking one publisher invalidated its independently authorized sibling")
	}
	tombstone, err := f.d.GetEnvironmentPublisherGrant(t.Context(), f.mutation.InspectEnvironmentPublisherGrantRequest)
	if err != nil || tombstone.Grant == nil || tombstone.Grant.ID != created.Grant.ID || tombstone.Grant.RevokedAt == nil {
		t.Fatal("inspect lost the exact revoked mapping", tombstone, err)
	}
	if _, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request); !errors.Is(err, ErrEnvironmentPublisherGrantConflict) {
		t.Fatal("old receipt resurrected a revoked grant", err)
	}
	freshIntent := f.request("approve-metrics-2")
	if _, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), freshIntent); !errors.Is(err, ErrEnvironmentPublisherGrantConflict) {
		t.Fatal("fresh key without tombstone precondition resurrected authority", err)
	}
	freshIntent.ExpectedPreviousGrantID = environmentPublisherGrantExpected(t, created.Grant.ID)
	reauthorized, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), freshIntent)
	if err != nil || !reauthorized.Created || reauthorized.Grant.ID == created.Grant.ID {
		t.Fatal("new deliberate intent did not create a fresh grant", reauthorized, err)
	}
	currentRun, _ := f.start(t, f.publisher, "metrics", "metrics-second-grant")
	f.acknowledge(t, f.publisher)
	if err := f.d.RevokeEnvironmentPublisherGrant(t.Context(), revoke); err != nil {
		t.Fatal("old DELETE replay was not an authorized no-op", err)
	}
	if !f.healthy(t, f.publisher) {
		t.Fatal("old DELETE invalidated the member using a newer grant")
	}
	if _, err := f.d.HeartbeatServiceRun(t.Context(), currentRun.ServiceID, currentRun.RunID, currentRun.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("old DELETE closed the newer grant's run", err)
	}
	if _, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request); !errors.Is(err, ErrEnvironmentPublisherGrantConflict) {
		t.Fatal("old receipt selected a replacement grant", err)
	}
	revoke.GrantID = reauthorized.Grant.ID
	if err := f.d.RevokeEnvironmentPublisherGrant(t.Context(), revoke); err != nil {
		t.Fatal(err)
	}
	beforeRollback := f.environment
	apply := ApplyEnvironmentRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, ActorID: f.r.ActorID, Now: f.now,
		EnvironmentApplication: EnvironmentApplication{EnvironmentID: f.environment.ID, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: f.definition.Revision,
			Targets: EnvironmentTargets{"api": {Address: "api.internal:3000"}, "metrics": {Address: "replacement.internal:9090"}}}}
	updated, err := f.d.ApplyEnvironment(t.Context(), apply)
	if err != nil {
		t.Fatal(err)
	}
	apply.ExpectedRevision, apply.Targets = updated.MutationRevision, beforeRollback.Targets
	rolled, err := f.d.ApplyEnvironment(t.Context(), apply)
	if err != nil || rolled.ConfigurationHash != beforeRollback.ConfigurationHash || rolled.MutationRevision <= updated.MutationRevision || !reflect.DeepEqual(rolled.Services, beforeRollback.Services) {
		t.Fatal("rollback changed retained endpoint identity", rolled, err)
	}
	after, err := f.d.GetEnvironmentPublisherGrant(t.Context(), f.mutation.InspectEnvironmentPublisherGrantRequest)
	if err != nil || after.Grant == nil || after.Grant.ID != reauthorized.Grant.ID || after.Grant.RevokedAt == nil || len(f.assignments(t, f.publisher).Services) != 1 {
		t.Fatal("apply/rollback restored revoked publisher authority", after, err)
	}
	if _, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), freshIntent); !errors.Is(err, ErrEnvironmentStale) {
		t.Fatal("old receipt bypassed the current environment application", err)
	}
}

func TestIntegrationEnvironmentPublisherGrantsReceiptsAndGenericGuards(t *testing.T) {
	f := newEnvironmentPublisherGrantFixture(t)
	sibling := enrollEnvironmentPublisher(t, f.d, f.r, f.environment)
	f.grow(t)
	manager, err := controlstatedb.New(f.d.pool).GetActivePublishRunMembership(t.Context(), controlstatedb.GetActivePublishRunMembershipParams{TeamID: f.r.TeamID, IdentityID: f.r.ActorID})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.d.CreatePublisherGrant(t.Context(), CreatePublisherGrantRequest{PublisherIdentityID: f.publisher.member.PublisherIdentityID,
		Scope: PublisherScope{TeamID: f.r.TeamID, Kind: "service", ServiceID: f.metrics.ServiceID}, EditorID: f.r.ActorID, EditorMembershipID: manager.ID, PolicyRevision: uint64(manager.PolicyRevision), Now: f.now})
	if !errors.Is(err, ErrProjectManaged) {
		t.Fatal("generic create bypassed group ownership", err)
	}
	f.assertNoMetricsAuthority(t)
	request := f.request("approved-intent")
	missing := request
	missing.ExpectedPreviousGrantID = EnvironmentPublisherGrantExpectation{}
	if _, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), missing); !errors.Is(err, ErrEnvironmentInvalid) {
		t.Fatal("missing previous-grant field was treated as explicit null", err)
	}
	created, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	f.acknowledge(t, f.publisher)
	replayed, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request)
	if err != nil || replayed.Created || !reflect.DeepEqual(replayed.EnvironmentPublisherGrantState, created.EnvironmentPublisherGrantState) || !f.healthy(t, f.publisher) {
		t.Fatal("active replay was not a stable no-op", replayed, err)
	}
	noop := f.request("already-active-intent")
	noop.ExpectedPreviousGrantID = environmentPublisherGrantExpected(t, created.Grant.ID)
	active, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), noop)
	if err != nil || active.Created || active.Grant.ID != created.Grant.ID || !f.healthy(t, f.publisher) {
		t.Fatal("new active no-op replaced authority or invalidated health", active, err)
	}
	for _, changed := range []AuthorizeEnvironmentPublisherServiceRequest{
		func() AuthorizeEnvironmentPublisherServiceRequest {
			r := request
			r.PublisherIdentityID = sibling.member.PublisherIdentityID
			return r
		}(),
		func() AuthorizeEnvironmentPublisherServiceRequest {
			r := request
			r.ExpectedPreviousGrantID = noop.ExpectedPreviousGrantID
			return r
		}(),
		func() AuthorizeEnvironmentPublisherServiceRequest {
			r := request
			r.ServiceID = f.publisher.assignments.Services[0].ServiceID
			return r
		}(),
	} {
		if _, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), changed); !errors.Is(err, ErrEnvironmentPublisherGrantConflict) {
			t.Fatal("idempotency key was rebound to changed intent", err)
		}
	}
	if err := f.d.RevokePublisherGrant(t.Context(), f.r.TeamID, f.publisher.member.PublisherIdentityID, created.Grant.ID, f.r.ActorID, f.now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("generic revoke bypassed environment ownership", err)
	}
	for _, statement := range []string{
		`DELETE FROM control.environment_publisher_grant_requests WHERE environment_id=$1`,
		`UPDATE control.environment_publisher_grant_requests SET request_digest=request_digest WHERE environment_id=$1`,
	} {
		_, err := f.d.pool.Exec(t.Context(), statement, f.environment.ID)
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23514" {
			t.Fatal("receipt history was mutable", err)
		}
	}
}

func (f *environmentPublisherGrantFixture) managerSession(t *testing.T, role TeamRole) ControlSession {
	t.Helper()
	name := rand.Text()
	session, err := f.d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", OIDCIdentity{Issuer: "https://identity.fixture.test", Subject: name, DisplayName: name,
		AssertionDigest: sha256.Sum256([]byte(name)), AssertionExpiry: f.now.Add(time.Hour)}, time.Hour, 24*time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	invitation := authorityInvitationRequest(f.r.ActorID, f.r.TeamID, strings.ToLower(name[:12]), f.now)
	invitation.InitialRole = role
	issued, err := f.d.CreateTeamInvitation(t.Context(), invitation, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.AcceptInvitation(t.Context(), session.Identity.Identity.ID, credentials.InvitationToken(issued.Secret), f.now); err != nil {
		t.Fatal(err)
	}
	return session
}

func TestIntegrationEnvironmentPublisherGrantsSelectionAndAuthority(t *testing.T) {
	for _, name := range []string{"missing-authority", "not-manager", "foreign-team", "foreign-project", "foreign-environment", "foreign-service", "nonmember", "revoked-publisher", "retired-key", "stale-revision", "stale-hash"} {
		t.Run(name, func(t *testing.T) {
			f := newEnvironmentPublisherGrantFixture(t)
			f.grow(t)
			request := f.request("denied-intent")
			want := ErrEnvironmentNotFound
			switch name {
			case "missing-authority":
				request.Manager, want = EnvironmentPublisherManager{}, ErrControlAuthentication
			case "not-manager":
				session := f.managerSession(t, TeamRoleMember)
				request.Manager, _ = f.d.AuthenticateEnvironmentPublisherManager(t.Context(), session.AccessToken)
				want = ErrServiceAccess
			case "foreign-team":
				request.TeamID, want = f.session.Identity.PersonalTeamID, ErrEnvironmentNotFound
			case "foreign-project":
				request.ProjectKey = "other-project"
			case "foreign-environment", "foreign-service", "nonmember":
				other, _ := createPublisherTestEnvironment(t, f.d, f.r, "other", f.definition.Revision, f.environment.Targets)
				if name == "foreign-environment" {
					request.EnvironmentID = other.ID
					request.ExpectedRevision, request.ExpectedConfigurationHash = other.MutationRevision, other.ConfigurationHash
				} else if name == "foreign-service" {
					request.ServiceID = other.Services[0].ServiceID
				} else {
					request.PublisherIdentityID = enrollEnvironmentPublisher(t, f.d, f.r, other).member.PublisherIdentityID
				}
			case "revoked-publisher":
				if err := f.d.RevokePublisherIdentity(t.Context(), f.r.TeamID, f.publisher.member.PublisherIdentityID, f.r.ActorID, f.now); err != nil {
					t.Fatal(err)
				}
			case "retired-key":
				if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`, f.publisher.member.KeyID, f.now); err != nil {
					t.Fatal(err)
				}
			case "stale-revision":
				request.ExpectedRevision--
				want = ErrEnvironmentStale
			case "stale-hash":
				request.ExpectedConfigurationHash, want = strings.Repeat("0", 64), ErrEnvironmentStale
			}
			if _, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request); !errors.Is(err, want) {
				t.Fatal("invalid selection or authority was not rejected", err, want)
			}
			if !strings.HasPrefix(name, "stale-") {
				if _, err := f.d.GetEnvironmentPublisherGrant(t.Context(), request.InspectEnvironmentPublisherGrantRequest); !errors.Is(err, want) {
					t.Fatal("inspect disclosed an unavailable tuple", err, want)
				}
			}
			if err := f.d.RevokeEnvironmentPublisherGrant(t.Context(), RevokeEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantMutation: request.EnvironmentPublisherGrantMutation, GrantID: f.publisher.assignments.Services[0].GrantID}); !errors.Is(err, want) {
				t.Fatal("revoke accepted an unavailable selection", err, want)
			}
			f.assertNoMetricsAuthority(t)
		})
	}
}

func TestIntegrationEnvironmentPublisherGrantsRemovedServiceDoesNotReuseIntent(t *testing.T) {
	f := newEnvironmentPublisherGrantFixture(t)
	f.grow(t)
	request := f.request("original-metrics-intent")
	created, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	originalService := f.metrics.ServiceID
	apply := ApplyEnvironmentRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, ActorID: f.r.ActorID, Now: f.now,
		EnvironmentApplication: EnvironmentApplication{EnvironmentID: f.environment.ID, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: f.creation.DefinitionRevision}}
	removed, err := f.d.ApplyEnvironment(t.Context(), apply)
	if err != nil {
		t.Fatal("retained receipt blocked service removal", err)
	}
	apply.ExpectedRevision, apply.DefinitionRevision, apply.Targets = removed.MutationRevision, f.definition.Revision, f.environment.Targets
	readded, err := f.d.ApplyEnvironment(t.Context(), apply)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range readded.Services {
		if service.Service == "metrics" {
			f.metrics = service
		}
	}
	if f.metrics.ServiceID == originalService {
		t.Fatal("removed saved service ID was reused")
	}
	request.ServiceID = f.metrics.ServiceID
	request.ExpectedRevision, request.ExpectedConfigurationHash = readded.MutationRevision, readded.ConfigurationHash
	inspection, err := f.d.GetEnvironmentPublisherGrant(t.Context(), request.InspectEnvironmentPublisherGrantRequest)
	if err != nil || inspection.Grant != nil {
		t.Fatal("readded service inherited a historical grant", inspection, err)
	}
	if _, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request); !errors.Is(err, ErrEnvironmentPublisherGrantConflict) {
		t.Fatal("old intent was rebound to a readded logical service", err)
	}
	old, err := controlstatedb.New(f.d.pool).GetPublisherGrant(t.Context(), controlstatedb.GetPublisherGrantParams{ID: created.Grant.ID, PublisherIdentityID: f.publisher.member.PublisherIdentityID})
	if err != nil || !old.RevokedAt.Valid || old.ServiceID.String != originalService {
		t.Fatal("readdition revived or rebound the retired grant", old, err)
	}
	var receipts int
	if err := f.d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.environment_publisher_grant_requests WHERE environment_id=$1`, f.environment.ID).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatal("removal lost the durable request receipt", receipts, err)
	}
}
