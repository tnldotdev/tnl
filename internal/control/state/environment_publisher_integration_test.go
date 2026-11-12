package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

type environmentPublisherTestProject struct {
	TeamID, ProjectKey, ActorID, SourceFingerprint string
	AccessToken                                    credentials.AccessToken
	Now                                            time.Time
}

type environmentPublisherReplica struct {
	member      EnvironmentPublisher
	private     ed25519.PrivateKey
	lease       EnvironmentPublisherLease
	assignments EnvironmentPublisherAssignments
	enrollment  EnvironmentPublisherEnrollment
}

func environmentPublisherDefinition(t *testing.T, d *Database, r environmentPublisherTestProject, services map[string]ServiceDefinitionService) ServiceDefinitionRevision {
	t.Helper()
	definition, err := d.CreateServiceDefinition(t.Context(), CreateServiceDefinitionRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ActorID: r.ActorID, Definition: ServiceDefinition{Services: services}, Now: r.Now})
	if err != nil {
		t.Fatal(err)
	}
	return definition
}

func createPublisherTestEnvironment(t *testing.T, d *Database, r environmentPublisherTestProject, name string, revision int64, targets EnvironmentTargets) (Environment, CreateEnvironmentRequest) {
	t.Helper()
	request := CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ActorID: r.ActorID, Name: name, DefinitionRevision: revision, Targets: targets, IdempotencyKey: "create/" + name, Now: r.Now}
	environment, err := d.CreateEnvironment(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	return environment, request
}

func environmentPublisherSelection(t *testing.T, d *Database, r environmentPublisherTestProject, e Environment) EnvironmentPublisherSelection {
	t.Helper()
	manager, err := d.AuthenticateEnvironmentPublisherManager(t.Context(), r.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	return EnvironmentPublisherSelection{TeamID: r.TeamID, ProjectKey: r.ProjectKey, EnvironmentID: e.ID, Manager: manager}
}

func enrollEnvironmentPublisher(t *testing.T, d *Database, r environmentPublisherTestProject, e Environment) environmentPublisherReplica {
	t.Helper()
	names := make([]string, 0, len(e.Services))
	for _, service := range e.Services {
		names = append(names, service.Service)
	}
	slices.Sort(names)
	enrollment, err := d.IssueEnvironmentPublisherEnrollment(t.Context(), IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: environmentPublisherSelection(t, d, r, e), ExpectedRevision: e.MutationRevision, ExpectedConfigurationHash: e.ConfigurationHash, Services: names, MaxMembers: 1, Lifetime: time.Hour, Now: r.Now})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := d.RedeemEnvironmentPublisherEnrollment(t.Context(), enrollment.Key, public, r.Now)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := d.RedeemEnvironmentPublisherEnrollment(t.Context(), enrollment.Key, public, r.Now)
	if err != nil || replay != member {
		t.Fatal("same installed key changed identity", err)
	}
	lease := acquireTestEnvironmentPublisherLease(t, d, member, private, r.Now)
	assignments, err := d.GetEnvironmentPublisherAssignments(t.Context(), lease.AccessToken, r.Now)
	if err != nil || assignments.Publisher != member || assignments.Environment != environmentPublicationForTest(e) {
		t.Fatal("enrollment lost its exact environment fence", err)
	}
	return environmentPublisherReplica{member: member, private: private, lease: lease, assignments: assignments, enrollment: enrollment}
}

func environmentPublicationForTest(e Environment) EnvironmentPublication {
	return EnvironmentPublication{EnvironmentID: e.ID, MutationRevision: e.MutationRevision, ConfigurationHash: e.ConfigurationHash}
}

func acquireTestEnvironmentPublisherLease(t *testing.T, d *Database, member EnvironmentPublisher, private ed25519.PrivateKey, now time.Time) EnvironmentPublisherLease {
	t.Helper()
	const audience = "https://control.example/v1/environment-publishers/lease"
	assertion, err := publisherproof.Sign(member.PublisherIdentityID, member.KeyID, member.EnvironmentID, audience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := d.AcquireEnvironmentPublisherLease(t.Context(), member.PublisherIdentityID, member.EnvironmentID, assertion, audience, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AcquireEnvironmentPublisherLease(t.Context(), member.PublisherIdentityID, member.EnvironmentID, assertion, audience, now); !errors.Is(err, ErrEnvironmentPublisher) {
		t.Fatal("environment assertion replay was accepted", err)
	}
	return lease
}

func environmentAssignmentAccess(t *testing.T, d *Database, replica environmentPublisherReplica, assignment EnvironmentPublisherAssignment, now time.Time) PublisherAccess {
	t.Helper()
	assertion, err := publisherproof.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, assignment.GrantID, publisherTestAudience, replica.private, now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := d.ExchangePublisherAssertion(t.Context(), replica.member.PublisherIdentityID, assignment.GrantID, publisherTestAudience, assertion, "", now)
	if err != nil {
		t.Fatal(err)
	}
	return access
}

func TestIntegrationEnvironmentPublisherEnrollmentCapturedServicesAndSameKeyReplay(t *testing.T) {
	f := newEnvironmentPublisherGrantFixture(t)
	original := f.publisher.member
	public := f.publisher.private.Public().(ed25519.PublicKey)
	f.grow(t)
	replay, err := f.d.RedeemEnvironmentPublisherEnrollment(t.Context(), f.publisher.enrollment.Key, public, f.now)
	if err != nil || replay != original {
		t.Fatal("growth changed the installed identity or current key", err)
	}
	f.publisher.lease = acquireTestEnvironmentPublisherLease(t, f.d, original, f.publisher.private, f.now)
	if assignments := f.assignments(t, f.publisher); len(assignments.Services) != 1 || assignments.Services[0].Service != "api" {
		t.Fatal("reenrollment or lease implicitly added metrics")
	}
	f.assertNoMetricsAuthority(t)
	// another explicit bootstrap secret cannot authorize an existing identity.
	request := IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: environmentPublisherSelection(t, f.d, f.r, f.environment), ExpectedRevision: f.environment.MutationRevision, ExpectedConfigurationHash: f.environment.ConfigurationHash, Services: []string{"metrics"}, MaxMembers: 2, Lifetime: time.Hour, Now: f.now}
	metricsEnrollment, err := f.d.IssueEnvironmentPublisherEnrollment(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := f.d.RedeemEnvironmentPublisherEnrollment(t.Context(), metricsEnrollment.Key, public, f.now); err != nil || replay != original {
		t.Fatal("another enrollment replaced the existing identity", err)
	}
	f.assertNoMetricsAuthority(t)
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	other, err := f.d.RedeemEnvironmentPublisherEnrollment(t.Context(), metricsEnrollment.Key, otherPublic, f.now)
	if err != nil || other.PublisherIdentityID == original.PublisherIdentityID || other.KeyID == original.KeyID {
		t.Fatal("new replica did not receive its own identity", err)
	}
	var granted []string
	rows, err := f.d.pool.Query(t.Context(), `SELECT service_id FROM control.publisher_grants WHERE publisher_identity_id=$1 AND revoked_at IS NULL ORDER BY service_id`, other.PublisherIdentityID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		granted = append(granted, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(granted) != 1 || granted[0] != f.metrics.ServiceID {
		t.Fatal("first redemption did not use only captured saved service IDs", err)
	}
	created, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), f.request("explicit-metrics-after-replay"))
	if err != nil || !created.Created || len(f.assignments(t, f.publisher).Services) != 2 {
		t.Fatal("only explicit service authorization may expand the existing publisher", err)
	}
	if err := f.d.RevokeEnvironmentPublisherGrant(t.Context(), RevokeEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantMutation: f.mutation, GrantID: created.Grant.ID}); err != nil {
		t.Fatal(err)
	}
	if replay, err := f.d.RedeemEnvironmentPublisherEnrollment(t.Context(), metricsEnrollment.Key, public, f.now); err != nil || replay != original {
		t.Fatal("revocation changed replay identity", err)
	}
	if len(f.assignments(t, f.publisher).Services) != 1 {
		t.Fatal("reenrollment restored a revoked grant")
	}
	if _, err := f.d.pool.Exec(t.Context(), `DELETE FROM control.publisher_group_service_grants WHERE publisher_identity_id=$1`, original.PublisherIdentityID); err != nil {
		t.Fatal(err)
	}
	if replay, err := f.d.RedeemEnvironmentPublisherEnrollment(t.Context(), f.publisher.enrollment.Key, public, f.now); err != nil || replay != original {
		t.Fatal("missing mapping changed replay identity", err)
	}
	if len(f.assignments(t, f.publisher).Services) != 0 {
		t.Fatal("reenrollment recreated a removed mapping")
	}
}

func TestIntegrationEnvironmentPublisherEnrollmentRequiresExactCurrentSelection(t *testing.T) {
	f := newEnvironmentPublisherGrantFixture(t)
	request := IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: environmentPublisherSelection(t, f.d, f.r, f.environment), ExpectedRevision: f.environment.MutationRevision, ExpectedConfigurationHash: f.environment.ConfigurationHash, Services: []string{"api"}, MaxMembers: 1, Lifetime: time.Hour, Now: f.now}
	for _, change := range []func(*IssueEnvironmentPublisherEnrollmentRequest){
		func(r *IssueEnvironmentPublisherEnrollmentRequest) { r.Services = nil },
		func(r *IssueEnvironmentPublisherEnrollmentRequest) { r.Services = []string{"api", "api"} },
		func(r *IssueEnvironmentPublisherEnrollmentRequest) { r.Services = []string{"metrics"} },
		func(r *IssueEnvironmentPublisherEnrollmentRequest) { r.ExpectedRevision++ },
		func(r *IssueEnvironmentPublisherEnrollmentRequest) {
			r.ExpectedConfigurationHash = strings.Repeat("0", 64)
		},
		func(r *IssueEnvironmentPublisherEnrollmentRequest) { r.Manager = EnvironmentPublisherManager{} },
	} {
		changed := request
		change(&changed)
		if _, err := f.d.IssueEnvironmentPublisherEnrollment(t.Context(), changed); err == nil {
			t.Fatal("invalid, stale or unauthenticated enrollment was accepted")
		}
	}
	var enrollments int
	if err := f.d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_group_enrollments`).Scan(&enrollments); err != nil || enrollments != 1 {
		t.Fatal("denied issuance saved an enrollment", enrollments, err)
	}
}
