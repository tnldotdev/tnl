package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func retainedEnvironmentProject(t *testing.T, d *Database, now time.Time) environmentPublisherTestProject {
	t.Helper()
	session := newOIDCSession(t, d, now)
	return environmentPublisherTestProject{TeamID: session.Identity.PersonalTeamID, ProjectKey: "example", ActorID: session.Identity.Identity.ID, SourceFingerprint: strings.Repeat("a", 64), AccessToken: session.AccessToken, Now: now}
}

func retainedFixtureDomain(t *testing.T, d *Database, r environmentPublisherTestProject) string {
	t.Helper()
	if _, err := ensureManagedDomain(t.Context(), controlstatedb.New(d.pool), "tunnels.example.test", r.Now); err != nil {
		t.Fatal(err)
	}
	request := ClaimDomainRequest{TeamID: r.TeamID, IdentityID: r.ActorID, Domain: r.ProjectKey + ".environment.example.test", IdempotencyKey: "environment-domain", RequestDigest: sha256.Sum256([]byte(r.ProjectKey))}
	domain, err := d.ClaimTeamDomain(t.Context(), request, r.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.domains SET state='ready',verified_at=$2 WHERE id=$1`, domain.ID, r.Now); err != nil {
		t.Fatal(err)
	}
	return domain.ID
}

func retainedServiceEnvironment(t *testing.T, d *Database, r environmentPublisherTestProject, name string, services map[string]EnvironmentServicePublication) (Environment, CreateEnvironmentRequest) {
	t.Helper()
	definition := ServiceDefinition{Services: map[string]ServiceDefinitionService{}}
	targets := EnvironmentTargets{}
	for name, service := range services {
		definition.Services[name] = ServiceDefinitionService{Protocol: service.Protocol}
		targets[name] = EnvironmentTarget{Address: service.Target, TLS: service.TargetTLS, Discovery: service.TargetDiscovery, HTTP: service.HTTP}
	}
	revision := environmentDefinition(t, d, r, definition.Services)
	return createTestEnvironment(t, d, r, name, revision.Revision, targets)
}

func retainedPublisherEnrollment(t *testing.T, d *Database, r environmentPublisherTestProject, environment Environment, members int, services ...string) EnvironmentPublisherEnrollment {
	t.Helper()
	if len(services) == 0 {
		for _, service := range environment.Services {
			services = append(services, service.Service)
		}
	}
	slices.Sort(services)
	enrollment, err := d.IssueEnvironmentPublisherEnrollment(t.Context(), IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: environmentPublisherSelection(t, d, r, environment), ExpectedRevision: environment.MutationRevision, ExpectedConfigurationHash: environment.ConfigurationHash, Services: services, MaxMembers: members, Lifetime: time.Hour, Now: r.Now})
	if err != nil {
		t.Fatal(err)
	}
	return enrollment
}

func retainedPublisherReplica(t *testing.T, d *Database, enrollment EnvironmentPublisherEnrollment, now time.Time) environmentPublisherReplica {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := d.RedeemEnvironmentPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := d.RedeemEnvironmentPublisherEnrollment(t.Context(), enrollment.Key, public, now); err != nil || replay != member {
		t.Fatal("same enrollment/key changed installed identity", err)
	}
	lease := acquireTestEnvironmentPublisherLease(t, d, member, private, now)
	assignments, err := d.GetEnvironmentPublisherAssignments(t.Context(), lease.AccessToken, now)
	if err != nil || assignments.Publisher != member {
		t.Fatal("lease lost its exact installed publisher", err)
	}
	return environmentPublisherReplica{member: member, private: private, lease: lease, assignments: assignments, enrollment: enrollment}
}

func retainedPublisherGrantMutation(t *testing.T, d *Database, r environmentPublisherTestProject, environment Environment, publisher, service string) EnvironmentPublisherGrantMutation {
	t.Helper()
	selection := environmentPublisherSelection(t, d, r, environment)
	return EnvironmentPublisherGrantMutation{InspectEnvironmentPublisherGrantRequest: InspectEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantSelection: EnvironmentPublisherGrantSelection{TeamID: r.TeamID, ProjectKey: r.ProjectKey, EnvironmentID: environment.ID, PublisherIdentityID: publisher, ServiceID: service}, Manager: selection.Manager}, ExpectedRevision: environment.MutationRevision, ExpectedConfigurationHash: environment.ConfigurationHash}
}

func retainedEnvironmentManager(t *testing.T, d *Database, owner environmentPublisherTestProject, slug string) (environmentPublisherTestProject, Membership) {
	t.Helper()
	var digest [32]byte
	if _, err := rand.Read(digest[:]); err != nil {
		t.Fatal(err)
	}
	session, err := d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", OIDCIdentity{Issuer: "https://identity.fixture.test", Subject: slug, DisplayName: slug, AssertionDigest: digest, AssertionExpiry: owner.Now.Add(time.Hour)}, time.Hour, 24*time.Hour, owner.Now)
	if err != nil {
		t.Fatal(err)
	}
	request := authorityInvitationRequest(owner.ActorID, owner.TeamID, slug, owner.Now)
	request.InitialRole = TeamRoleAdmin
	invitation, err := d.CreateTeamInvitation(t.Context(), request, owner.Now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := d.AcceptInvitation(t.Context(), session.Identity.Identity.ID, credentials.InvitationToken(invitation.Secret), owner.Now)
	if err != nil {
		t.Fatal(err)
	}
	manager := owner
	manager.ActorID, manager.AccessToken = session.Identity.Identity.ID, session.AccessToken
	return manager, member
}

// namespace-owner fixtures omit an environment. they exercise the reservation
// boundary without recreating public rename or service-move APIs.
func retainedNamespaceClaim(t *testing.T, d *Database, r environmentPublisherTestProject, label, domain string, now time.Time) (string, error) {
	t.Helper()
	ctx := t.Context()
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	id, err := opaqueid.New("pgrp_")
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO control.project_publisher_groups(id,team_id,project_key,name) VALUES($1,$2,$3,$4)`, id, r.TeamID, r.ProjectKey, label); err != nil {
		return "", projectConstraintError(err)
	}
	if domain == "" {
		if err = tx.QueryRow(ctx, `SELECT default_domain_id FROM control.teams WHERE id=$1`, r.TeamID).Scan(&domain); err != nil {
			return "", err
		}
	}
	if err = d.ensureEnvironmentNamespace(ctx, tx, serviceResourceMutation{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Now: now}, id, label, environmentNamespace{DomainID: domain}); err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}
