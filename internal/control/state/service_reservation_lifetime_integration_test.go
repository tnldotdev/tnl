package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationStandaloneSharedSameSourceHandoffKeepsLifetimeReceiptsAndGrants(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	creator := addAuthorityMember(t, d, now, owner, team.ID, "handoff-creator", TeamRoleAdmin)
	domain := deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: owner}, now)
	placement := ServicePlacement{Reserve: true, DomainID: domain.ID, Hostname: "handoff.custom.example.test"}
	declaration := &ProjectServiceConfiguration{Target: "app", Protocol: "http"}
	first, err := d.CreateServiceAt(t.Context(), team.ID, creator.IdentityID, "handoff", "original", placement, now, ServiceMetadata{}, declaration)
	if err != nil {
		t.Fatal(err)
	}
	var source, ownerTeam string
	if err := d.pool.QueryRow(t.Context(), `SELECT local_source_key,owner_team_id FROM control.service_namespace_claims WHERE namespace=$1`, placement.Hostname).Scan(&source, &ownerTeam); err != nil || ownerTeam != team.ID {
		t.Fatal("shared claim did not capture the team source", err)
	}
	enrollment, err := d.IssuePublisherEnrollment(t.Context(), standaloneEnrollmentRequest(t, d, first, creator.IdentityID, "original", now))
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	access := publisherAccess(t, d, publisher, private, "", now)
	if recovered, err := d.CreateServiceAt(t.Context(), team.ID, owner, "handoff", "owner-recovery", placement, now, ServiceMetadata{}, declaration); err != nil || recovered.ID != first.ID || !recovered.Recovered {
		t.Fatal("current administrator could not recover the shared team source", recovered, err)
	}
	if err := d.RemoveMembership(t.Context(), owner, team.ID, creator.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteService(t.Context(), first.ID, owner, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	second, err := d.CreateServiceAt(t.Context(), team.ID, owner, "handoff", "replacement", placement, now.Add(3*time.Second), ServiceMetadata{}, declaration)
	if err != nil || second.ID == first.ID || second.Recovered || second.Endpoint.Hostname != first.Endpoint.Hostname {
		t.Fatal("same team source could not hand off a deleted lifetime", second, err)
	}
	var sameOwner bool
	if err := d.pool.QueryRow(t.Context(), `SELECT claim.local_source_key=$2 AND claim.owner_team_id=$3 AND claim.membership_id IS NULL
	    AND endpoint.service_id=$4 AND endpoint.local_source_key=$2 AND endpoint.retired_at IS NULL
	    FROM control.service_namespace_claims claim JOIN control.service_endpoints endpoint ON endpoint.hostname=claim.namespace WHERE claim.namespace=$1`,
		placement.Hostname, source, team.ID, second.ID).Scan(&sameOwner); err != nil || !sameOwner {
		t.Fatal("handoff replaced the durable owner or source", err)
	}
	if _, err := d.CreateServiceAt(t.Context(), team.ID, creator.IdentityID, "handoff", "original", placement, now.Add(3*time.Second), ServiceMetadata{}, declaration); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("removed creator recovered another lifetime", err)
	}
	if _, err := d.CreateServiceAt(t.Context(), team.ID, owner, "handoff", "owner-recovery", placement, now.Add(3*time.Second), ServiceMetadata{}, declaration); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("a current administrator's old receipt recovered the replacement lifetime", err)
	}
	var bound string
	if err := d.pool.QueryRow(t.Context(), `SELECT service_id FROM control.service_creation_requests WHERE created_by_identity_id=$1 AND idempotency_key='original'`, creator.IdentityID).Scan(&bound); err != nil || bound != first.ID {
		t.Fatal("old operation receipt moved to the replacement", bound, err)
	}
	if _, err := d.GetServiceForPublisher(t.Context(), second.ID, publisher, now.Add(3*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("old exact grant adopted the replacement service", err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now.Add(3*time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("retained old access selected the new lifetime", err)
	}
	recovered, err := d.CreateServiceAt(t.Context(), team.ID, owner, "handoff", "replacement", placement, now.Add(3*time.Second), ServiceMetadata{}, declaration)
	if err != nil || !recovered.Recovered || recovered.ID != second.ID {
		t.Fatal("new receipt did not recover only its own lifetime", recovered, err)
	}
}

func TestIntegrationExactReservationRejectsActualDeploymentWithoutChangingItsOwner(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_reservation")
	request := appliedProjectRequest(t, d, now)
	domain := deploymentCustomDomain(t, d, request, now)
	request.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{DomainID: domain.ID}, Services: map[string]ProjectServiceConfiguration{
		"web": {Target: "app", Public: new(true), DomainID: domain.ID, Hostname: "reservation.custom.example.test"},
	}}
	request = selectedProjectRequest(request, "production")
	if _, err := d.ApplyProjectConfiguration(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	deployment, err := d.GetDeployment(t.Context(), DeploymentScope{TeamID: request.TeamID, ProjectKey: request.ProjectKey, ActorID: request.ActorID}, "production")
	if err != nil {
		t.Fatal(err)
	}
	serviceID := deployment.Services["web"].ID
	saved, err := d.GetService(t.Context(), serviceID, request.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	before, err := q.GetServiceConfiguration(t.Context(), serviceID)
	if err != nil || !before.DeploymentOwned {
		t.Fatal("fixture did not apply a real deployment service", before, err)
	}
	placement := ServicePlacement{Reserve: true, DomainID: saved.DomainID, Hostname: saved.Endpoint.Hostname}
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlstatedb.New(tx).LockLocalTeamForMutation(t.Context(), request.TeamID); err != nil {
		rollbackTestTransaction(t, tx)
		t.Fatal(err)
	}
	if _, err := d.serviceReservationOwner(t.Context(), tx, request.TeamID, request.ActorID, saved.Name, placement,
		&ProjectServiceConfiguration{Target: "app"}, now); err != nil {
		rollbackTestTransaction(t, tx)
		t.Fatal("fixture failed namespace selection before the association guard", err)
	}
	rollbackTestTransaction(t, tx)
	result, err := d.CreateServiceAt(t.Context(), request.TeamID, request.ActorID, saved.Name, "deployment-adoption", placement, now,
		ServiceMetadata{}, &ProjectServiceConfiguration{Target: "app"})
	if !errors.Is(err, ErrServiceAccess) && !errors.Is(err, ErrServiceConflict) || result.ID != "" {
		t.Fatal("reservation adopted the actual deployment association", result, err)
	}
	after, err := q.GetServiceConfiguration(t.Context(), serviceID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("denied reservation changed deployment intent or provenance", err)
	}
	var receipts int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_creation_requests WHERE created_by_identity_id=$1 AND idempotency_key='deployment-adoption'`, request.ActorID).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("denied deployment adoption wrote a receipt", receipts, err)
	}
}
