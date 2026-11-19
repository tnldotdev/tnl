package state

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestIntegrationExplicitDeploymentCertificateScope(t *testing.T) {
	d, now, _, _ := newConnectorPairPrerequisites(t)
	ctx := t.Context()
	session := newOIDCSession(t, d, now)
	team, actor := session.Identity.Memberships[0].TeamID, session.Identity.Identity.ID
	domain := appliedEndpointDomain(t, d, team, actor, "certificate.example.test", now)
	parent := "publishers." + domain.CanonicalDomain
	serviceConfig := ProjectServiceConfiguration{
		Protocol: "http", Target: "app", Public: new(true),
		Hostname: "production." + parent, RunAliasParent: parent, CertificateScope: parent,
	}
	request := selectedProjectRequest(ApplyProjectConfigurationRequest{
		TeamID: team, ActorID: actor, ProjectKey: "wildcard", ProjectLabel: "wildcard",
		SourceFingerprint: strings.Repeat("a", 64), Now: now,
		Configuration: ProjectConfiguration{
			Settings: &DeploymentSettings{DomainID: domain.ID},
			Services: map[string]ProjectServiceConfiguration{"api": serviceConfig},
		},
	}, "production")
	apex := request
	apexService := serviceConfig
	apexService.Hostname, apexService.RunAliasParent, apexService.CertificateScope =
		"production."+domain.CanonicalDomain, domain.CanonicalDomain, domain.CanonicalDomain
	apex.Configuration.Services = map[string]ProjectServiceConfiguration{"api": apexService}
	if _, err := d.ApplyProjectConfiguration(ctx, apex); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("the entire custom domain was accepted as a wildcard scope", err)
	}
	if _, err := d.ApplyProjectConfiguration(ctx, request); err != nil {
		t.Fatal("reserve dedicated scope", err)
	}
	scope := DeploymentScope{TeamID: team, ActorID: actor, ProjectKey: request.ProjectKey}
	deployment, err := d.GetDeployment(ctx, scope, "production")
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.GetService(ctx, deployment.Services["api"].ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, team, request.ProjectKey, "production", actor, 2, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	for i, key := range []string{"first-wildcard", "second-wildcard"} {
		replica := enrollAppliedDeployment(t, d, request, enrollment, now)
		assignments, err := d.GetDeploymentPublisherAppAssignments(ctx, replica.lease.AccessToken, now)
		if err != nil {
			t.Fatal(err)
		}
		access := deploymentAssignmentAccess(t, d, replica, appliedEndpointAssignment(t, assignments, "api"), now)
		prepared, err := d.PrepareServiceRun(ctx, service.ID, access.PublisherIdentity, key, now, ServiceRunRequest{Metadata: service.ServiceMetadata})
		if err != nil {
			t.Fatal(err)
		}
		if prepared.CertificatePlan.Scope != parent || !slices.Equal(prepared.CertificatePlan.Identifiers, []string{"*." + parent}) ||
			!strings.HasSuffix(prepared.RunHostname, "."+parent) {
			t.Fatal("run did not receive the approved wildcard and an alias beneath it", prepared.CertificatePlan)
		}
		if i == 0 {
			run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
			if err != nil {
				t.Fatal(err)
			}
			installPrivateTestCertificate(t, d, prepared, run, now, 30*24*time.Hour)
		}
	}
	registration, key := managementRegistration(t, scope, now)
	registration.Permissions = map[string][]string{"publish": {"api"}}
	registration.AllDeployments, registration.DeploymentIDs = false, []string{deployment.ID}
	credential, err := d.RegisterDeploymentCredential(ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	access := managementAccess(t, d, credential, key, now)
	prepared, err := d.PrepareServiceRun(ctx, service.ID, access.PublisherIdentity, "narrow-credential", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.CertificatePlan.Scope != serviceConfig.Hostname ||
		!slices.Contains(prepared.CertificatePlan.Identifiers, prepared.RunHostname) ||
		slices.Contains(prepared.CertificatePlan.Identifiers, "*."+parent) {
		t.Fatal("a registered deployment credential gained wildcard issuance", prepared.CertificatePlan)
	}
	other := request
	other.ProjectKey, other.ProjectLabel = "different", "different"
	otherService := serviceConfig
	otherService.Hostname = "other." + parent
	other.Configuration.Services = map[string]ProjectServiceConfiguration{"api": otherService}
	if _, err := d.ApplyProjectConfiguration(ctx, other); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("another deployment claimed addresses under the wildcard", err)
	}
	otherCertificate := otherService
	otherCertificate.CertificateScope = ""
	other.Configuration.Services["api"] = otherCertificate
	if _, err := d.ApplyProjectConfiguration(ctx, other); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("an exact address bypassed the wildcard reservation", err)
	}
	if err := d.DeleteDeployment(ctx, scope, deployment.ID, deployment.Revision, now.Add(time.Second)); err != nil {
		t.Fatal("retire wildcard deployment", err)
	}
	other.Now = now.Add(8 * 24 * time.Hour) // past ordinary quarantine, before certificate expiry
	if _, err := d.ApplyProjectConfiguration(ctx, other); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("a retired scope was released while its wildcard was valid", err)
	}
}
