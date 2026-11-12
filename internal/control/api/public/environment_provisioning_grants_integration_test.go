package public

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationEnvironmentProvisioningHTTPPublisherGrantIntent(t *testing.T) {
	f := newEnvironmentProvisioningHTTPFixture(t)
	environment := f.createMachine("one")
	manager, err := f.database.AuthenticateEnvironmentPublisherManager(t.Context(), f.session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := f.database.IssueEnvironmentPublisherEnrollment(t.Context(), controlstate.IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: controlstate.EnvironmentPublisherSelection{TeamID: f.team, ProjectKey: f.project, EnvironmentID: environment.Id, Manager: manager}, ExpectedRevision: environment.MutationRevision, ExpectedConfigurationHash: environment.ConfigurationHash, Services: []string{"api"}, MaxMembers: 1, Lifetime: time.Minute, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.client.RedeemEnvironmentPublisherEnrollmentWithResponse(t.Context(), controlv1.RedeemEnvironmentPublisherEnrollmentRequest{EnrollmentKey: enrollment.Key, PublicKey: base64.RawURLEncoding.EncodeToString(public)})
	if err != nil || member.JSON200 == nil {
		t.Fatal(member, err)
	}
	service := environment.Services[0].ServiceId
	read := provisioningBearer(f.token(controlstate.ProvisioningRead))
	before, err := f.client.GetEnvironmentPublisherGrantWithResponse(t.Context(), f.project, environment.Id, member.JSON200.PublisherIdentityId, service, &controlv1.GetEnvironmentPublisherGrantParams{TeamId: f.team}, read)
	if err != nil || before.JSON200 == nil || before.JSON200.Grant == nil {
		t.Fatal(before, err)
	}
	revoke, err := f.client.RevokeEnvironmentPublisherGrantWithResponse(t.Context(), f.project, environment.Id, member.JSON200.PublisherIdentityId, service, before.JSON200.Grant.Id, &controlv1.RevokeEnvironmentPublisherGrantParams{TeamId: f.team, ExpectedRevision: environment.MutationRevision, ExpectedConfigurationHash: environment.ConfigurationHash}, provisioningBearer(f.token(controlstate.ProvisioningRevokeMember)))
	if err != nil || revoke.StatusCode() != http.StatusNoContent {
		t.Fatal(revoke, err)
	}
	updated, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: environment.MutationRevision, DefinitionRevision: f.definition.Revision}, provisioningBearer(f.token(controlstate.ProvisioningUpdate)))
	if err != nil || updated.JSON200 == nil {
		t.Fatal(updated, err)
	}
	environment = *updated.JSON200
	afterApply, err := f.client.GetEnvironmentPublisherGrantWithResponse(t.Context(), f.project, environment.Id, member.JSON200.PublisherIdentityId, service, &controlv1.GetEnvironmentPublisherGrantParams{TeamId: f.team}, read)
	if err != nil || afterApply.JSON200 == nil || afterApply.JSON200.Grant == nil || afterApply.JSON200.Grant.RevokedAt == nil || afterApply.JSON200.Grant.Id != before.JSON200.Grant.Id || f.used() != 0 {
		t.Fatal("apply repaired a revoked grant", afterApply, err)
	}
	intent := controlv1.AuthorizeEnvironmentPublisherServiceRequest{TeamId: f.team, ExpectedRevision: environment.MutationRevision, ExpectedConfigurationHash: environment.ConfigurationHash, ExpectedPreviousGrantId: new(before.JSON200.Grant.Id), IdempotencyKey: "restore-api-explicitly"}
	enroll := provisioningBearer(f.token(controlstate.ProvisioningEnroll))
	created, err := f.client.AuthorizeEnvironmentPublisherServiceWithResponse(t.Context(), f.project, environment.Id, member.JSON200.PublisherIdentityId, service, intent, enroll)
	if err != nil || created.JSON201 == nil || created.JSON201.Grant == nil || f.used() != 1 {
		t.Fatal("explicit exact grant authorization failed", created, err)
	}
	grant := created.JSON201.Grant
	if grant.CreatedByIdentityId != nil || grant.CreatedByMachineId == nil || *grant.CreatedByMachineId != f.machine.ID || grant.ProvisioningGrantId == nil || *grant.ProvisioningGrantId != f.grant.ID {
		t.Fatal("explicit authorization impersonated manager", grant)
	}
	replayed, err := f.client.AuthorizeEnvironmentPublisherServiceWithResponse(t.Context(), f.project, environment.Id, member.JSON200.PublisherIdentityId, service, intent, enroll)
	if err != nil || replayed.JSON200 == nil || replayed.JSON200.Grant == nil || replayed.JSON200.Grant.Id != grant.Id || f.used() != 1 {
		t.Fatal("grant-intent replay double-spent or widened authority", replayed, err)
	}
	// a manager may grow the definition, but the machine's fixed allowlist must
	// reject both whole-environment changes and grants for the added service.
	definition, err := f.client.CreateServiceDefinitionWithResponse(t.Context(), f.project, controlv1.CreateServiceDefinitionRequest{TeamId: f.team, SourceFingerprint: f.source, Definition: controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{"api": {Protocol: "http"}, "metrics": {Protocol: "http"}}}})
	if err != nil || definition.JSON200 == nil {
		t.Fatal(definition, err)
	}
	targets := controlv1.EnvironmentTargets{"api": {Address: new("api.customer.internal:3000")}, "metrics": {Address: new("metrics.internal:9090")}}
	denied, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: environment.MutationRevision, DefinitionRevision: definition.JSON200.Revision, Targets: &targets}, provisioningBearer(f.token(controlstate.ProvisioningUpdate)))
	if err != nil || denied.StatusCode() != http.StatusForbidden {
		t.Fatal("machine applied services outside allowlist", denied, err)
	}
	grown, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: environment.MutationRevision, DefinitionRevision: definition.JSON200.Revision, Targets: &targets})
	if err != nil || grown.JSON200 == nil {
		t.Fatal(grown, err)
	}
	var metrics string
	for _, s := range grown.JSON200.Services {
		if s.Service == "metrics" {
			metrics = s.ServiceId
		}
	}
	intent.ExpectedRevision, intent.ExpectedConfigurationHash, intent.ExpectedPreviousGrantId, intent.IdempotencyKey = grown.JSON200.MutationRevision, grown.JSON200.ConfigurationHash, nil, "unapproved-metrics"
	unapproved, err := f.client.AuthorizeEnvironmentPublisherServiceWithResponse(t.Context(), f.project, environment.Id, member.JSON200.PublisherIdentityId, metrics, intent, enroll)
	if err != nil || unapproved.StatusCode() != http.StatusForbidden || f.used() != 1 {
		t.Fatal("new definition widened grant authority or budget", unapproved, err)
	}
}
