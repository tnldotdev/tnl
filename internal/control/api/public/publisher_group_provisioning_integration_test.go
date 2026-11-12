package public

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// retain the historical selector while exercising the canonical environment API.
func TestIntegrationPublisherGroupProvisioningHTTP(t *testing.T) {
	f := newEnvironmentProvisioningHTTPFixture(t)
	ctx := t.Context()
	hidden := f.create("hidden", f.definition.Revision, controlv1.EnvironmentTargets{"api": {Address: new("secret.internal:3000")}})
	manager, err := f.database.AuthenticateEnvironmentPublisherManager(ctx, f.session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	hiddenEnrollment, err := f.database.IssueEnvironmentPublisherEnrollment(ctx, controlstate.IssueEnvironmentPublisherEnrollmentRequest{
		EnvironmentPublisherSelection: controlstate.EnvironmentPublisherSelection{TeamID: f.team, ProjectKey: f.project, EnvironmentID: hidden.Id, Manager: manager},
		ExpectedRevision:              hidden.MutationRevision, ExpectedConfigurationHash: hidden.ConfigurationHash, Services: []string{"api"}, MaxMembers: 1, Lifetime: time.Minute, Now: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	hiddenPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hiddenMember, err := f.database.RedeemEnvironmentPublisherEnrollment(ctx, hiddenEnrollment.Key, hiddenPublic, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	create, read := f.token(controlstate.ProvisioningCreate), f.token(controlstate.ProvisioningRead)
	request := f.creation("one")
	created, err := f.client.CreateEnvironmentWithResponse(ctx, f.project, request, provisioningBearer(create))
	if err != nil || created.JSON200 == nil {
		t.Fatal("machine create", created, err)
	}
	environment := *created.JSON200
	list, err := f.client.ListEnvironmentsWithResponse(ctx, f.project, &controlv1.ListEnvironmentsParams{TeamId: f.team}, provisioningBearer(read))
	if err != nil || list.JSON200 == nil || len(*list.JSON200) != 1 || (*list.JSON200)[0].Id != environment.Id {
		t.Fatal("scoped list", list, err)
	}
	for _, secret := range []string{hidden.Id, "secret.internal", `"configuration"`, read, create} {
		if strings.Contains(string(list.Body), secret) {
			t.Fatal("list disclosed unrelated data or credential")
		}
	}
	get, err := f.client.GetEnvironmentWithResponse(ctx, f.project, hidden.Id, &controlv1.GetEnvironmentParams{TeamId: f.team}, provisioningBearer(read))
	if err != nil || get.StatusCode() != http.StatusForbidden {
		t.Fatal("unauthorized exact read", get, err)
	}
	get, err = f.client.GetEnvironmentWithResponse(ctx, f.project, environment.Id, &controlv1.GetEnvironmentParams{TeamId: f.team}, provisioningBearer(create))
	if err != nil || get.StatusCode() != http.StatusForbidden {
		t.Fatal("create token became read permission", get, err)
	}
	full, err := f.client.CreateServiceDefinitionWithResponse(ctx, f.project, controlv1.CreateServiceDefinitionRequest{TeamId: f.team, SourceFingerprint: f.source, Definition: f.definition.Definition}, provisioningBearer(read))
	if err != nil || full.StatusCode() != http.StatusUnauthorized {
		t.Fatal("machine became definition manager", full, err)
	}
	bad := request
	bad.Name, bad.IdempotencyKey = "outside-collection", "customer/outside-collection"
	bad.CollectionId, bad.ExpectedCollectionRevision, bad.DefinitionRevision = nil, nil, new(f.definition.Revision)
	denied, err := f.client.CreateEnvironmentWithResponse(ctx, f.project, bad, provisioningBearer(create))
	if err != nil || denied.StatusCode() != http.StatusForbidden {
		t.Fatal("unapproved collection", denied, err)
	}
	e, err := f.client.CreateEnvironmentPublisherEnrollmentWithResponse(ctx, f.project, environment.Id, &controlv1.CreateEnvironmentPublisherEnrollmentParams{IdempotencyKey: new("first")}, controlv1.CreateEnvironmentPublisherEnrollmentRequest{TeamId: f.team, ExpectedRevision: environment.MutationRevision, ConfigurationHash: environment.ConfigurationHash, Services: []string{"api"}, MaxMembers: 1, ExpiresIn: 60}, provisioningBearer(f.token(controlstate.ProvisioningEnroll)))
	if err != nil || e.JSON201 == nil {
		t.Fatal("machine enrollment", e, err)
	}
	memberPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.client.RedeemEnvironmentPublisherEnrollmentWithResponse(ctx, controlv1.RedeemEnvironmentPublisherEnrollmentRequest{EnrollmentKey: e.JSON201.EnrollmentKey, PublicKey: base64.RawURLEncoding.EncodeToString(memberPublic)})
	if err != nil || member.JSON200 == nil {
		t.Fatal("redeem machine-issued enrollment", member, err)
	}
	members, err := f.client.ListEnvironmentPublishersWithResponse(ctx, f.project, environment.Id, &controlv1.ListEnvironmentPublishersParams{TeamId: f.team}, provisioningBearer(read))
	if err != nil || members.JSON200 == nil || len(*members.JSON200) != 1 || (*members.JSON200)[0].PublisherIdentityId != member.JSON200.PublisherIdentityId {
		t.Fatal("scoped publishers", members, err)
	}
	list, err = f.client.ListEnvironmentsWithResponse(ctx, f.project, &controlv1.ListEnvironmentsParams{TeamId: f.team}, provisioningBearer(read))
	if err != nil || list.JSON200 == nil || len(*list.JSON200) != 1 || (*list.JSON200)[0].Id != environment.Id {
		t.Fatal("list did not isolate populated environments", list, err)
	}
	get, err = f.client.GetEnvironmentWithResponse(ctx, f.project, environment.Id, &controlv1.GetEnvironmentParams{TeamId: f.team}, provisioningBearer(read))
	if err != nil || get.JSON200 == nil || get.JSON200.Id != environment.Id {
		t.Fatal("exact get did not isolate populated environment", get, err)
	}
	for _, body := range [][]byte{list.Body, get.Body, members.Body} {
		for _, secret := range []string{hidden.Id, hiddenMember.PublisherIdentityID, "secret.internal", hiddenEnrollment.Key, e.JSON201.EnrollmentKey} {
			if strings.Contains(string(body), secret) {
				t.Fatal("scoped response disclosed hidden environment/publisher or enrollment secret")
			}
		}
	}
	hiddenMembers, err := f.client.ListEnvironmentPublishersWithResponse(ctx, f.project, hidden.Id, &controlv1.ListEnvironmentPublishersParams{TeamId: f.team}, provisioningBearer(read))
	if err != nil || hiddenMembers.StatusCode() != http.StatusForbidden || strings.Contains(string(hiddenMembers.Body), hiddenMember.PublisherIdentityID) {
		t.Fatal("hidden publisher list disclosed data", hiddenMembers, err)
	}
	targets := controlv1.EnvironmentTargets{"api": {Address: new("192.0.2.42:3001")}}
	updated, err := f.client.ApplyEnvironmentWithResponse(ctx, f.project, environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: environment.MutationRevision, DefinitionRevision: f.definition.Revision, Targets: &targets}, provisioningBearer(f.token(controlstate.ProvisioningUpdate)))
	if err != nil || updated.JSON200 == nil {
		t.Fatal("machine target update", updated, err)
	}
	revoked, err := f.client.RevokeEnvironmentPublisherWithResponse(ctx, f.project, environment.Id, member.JSON200.PublisherIdentityId, &controlv1.RevokeEnvironmentPublisherParams{TeamId: f.team}, provisioningBearer(f.token(controlstate.ProvisioningRevokeMember)))
	if err != nil || revoked.StatusCode() != http.StatusNoContent {
		t.Fatal("machine publisher revocation", revoked, err)
	}
	retired, err := f.client.RetireEnvironmentWithResponse(ctx, f.project, environment.Id, &controlv1.RetireEnvironmentParams{TeamId: f.team, ExpectedRevision: updated.JSON200.MutationRevision}, provisioningBearer(f.token(controlstate.ProvisioningRetire)))
	if err != nil || retired.StatusCode() != http.StatusNoContent {
		t.Fatal("machine retirement", retired, err)
	}
	list, err = f.client.ListEnvironmentsWithResponse(ctx, f.project, &controlv1.ListEnvironmentsParams{TeamId: f.team}, provisioningBearer(read))
	if err != nil || list.JSON200 == nil || len(*list.JSON200) != 0 {
		t.Fatal("list included retired visible or live hidden environment", list, err)
	}
	get, err = f.client.GetEnvironmentWithResponse(ctx, f.project, environment.Id, &controlv1.GetEnvironmentParams{TeamId: f.team}, provisioningBearer(read))
	if err != nil || get.StatusCode() != http.StatusForbidden {
		t.Fatal("retired environment remained machine-readable", get, err)
	}
	members, err = f.client.ListEnvironmentPublishersWithResponse(ctx, f.project, environment.Id, &controlv1.ListEnvironmentPublishersParams{TeamId: f.team}, provisioningBearer(read))
	if err != nil || members.StatusCode() < 400 {
		t.Fatal("retired publishers remained machine-readable", members, err)
	}
	hiddenStatus, err := f.database.GetEnvironment(ctx, f.team, f.project, hidden.Id, f.session.Identity.Identity.ID)
	if err != nil || hiddenStatus.Retired || len(hiddenStatus.Members) != 1 || hiddenStatus.Members[0].PublisherIdentityID != hiddenMember.PublisherIdentityID {
		t.Fatal("isolation fixture lost hidden environment's live publisher", err)
	}
	if err = f.database.RevokeProvisioningGrant(ctx, f.team, f.grant.ID, f.session.Identity.Identity.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	denied, err = f.client.CreateEnvironmentWithResponse(ctx, f.project, request, provisioningBearer(create))
	if err != nil || denied.StatusCode() < 400 {
		t.Fatal("revoked replay returned resource", denied, err)
	}
}
