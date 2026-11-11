package public

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherGroupProvisioningHTTP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	dsn := testutil.NewDisposablePostgresDatabaseURL(t, "provisioning_http")
	if err := controlstate.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, dsn, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC().Truncate(time.Second)
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	team, actor := session.Identity.Memberships[0].TeamID, session.Identity.Identity.ID
	current, err := d.ApplyProjectConfiguration(ctx, controlstate.ApplyProjectConfigurationRequest{TeamID: team, ProjectKey: "customers", ActorID: actor, SourceFingerprint: strings.Repeat("a", 64), Now: now, Configuration: controlstate.ProjectConfiguration{PublisherGroups: map[string]controlstate.ProjectPublisherGroup{"equipment": {Template: true}, "private": {Template: true}}, Services: map[string]controlstate.ProjectServiceConfiguration{"api": {PublisherGroup: "equipment", TargetBinding: "group"}, "secret": {PublisherGroup: "private", Target: "secret.internal:3000"}}}})
	if err != nil {
		t.Fatal(err)
	}
	current, err = d.CreatePublisherGroup(ctx, team, "customers", "hidden", "private", actor, current.Revision, false, now)
	if err != nil {
		t.Fatal(err)
	}
	hidden := current.Groups[0].ID
	hiddenEnrollment, err := d.IssuePublisherGroupEnrollment(ctx, team, "customers", hidden, actor, 1, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	hiddenPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hiddenMember, err := d.RedeemPublisherGroupEnrollment(ctx, hiddenEnrollment.Key, hiddenPublic, now)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := d.RegisterMachineIdentity(ctx, controlstate.RegisterMachineRequest{TeamID: team, ActorID: actor, Name: "installer", ProofKind: "signing_key", KeyID: "first", PublicKey: public}, now)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := d.CreateProvisioningGrant(ctx, controlstate.ProvisioningGrant{TeamID: team, MachineID: machine.ID, ProjectKey: "customers", Templates: []string{"equipment"}, Operations: []controlstate.ProvisioningOperation{controlstate.ProvisioningCreate, controlstate.ProvisioningRead, controlstate.ProvisioningUpdate, controlstate.ProvisioningEnroll, controlstate.ProvisioningRevokeMember, controlstate.ProvisioningRetire}, MaxEnrollmentMembers: 1, MaxEnrollmentSeconds: 600, EnrollmentBudget: 2, ExpiresAt: now.Add(time.Hour)}, actor, now)
	if err != nil {
		t.Fatal(err)
	}
	const server = "https://control.example"
	token := func(op controlstate.ProvisioningOperation) string {
		t.Helper()
		audience := server + "/v1/provisioning-sessions/exchange"
		proof, e := publisherproof.Sign(machine.ID, "first", machineproof.Provisioning(grant.ID, string(op)), audience, key, now)
		if e != nil {
			t.Fatal(e)
		}
		s, e := d.ExchangeProvisioning(ctx, machine.ID, grant.ID, op, controlstate.MachineProof{Assertion: proof}, audience, now)
		if e != nil {
			t.Fatal(e)
		}
		return s.Credential
	}
	h, err := NewHandler(Config{ControlURL: server}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := controlv1.NewClientWithResponses(server, controlv1.WithHTTPClient(&http.Client{Transport: &runtimeHTTPTransport{handler: h, peer: "10.0.0.2:1234", source: "8.8.8.8"}}))
	if err != nil {
		t.Fatal(err)
	}
	bearer := func(value string) controlv1.RequestEditorFn {
		return func(_ context.Context, r *http.Request) error {
			r.Header.Set("Authorization", "Bearer "+value)
			return nil
		}
	}
	create, read := token(controlstate.ProvisioningCreate), token(controlstate.ProvisioningRead)
	bindings := controlv1.PublisherGroupBindings{"api": {Target: new("192.0.2.42:3000")}}
	request := controlv1.CreatePublisherGroupRequest{TeamId: team, From: "equipment", ExpectedRevision: current.Revision, IdempotencyKey: new("customer/42"), Bindings: &bindings}
	created, err := client.CreateBoundPublisherGroupWithResponse(ctx, "customers", request, bearer(create))
	if err != nil || created.JSON200 == nil {
		t.Fatal("machine create", err)
	}
	group := *created.JSON200
	list, err := client.ListPublisherGroupsWithResponse(ctx, "customers", &controlv1.ListPublisherGroupsParams{TeamId: team}, bearer(read))
	if err != nil || list.JSON200 == nil || len(*list.JSON200) != 1 || (*list.JSON200)[0].Id != group.Id {
		t.Fatal("scoped list", err)
	}
	for _, secret := range []string{hidden, "secret.internal", `"configuration"`, read, create} {
		if strings.Contains(string(list.Body), secret) {
			t.Fatal("list disclosed unrelated data or credential")
		}
	}
	get, err := client.GetPublisherGroupWithResponse(ctx, "customers", hidden, &controlv1.GetPublisherGroupParams{TeamId: team}, bearer(read))
	if err != nil || get.StatusCode() != 403 {
		t.Fatal("unauthorized exact read", err)
	}
	get, err = client.GetPublisherGroupWithResponse(ctx, "customers", group.Id, &controlv1.GetPublisherGroupParams{TeamId: team}, bearer(create))
	if err != nil || get.StatusCode() != 403 {
		t.Fatal("create token became read permission", err)
	}
	full, err := client.GetProjectConfigurationWithResponse(ctx, "customers", &controlv1.GetProjectConfigurationParams{TeamId: team}, bearer(read))
	if err != nil || full.StatusCode() != 401 {
		t.Fatal("machine read full configuration", err)
	}
	bad := request
	bad.From = "private"
	denied, err := client.CreateBoundPublisherGroupWithResponse(ctx, "customers", bad, bearer(create))
	if err != nil || denied.StatusCode() != 403 {
		t.Fatal("unapproved template", err)
	}
	e, err := client.CreatePublisherGroupEnrollmentWithResponse(ctx, "customers", group.Id, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: team, MaxMembers: 1, ExpiresIn: 60}, bearer(token(controlstate.ProvisioningEnroll)))
	if err != nil || e.JSON201 == nil {
		t.Fatal("machine enrollment", err)
	}
	memberPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := client.RedeemPublisherGroupEnrollmentWithResponse(ctx, controlv1.RedeemPublisherGroupEnrollmentRequest{EnrollmentKey: e.JSON201.EnrollmentKey, PublicKey: base64.RawURLEncoding.EncodeToString(memberPublic)})
	if err != nil || member.JSON200 == nil {
		t.Fatal("redeem machine-issued enrollment", err)
	}
	members, err := client.ListPublisherGroupMembersWithResponse(ctx, "customers", group.Id, &controlv1.ListPublisherGroupMembersParams{TeamId: team}, bearer(read))
	if err != nil || members.JSON200 == nil || len(*members.JSON200) != 1 || (*members.JSON200)[0].PublisherIdentityId != member.JSON200.PublisherIdentityId {
		t.Fatal("scoped members", err)
	}
	list, err = client.ListPublisherGroupsWithResponse(ctx, "customers", &controlv1.ListPublisherGroupsParams{TeamId: team}, bearer(read))
	if err != nil || list.JSON200 == nil || len(*list.JSON200) != 1 || (*list.JSON200)[0].Id != group.Id || len((*list.JSON200)[0].Members) != 1 || (*list.JSON200)[0].Members[0].PublisherIdentityId != member.JSON200.PublisherIdentityId {
		t.Fatal("list did not isolate two populated groups", err)
	}
	get, err = client.GetPublisherGroupWithResponse(ctx, "customers", group.Id, &controlv1.GetPublisherGroupParams{TeamId: team}, bearer(read))
	if err != nil || get.JSON200 == nil || get.JSON200.Id != group.Id || len(get.JSON200.Members) != 1 || get.JSON200.Members[0].PublisherIdentityId != member.JSON200.PublisherIdentityId {
		t.Fatal("exact get did not isolate populated visible group", err)
	}
	for _, body := range [][]byte{list.Body, get.Body, members.Body} {
		for _, secret := range []string{hidden, hiddenMember.PublisherIdentityID, "secret.internal", hiddenEnrollment.Key, e.JSON201.EnrollmentKey} {
			if strings.Contains(string(body), secret) {
				t.Fatal("scoped response disclosed hidden group/member or enrollment secret")
			}
		}
	}
	hiddenMembers, err := client.ListPublisherGroupMembersWithResponse(ctx, "customers", hidden, &controlv1.ListPublisherGroupMembersParams{TeamId: team}, bearer(read))
	if err != nil || hiddenMembers.StatusCode() != 403 || strings.Contains(string(hiddenMembers.Body), hiddenMember.PublisherIdentityID) {
		t.Fatal("hidden populated member list disclosed data", err)
	}
	updated, err := client.UpdatePublisherGroupBindingsWithResponse(ctx, "customers", group.Id, controlv1.UpdatePublisherGroupBindingsRequest{TeamId: team, ExpectedRevision: group.Revision, Bindings: controlv1.PublisherGroupBindings{"api": {Target: new("192.0.2.42:3001")}}}, bearer(token(controlstate.ProvisioningUpdate)))
	if err != nil || updated.JSON200 == nil {
		t.Fatal("machine binding update", err)
	}
	revoked, err := client.RevokePublisherGroupMemberWithResponse(ctx, "customers", group.Id, member.JSON200.PublisherIdentityId, &controlv1.RevokePublisherGroupMemberParams{TeamId: team}, bearer(token(controlstate.ProvisioningRevokeMember)))
	if err != nil || revoked.StatusCode() != 204 {
		t.Fatal("machine member revocation", err)
	}
	retired, err := client.RemovePublisherGroupWithResponse(ctx, "customers", group.Id, &controlv1.RemovePublisherGroupParams{TeamId: team, ExpectedRevision: updated.JSON200.Revision}, bearer(token(controlstate.ProvisioningRetire)))
	if err != nil || retired.StatusCode() != 204 {
		t.Fatal("machine retirement", err)
	}
	list, err = client.ListPublisherGroupsWithResponse(ctx, "customers", &controlv1.ListPublisherGroupsParams{TeamId: team}, bearer(read))
	if err != nil || list.JSON200 == nil || len(*list.JSON200) != 0 {
		t.Fatal("list included retired visible group or live hidden group", err)
	}
	get, err = client.GetPublisherGroupWithResponse(ctx, "customers", group.Id, &controlv1.GetPublisherGroupParams{TeamId: team}, bearer(read))
	if err != nil || get.StatusCode() != 403 {
		t.Fatal("retired group remained machine-readable", err)
	}
	members, err = client.ListPublisherGroupMembersWithResponse(ctx, "customers", group.Id, &controlv1.ListPublisherGroupMembersParams{TeamId: team}, bearer(read))
	if err != nil || members.StatusCode() != 403 {
		t.Fatal("retired members remained machine-readable", err)
	}
	hiddenStatus, err := d.GetManagedPublisherGroup(ctx, team, "customers", hidden, actor)
	if err != nil || hiddenStatus.Retired || len(hiddenStatus.Members) != 1 || hiddenStatus.Members[0].PublisherIdentityID != hiddenMember.PublisherIdentityID {
		t.Fatal("isolation fixture lost the hidden group's live member", err)
	}
	if err = d.RevokeProvisioningGrant(ctx, team, grant.ID, actor, now); err != nil {
		t.Fatal(err)
	}
	denied, err = client.CreateBoundPublisherGroupWithResponse(ctx, "customers", request, bearer(create))
	if err != nil || denied.StatusCode() != 403 {
		t.Fatal("revoked replay returned a resource", err)
	}
}
