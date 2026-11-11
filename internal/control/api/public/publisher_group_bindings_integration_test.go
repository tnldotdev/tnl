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
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherGroupBindingsHTTP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	dsn := testutil.NewDisposablePostgresDatabaseURL(t, "bindings_http")
	if err := controlstate.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, dsn, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const server = "https://control.example"
	handler, err := NewHandler(Config{ControlURL: server}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &runtimeHTTPTransport{handler: handler, peer: "10.0.0.2:1234", source: "8.8.8.8"}
	client, err := controlv1.NewClientWithResponses(server, controlv1.WithHTTPClient(&http.Client{Transport: transport}), controlv1.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+string(session.AccessToken))
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity.Memberships[0].TeamID
	group := "customer-services"
	configuration := controlv1.ProjectConfiguration{PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {Template: new(true)}}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {PublisherGroup: &group, TargetBinding: new(controlv1.ProjectServiceConfigurationTargetBinding("group"))}}, Webhooks: map[string]controlv1.ProjectWebhook{}}
	applied, err := client.ApplyProjectConfigurationWithResponse(ctx, "customers", controlv1.ApplyProjectConfigurationRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Configuration: configuration})
	if err != nil || applied.JSON200 == nil {
		t.Fatal("apply template", applied, err)
	}
	bindings := controlv1.PublisherGroupBindings{"api": {Target: new("http://192.0.2.42:3000/")}}
	request := controlv1.CreatePublisherGroupRequest{TeamId: team, From: group, ExpectedRevision: applied.JSON200.Revision, IdempotencyKey: new("arbitrary/customer:42"), Bindings: &bindings}
	created, err := client.CreateBoundPublisherGroupWithResponse(ctx, "customers", request)
	if err != nil || created.JSON200 == nil {
		t.Fatal("create bound group", created, err)
	}
	resource := *created.JSON200
	if resource.Id == "" || resource.Name == "" || resource.From != group || resource.Revision <= request.ExpectedRevision || resource.Retired || len(resource.Services) != 1 {
		t.Fatal("missing management context", resource)
	}
	// a reordered, normalized JSON request with an older precondition is the
	// same operation, not a second allocation or a stale-revision rejection.
	replayed, err := client.CreateBoundPublisherGroupWithBodyWithResponse(ctx, "customers", "application/json", strings.NewReader(`{"bindings":{"api":{"target":"192.0.2.42:3000"}},"idempotency_key":"arbitrary/customer:42","expected_revision":1,"from":"customer-services","team_id":"`+team+`"}`))
	if err != nil || replayed.JSON200 == nil || replayed.JSON200.Id != resource.Id || replayed.JSON200.Revision != resource.Revision {
		t.Fatal("normalized replay", replayed, err)
	}
	changed := request
	changed.Name = new("different")
	conflict, err := client.CreateBoundPublisherGroupWithResponse(ctx, "customers", changed)
	if err != nil || conflict.StatusCode() != http.StatusConflict {
		t.Fatal("changed key accepted", conflict, err)
	}
	get, err := client.GetPublisherGroupWithResponse(ctx, "customers", resource.Id, &controlv1.GetPublisherGroupParams{TeamId: team})
	if err != nil || get.JSON200 == nil || get.JSON200.Id != resource.Id {
		t.Fatal("get by ID", get, err)
	}
	list, err := client.ListPublisherGroupsWithResponse(ctx, "customers", &controlv1.ListPublisherGroupsParams{TeamId: team})
	if err != nil || list.JSON200 == nil || len(*list.JSON200) != 1 {
		t.Fatal("list concrete groups", list, err)
	}
	enrollment, err := client.CreatePublisherGroupEnrollmentWithResponse(ctx, "customers", resource.Id, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: team, MaxMembers: 1, ExpiresIn: 600})
	if err != nil || enrollment.JSON201 == nil {
		t.Fatal("enroll by ID", enrollment, err)
	}
	e := enrollment.JSON201
	if e.Publisher.Server != server || e.Publisher.Project != "customers" || e.Publisher.Group != resource.Name || e.EnrollmentKey == "" {
		t.Fatal("incomplete installation context")
	}
	if strings.Contains(string(get.Body), e.EnrollmentKey) || strings.Contains(string(list.Body), e.EnrollmentKey) {
		t.Fatal("resource leaked enrollment secret")
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := client.RedeemPublisherGroupEnrollmentWithResponse(ctx, controlv1.RedeemPublisherGroupEnrollmentRequest{EnrollmentKey: e.EnrollmentKey, PublicKey: base64.RawURLEncoding.EncodeToString(public)})
	if err != nil || member.JSON200 == nil {
		t.Fatal("redeem", member, err)
	}
	members, err := client.ListPublisherGroupMembersWithResponse(ctx, "customers", resource.Id, &controlv1.ListPublisherGroupMembersParams{TeamId: team})
	if err != nil || members.JSON200 == nil || len(*members.JSON200) != 1 || (*members.JSON200)[0].PublisherIdentityId != member.JSON200.PublisherIdentityId {
		t.Fatal("member observations", members, err)
	}
	updated, err := client.UpdatePublisherGroupBindingsWithResponse(ctx, "customers", resource.Id, controlv1.UpdatePublisherGroupBindingsRequest{TeamId: team, ExpectedRevision: resource.Revision, Bindings: controlv1.PublisherGroupBindings{"api": {Target: new("192.0.2.42:3001")}}})
	if err != nil || updated.JSON200 == nil || updated.JSON200.Id != resource.Id || updated.JSON200.Services[0].ServiceId == nil || *updated.JSON200.Services[0].ServiceId != *resource.Services[0].ServiceId {
		t.Fatal("binding mutation", updated, err)
	}
	stale, err := client.UpdatePublisherGroupBindingsWithResponse(ctx, "customers", resource.Id, controlv1.UpdatePublisherGroupBindingsRequest{TeamId: team, ExpectedRevision: resource.Revision, Bindings: updated.JSON200.Bindings})
	if err != nil || stale.StatusCode() != http.StatusConflict {
		t.Fatal("stale binding update accepted", stale, err)
	}
	revoked, err := client.RevokePublisherGroupMemberWithResponse(ctx, "customers", resource.Id, member.JSON200.PublisherIdentityId, &controlv1.RevokePublisherGroupMemberParams{TeamId: team})
	if err != nil || revoked.StatusCode() != http.StatusNoContent {
		t.Fatal("exact member revoke", revoked, err)
	}
	members, err = client.ListPublisherGroupMembersWithResponse(ctx, "customers", resource.Id, &controlv1.ListPublisherGroupMembersParams{TeamId: team})
	if err != nil || members.JSON200 == nil || len(*members.JSON200) != 0 {
		t.Fatal("revoked member remains current", members, err)
	}
	retired, err := client.RemovePublisherGroupWithResponse(ctx, "customers", resource.Id, &controlv1.RemovePublisherGroupParams{TeamId: team, ExpectedRevision: updated.JSON200.Revision})
	if err != nil || retired.StatusCode() != http.StatusNoContent {
		t.Fatal("retire by ID", retired, err)
	}
	replayed, err = client.CreateBoundPublisherGroupWithResponse(ctx, "customers", request)
	if err != nil || replayed.StatusCode() != http.StatusConflict || replayed.JSON200 != nil {
		t.Fatal("retired create returned usable identity", replayed, err)
	}
	get, err = client.GetPublisherGroupWithResponse(ctx, "customers", resource.Id, &controlv1.GetPublisherGroupParams{TeamId: team})
	if err != nil || get.JSON200 == nil || !get.JSON200.Retired {
		t.Fatal("missing retired tombstone", get, err)
	}
	denied, err := client.GetPublisherGroupWithResponse(ctx, "customers", resource.Id, &controlv1.GetPublisherGroupParams{TeamId: team}, func(_ context.Context, r *http.Request) error { r.Header.Del("Authorization"); return nil })
	if err != nil || denied.StatusCode() != http.StatusUnauthorized {
		t.Fatal("unauthorized read", denied, err)
	}
}
