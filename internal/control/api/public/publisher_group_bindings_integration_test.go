package public

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"maps"
	"net/http"
	"strings"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherGroupBindingsHTTP(t *testing.T) {
	f := newEnvironmentHTTPFixture(t)
	ctx := t.Context()
	definition := f.definition(controlv1.Postgres)
	collection := createCollectionHTTP(t, f, "customer services", definition.Revision)
	request := collectionHTTPEnvironmentRequest(f, collection, "customer 42", "db.internal", "5432")
	request.IdempotencyKey = "arbitrary/customer:42"
	request.Targets["api"] = controlv1.EnvironmentTarget{Address: new("http://192.0.2.42:3000/")}
	resource := createCollectionHTTPEnvironment(t, f, request)
	if resource.Id == "" || resource.Name != request.Name || resource.MutationRevision != 1 || resource.CollectionId == nil || *resource.CollectionId != collection.CollectionId || len(resource.Services) != 2 {
		t.Fatal("missing management context")
	}
	// reordered, normalized JSON has the same creation intent and saved IDs.
	replayed, err := f.client.CreateEnvironmentWithBodyWithResponse(ctx, f.project, "application/json", strings.NewReader(`{"targets":{"api":{"address":"192.0.2.42:3000"},"database":{"address":"db.internal:5432","tls":{}}},"idempotency_key":"arbitrary/customer:42","expected_collection_revision":1,"collection_id":"`+collection.CollectionId+`","name":"customer 42","source_fingerprint":"`+f.source+`","team_id":"`+f.team+`"}`))
	if err != nil || replayed.JSON200 == nil || replayed.JSON200.Id != resource.Id || replayed.JSON200.MutationRevision != resource.MutationRevision || replayed.JSON200.Services[0].ServiceId != resource.Services[0].ServiceId {
		t.Fatal("normalized replay", replayed, err)
	}
	changed := request
	changed.Name = "different"
	assertCollectionHTTPCreateConflict(t, f, changed)
	get, err := f.client.GetEnvironmentWithResponse(ctx, f.project, resource.Id, &controlv1.GetEnvironmentParams{TeamId: f.team})
	if err != nil || get.JSON200 == nil || get.JSON200.Id != resource.Id {
		t.Fatal("get by ID", get, err)
	}
	list, err := f.client.ListEnvironmentsWithResponse(ctx, f.project, &controlv1.ListEnvironmentsParams{TeamId: f.team})
	if err != nil || list.JSON200 == nil || len(*list.JSON200) != 1 {
		t.Fatal("list concrete environments", list, err)
	}
	enrollment, err := f.client.CreateEnvironmentPublisherEnrollmentWithResponse(ctx, f.project, resource.Id, nil, controlv1.CreateEnvironmentPublisherEnrollmentRequest{TeamId: f.team, ExpectedRevision: resource.MutationRevision, ConfigurationHash: resource.ConfigurationHash, Services: []string{"api"}, MaxMembers: 1, ExpiresIn: 600})
	if err != nil || enrollment.JSON201 == nil {
		t.Fatal("enroll by ID", enrollment, err)
	}
	e := enrollment.JSON201
	if e.Ref != resource.Ref || e.EnrollmentKey == "" {
		t.Fatal("incomplete installation context")
	}
	if strings.Contains(string(get.Body), e.EnrollmentKey) || strings.Contains(string(list.Body), e.EnrollmentKey) {
		t.Fatal("resource leaked enrollment secret")
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.client.RedeemEnvironmentPublisherEnrollmentWithResponse(ctx, controlv1.RedeemEnvironmentPublisherEnrollmentRequest{EnrollmentKey: e.EnrollmentKey, PublicKey: base64.RawURLEncoding.EncodeToString(public)})
	if err != nil || member.JSON200 == nil || member.JSON200.EnvironmentId != resource.Id {
		t.Fatal("redeem", member, err)
	}
	members, err := f.client.ListEnvironmentPublishersWithResponse(ctx, f.project, resource.Id, &controlv1.ListEnvironmentPublishersParams{TeamId: f.team})
	if err != nil || members.JSON200 == nil || len(*members.JSON200) != 1 || (*members.JSON200)[0].PublisherIdentityId != member.JSON200.PublisherIdentityId {
		t.Fatal("publisher observations", members, err)
	}
	targets := maps.Clone(request.Targets)
	targets["api"] = controlv1.EnvironmentTarget{Address: new("192.0.2.42:3001")}
	update := controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: resource.MutationRevision, DefinitionRevision: definition.Revision, Targets: &targets}
	updated, err := f.client.ApplyEnvironmentWithResponse(ctx, f.project, resource.Id, update)
	if err != nil || updated.JSON200 == nil || updated.JSON200.Id != resource.Id || len(updated.JSON200.Services) != len(resource.Services) {
		t.Fatal("target mutation", updated, err)
	}
	for i, service := range updated.JSON200.Services {
		if service.ServiceId != resource.Services[i].ServiceId {
			t.Fatal("target mutation replaced saved service identity")
		}
	}
	stale, err := f.client.ApplyEnvironmentWithResponse(ctx, f.project, resource.Id, update)
	if err != nil || stale.StatusCode() != http.StatusConflict {
		t.Fatal("stale target update accepted", stale, err)
	}
	revoked, err := f.client.RevokeEnvironmentPublisherWithResponse(ctx, f.project, resource.Id, member.JSON200.PublisherIdentityId, &controlv1.RevokeEnvironmentPublisherParams{TeamId: f.team})
	if err != nil || revoked.StatusCode() != http.StatusNoContent {
		t.Fatal("exact publisher revoke", revoked, err)
	}
	members, err = f.client.ListEnvironmentPublishersWithResponse(ctx, f.project, resource.Id, &controlv1.ListEnvironmentPublishersParams{TeamId: f.team})
	if err != nil || members.JSON200 == nil || len(*members.JSON200) != 0 {
		t.Fatal("revoked publisher remains current", members, err)
	}
	retired, err := f.client.RetireEnvironmentWithResponse(ctx, f.project, resource.Id, &controlv1.RetireEnvironmentParams{TeamId: f.team, ExpectedRevision: updated.JSON200.MutationRevision})
	if err != nil || retired.StatusCode() != http.StatusNoContent {
		t.Fatal("retire by ID", retired, err)
	}
	// the saved creation key remains fenced even though retired environments are
	// no longer returned as usable manager resources.
	retry, err := f.client.CreateEnvironmentWithResponse(ctx, f.project, request)
	if err != nil || retry.StatusCode() != http.StatusConflict || retry.JSON200 != nil {
		t.Fatal("retired create returned usable identity", retry, err)
	}
	get, err = f.client.GetEnvironmentWithResponse(ctx, f.project, resource.Id, &controlv1.GetEnvironmentParams{TeamId: f.team})
	if err != nil || get.StatusCode() != http.StatusNotFound {
		t.Fatal("retired environment recovered", get, err)
	}
	denied, err := f.client.GetEnvironmentWithResponse(ctx, f.project, resource.Id, &controlv1.GetEnvironmentParams{TeamId: f.team}, func(_ context.Context, r *http.Request) error { r.Header.Del("Authorization"); return nil })
	if err != nil || denied.StatusCode() != http.StatusUnauthorized {
		t.Fatal("unauthorized read", denied, err)
	}
	assertRetainedHTTPRemoved(t, &http.Client{Transport: f.transport}, "https://control.example.test", f.session.AccessToken.String(), http.MethodPost, "/v1/projects/"+f.project+"/publisher-groups")
}
