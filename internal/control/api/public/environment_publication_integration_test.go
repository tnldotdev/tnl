package public

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationEnvironmentHTTPPublicationFence(t *testing.T) {
	f := newEnvironmentHTTPFixture(t)
	definition := f.definition(controlv1.Postgres)
	original := environmentHTTPTargets("db.original.internal", "5432")
	environment := f.create("production", definition.Revision, original)
	inspect, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inspect.Close(context.Background()) })
	var group string
	if err := inspect.QueryRow(t.Context(), `SELECT group_id FROM control.environments WHERE id=$1 AND team_id=$2 AND project_key=$3`, environment.Id, f.team, f.project).Scan(&group); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	enrollment, err := f.database.IssuePublisherGroupEnrollment(t.Context(), f.team, f.project, group, f.session.Identity.Identity.ID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.database.RedeemPublisherGroupEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	const audience = "https://control.example.test/v1/publisher-groups/lease"
	assertion, err := publisherproof.Sign(member.PublisherIdentityID, member.KeyID, group, audience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.database.AcquirePublisherGroupLease(t.Context(), member.PublisherIdentityID, group, assertion, audience, now)
	if err != nil {
		t.Fatal(err)
	}
	bearer := func(token string) controlv1.RequestEditorFn {
		return func(_ context.Context, request *http.Request) error {
			request.Header.Set("Authorization", "Bearer "+token)
			return nil
		}
	}
	poll := func() controlv1.PublisherGroupServiceAssignment {
		t.Helper()
		response, err := f.client.GetPublisherGroupAssignmentsWithResponse(t.Context(), bearer(lease.AccessToken))
		if err != nil || response == nil || response.JSON200 == nil {
			t.Fatal("read environment publisher assignments", response, err)
		}
		for _, assignment := range response.JSON200.Services {
			if assignment.Service == "api" {
				if assignment.Environment == nil || assignment.Environment.EnvironmentId != environment.Id || assignment.Environment.MutationRevision != response.JSON200.Revision || assignment.Environment.ConfigurationHash != response.JSON200.ConfigurationHash {
					t.Fatal("wire assignment omitted or changed the exact environment application")
				}
				return assignment
			}
		}
		t.Fatal("publisher assignment omitted the HTTP service")
		return controlv1.PublisherGroupServiceAssignment{}
	}
	assigned := poll()
	const publisherAudience = "https://control.example.test/v1/publishers/assertions"
	assertion, err = publisherproof.Sign(member.PublisherIdentityID, member.KeyID, assigned.GrantId, publisherAudience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := f.database.ExchangePublisherAssertion(t.Context(), member.PublisherIdentityID, assigned.GrantId, publisherAudience, assertion, "", now)
	if err != nil {
		t.Fatal(err)
	}
	preferences := []string{"fly:sjc", "aws:us-west-1"}
	declaration := controlv1.ServiceRunDeclaration{Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: assigned.TrustRevision, PreferredRegions: &preferences}
	missing, err := f.client.PrepareServiceRunWithResponse(t.Context(), assigned.ServiceId, &controlv1.PrepareServiceRunParams{IdempotencyKey: "missing-application"}, declaration, bearer(access.Token))
	if err != nil || missing == nil {
		t.Fatal("preparation without an application failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, missing.StatusCode(), missing.Body, http.StatusConflict, controlv1.Conflict)
	declaration.Environment = assigned.Environment
	prepared, err := f.client.PrepareServiceRunWithResponse(t.Context(), assigned.ServiceId, &controlv1.PrepareServiceRunParams{IdempotencyKey: "pinned-application"}, declaration, bearer(access.Token))
	if err != nil || prepared == nil || prepared.JSON201 == nil {
		t.Fatal("prepare exact assigned application", prepared, err)
	}
	var storedPreferences []string
	if err := inspect.QueryRow(t.Context(), `SELECT preferred_regions FROM control.service_runs WHERE id=$1`, prepared.JSON201.ServiceRunId).Scan(&storedPreferences); err != nil || !slices.Equal(storedPreferences, preferences) {
		t.Fatal("environment HTTP preparation dropped ordered region preferences", err)
	}
	replacement := environmentHTTPTargets("db.original.internal", "5432")
	replacement["api"] = controlv1.EnvironmentTarget{Address: new("replacement.internal:8080")}
	applied, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: environment.MutationRevision, DefinitionRevision: definition.Revision, Targets: &replacement})
	if err != nil || applied == nil || applied.JSON200 == nil {
		t.Fatal("apply target-only replacement", applied, err)
	}
	stale, err := f.client.PrepareServiceRunWithResponse(t.Context(), assigned.ServiceId, &controlv1.PrepareServiceRunParams{IdempotencyKey: "stale-worker-fresh-key"}, declaration, bearer(access.Token))
	if err != nil || stale == nil {
		t.Fatal("stale preparation failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, stale.StatusCode(), stale.Body, http.StatusConflict, controlv1.Conflict)
	start, err := f.client.StartServiceRunWithResponse(t.Context(), assigned.ServiceId, prepared.JSON201.ServiceRunId, controlv1.StartServiceRunJSONRequestBody{RunNumber: prepared.JSON201.RunNumber}, bearer(access.Token))
	if err != nil || start == nil {
		t.Fatal("stale start failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, start.StatusCode(), start.Body, http.StatusNotFound, controlv1.NotFound)
	current := poll()
	if current.TrustRevision != assigned.TrustRevision {
		t.Fatal("target-only apply relied on a protocol/TLS revision change")
	}
	declaration.Environment = current.Environment
	fresh, err := f.client.PrepareServiceRunWithResponse(t.Context(), current.ServiceId, &controlv1.PrepareServiceRunParams{IdempotencyKey: "current-application"}, declaration, bearer(access.Token))
	if err != nil || fresh == nil || fresh.JSON201 == nil {
		t.Fatal("current application could not prepare after replacement", fresh, err)
	}
	rolled, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: applied.JSON200.MutationRevision, DefinitionRevision: definition.Revision, Targets: &original})
	if err != nil || rolled == nil || rolled.JSON200 == nil || rolled.JSON200.ConfigurationHash != environment.ConfigurationHash || rolled.JSON200.MutationRevision <= current.Environment.MutationRevision {
		t.Fatal("rollback did not restore configuration with a new application revision", rolled, err)
	}
	declaration.Environment = assigned.Environment
	stale, err = f.client.PrepareServiceRunWithResponse(t.Context(), assigned.ServiceId, &controlv1.PrepareServiceRunParams{IdempotencyKey: "old-revision-after-rollback"}, declaration, bearer(access.Token))
	if err != nil || stale == nil {
		t.Fatal("old rollback revision failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, stale.StatusCode(), stale.Body, http.StatusConflict, controlv1.Conflict)
}
