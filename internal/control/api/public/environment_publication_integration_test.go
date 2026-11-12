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
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
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
	manager, err := f.database.AuthenticateEnvironmentPublisherManager(t.Context(), f.session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	enrollment, err := f.database.IssueEnvironmentPublisherEnrollment(t.Context(), controlstate.IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: controlstate.EnvironmentPublisherSelection{TeamID: f.team, ProjectKey: f.project, EnvironmentID: environment.Id, Manager: manager}, ExpectedRevision: environment.MutationRevision, ExpectedConfigurationHash: environment.ConfigurationHash, Services: []string{"api"}, MaxMembers: 1, Lifetime: time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.database.RedeemEnvironmentPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	const audience = "https://control.example.test/v1/environment-publishers/lease"
	assertion, err := publisherproof.Sign(member.PublisherIdentityID, member.KeyID, environment.Id, audience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.database.AcquireEnvironmentPublisherLease(t.Context(), member.PublisherIdentityID, environment.Id, assertion, audience, now)
	if err != nil {
		t.Fatal(err)
	}
	bearer := func(token string) controlv1.RequestEditorFn {
		return func(_ context.Context, request *http.Request) error {
			request.Header.Set("Authorization", "Bearer "+token)
			return nil
		}
	}
	var application controlv1.EnvironmentPublication
	poll := func() controlv1.EnvironmentPublisherAssignment {
		t.Helper()
		response, err := f.client.GetEnvironmentPublisherAssignmentsWithResponse(t.Context(), bearer(lease.AccessToken))
		if err != nil || response == nil || response.JSON200 == nil {
			t.Fatal("read environment publisher assignments", response, err)
		}
		application = response.JSON200.Environment
		if application.EnvironmentId != environment.Id || application.MutationRevision < 1 || application.ConfigurationHash == "" || response.JSON200.Publisher.EnvironmentId != environment.Id || response.JSON200.Publisher.PublisherIdentityId != member.PublisherIdentityID {
			t.Fatal("wire envelope omitted or changed the exact publisher and environment application")
		}
		for _, assignment := range response.JSON200.Services {
			if assignment.Service == "api" {
				return assignment
			}
		}
		t.Fatal("publisher assignment omitted the HTTP service")
		return controlv1.EnvironmentPublisherAssignment{}
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
	originalApplication := application
	declaration.Environment = &originalApplication
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
	currentApplication := application
	if current.ServiceId != assigned.ServiceId || current.GrantId != assigned.GrantId {
		t.Fatal("target replacement changed the saved service or publisher grant")
	}
	declaration.Environment = &currentApplication
	fresh, err := f.client.PrepareServiceRunWithResponse(t.Context(), current.ServiceId, &controlv1.PrepareServiceRunParams{IdempotencyKey: "current-application"}, declaration, bearer(access.Token))
	if err != nil || fresh == nil || fresh.JSON201 == nil {
		t.Fatal("current application could not prepare after replacement", fresh, err)
	}
	rolled, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: applied.JSON200.MutationRevision, DefinitionRevision: definition.Revision, Targets: &original})
	if err != nil || rolled == nil || rolled.JSON200 == nil || rolled.JSON200.ConfigurationHash != environment.ConfigurationHash || rolled.JSON200.MutationRevision <= currentApplication.MutationRevision {
		t.Fatal("rollback did not restore configuration with a new application revision", rolled, err)
	}
	declaration.Environment = &originalApplication
	stale, err = f.client.PrepareServiceRunWithResponse(t.Context(), assigned.ServiceId, &controlv1.PrepareServiceRunParams{IdempotencyKey: "old-revision-after-rollback"}, declaration, bearer(access.Token))
	if err != nil || stale == nil {
		t.Fatal("old rollback revision failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, stale.StatusCode(), stale.Body, http.StatusConflict, controlv1.Conflict)
}
