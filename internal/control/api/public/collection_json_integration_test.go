package public

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationCollectionHTTPRejectsInvalidWirePresenceAndValues(t *testing.T) {
	f := newEnvironmentHTTPFixture(t)
	d1 := f.definition(controlv1.Postgres)
	c := createCollectionHTTP(t, f, "wire validation", d1.Revision)
	request := collectionHTTPEnvironmentRequest(f, c, "preserved", "db.preserved.internal", "5432")
	installed := createCollectionHTTPEnvironment(t, f, request)
	encode := func(body map[string]any) string {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	invalidRevisions := []any{nil, 0, -1, "1", 1.5, true, []int{1}, map[string]int{"revision": 1}, json.RawMessage(`9223372036854775808`)}
	create := map[string]any{"team_id": f.team, "name": "must not create", "default_definition_revision": d1.Revision}
	createBodies := []string{`null`, `{`, `{} {}`, strings.Repeat(" ", int(environmentRequestBodyLimit)+1) + `{}`}
	for _, field := range []string{"team_id", "name", "default_definition_revision"} {
		body := maps.Clone(create)
		delete(body, field)
		createBodies = append(createBodies, encode(body))
		body = maps.Clone(create)
		body[field] = nil
		createBodies = append(createBodies, encode(body))
	}
	for _, revision := range invalidRevisions {
		body := maps.Clone(create)
		body["default_definition_revision"] = revision
		createBodies = append(createBodies, encode(body))
	}
	for _, name := range []any{" padded", "trailing ", "line\nbreak", strings.Repeat("a", 129), 1} {
		body := maps.Clone(create)
		body["name"] = name
		createBodies = append(createBodies, encode(body))
	}
	for _, field := range []string{"collection_id", "targets", "permissions", "idempotency_key", "expected_revision"} {
		body := maps.Clone(create)
		body[field] = "sensitive-marker"
		createBodies = append(createBodies, encode(body))
	}
	for _, body := range createBodies {
		response, err := f.client.CreateCollectionWithBodyWithResponse(t.Context(), f.project, "application/json", strings.NewReader(body))
		if err != nil || response == nil {
			t.Fatal(err)
		}
		assertEnvironmentHTTPProblem(t, response.StatusCode(), response.Body, 400, controlv1.InvalidRequest)
		assertCollectionHTTPNoStore(t, response.HTTPResponse)
		if strings.Contains(string(response.Body), "sensitive-marker") {
			t.Fatal("invalid collection request was reflected into its problem")
		}
	}
	update := map[string]any{"team_id": f.team, "expected_revision": c.MutationRevision, "definition_revision": d1.Revision}
	var updateBodies []string
	for _, field := range []string{"team_id", "expected_revision", "definition_revision"} {
		body := maps.Clone(update)
		delete(body, field)
		updateBodies = append(updateBodies, encode(body))
		body = maps.Clone(update)
		body[field] = nil
		updateBodies = append(updateBodies, encode(body))
	}
	for _, field := range []string{"expected_revision", "definition_revision"} {
		for _, revision := range invalidRevisions {
			body := maps.Clone(update)
			body[field] = revision
			updateBodies = append(updateBodies, encode(body))
		}
	}
	body := maps.Clone(update)
	body["expected_revision"] = json.RawMessage(`9223372036854775807`)
	updateBodies = append(updateBodies, encode(body), `null`)
	for _, field := range []string{"collection_id", "targets", "membership", "default_definition_revision"} {
		body := maps.Clone(update)
		body[field] = "sensitive-marker"
		updateBodies = append(updateBodies, encode(body))
	}
	for _, body := range updateBodies {
		response, err := f.client.UpdateCollectionDefaultWithBodyWithResponse(t.Context(), f.project, c.CollectionId, "application/json", strings.NewReader(body))
		if err != nil || response == nil {
			t.Fatal(err)
		}
		assertEnvironmentHTTPProblem(t, response.StatusCode(), response.Body, 400, controlv1.InvalidRequest)
		assertCollectionHTTPNoStore(t, response.HTTPResponse)
	}
	environment := map[string]any{"team_id": f.team, "source_fingerprint": f.source, "name": "must not materialize", "idempotency_key": "invalid-wire", "targets": request.Targets, "collection_id": c.CollectionId, "expected_collection_revision": c.MutationRevision}
	var environmentBodies []string
	for _, field := range []string{"expected_collection_revision", "definition_revision"} {
		for _, revision := range invalidRevisions {
			body := maps.Clone(environment)
			body[field] = revision
			environmentBodies = append(environmentBodies, encode(body))
		}
	}
	for _, id := range []any{nil, "", "env_AAAAAAAAAAAAAAAAAAAAAA", 1, true} {
		body := maps.Clone(environment)
		body["collection_id"] = id
		environmentBodies = append(environmentBodies, encode(body))
	}
	for _, omitted := range [][]string{{"collection_id"}, {"expected_collection_revision"}, {"collection_id", "expected_collection_revision"}} {
		body := maps.Clone(environment)
		for _, field := range omitted {
			delete(body, field)
		}
		environmentBodies = append(environmentBodies, encode(body))
	}
	body = maps.Clone(environment)
	delete(body, "collection_id")
	body["definition_revision"] = d1.Revision
	environmentBodies = append(environmentBodies, encode(body))
	for _, field := range []string{"membership", "permissions", "default_definition_revision", "expected_revision"} {
		body := maps.Clone(environment)
		body[field] = "sensitive-marker"
		environmentBodies = append(environmentBodies, encode(body))
	}
	for _, body := range environmentBodies {
		response, err := f.client.CreateEnvironmentWithBodyWithResponse(t.Context(), f.project, "application/json", strings.NewReader(body))
		if err != nil || response == nil {
			t.Fatal(err)
		}
		assertEnvironmentHTTPProblem(t, response.StatusCode(), response.Body, 400, controlv1.InvalidRequest)
		assertCollectionHTTPNoStore(t, response.HTTPResponse)
	}
	got, err := f.client.GetCollectionWithResponse(t.Context(), f.project, c.CollectionId, &controlv1.GetCollectionParams{TeamId: f.team})
	if err != nil || got == nil || got.JSON200 == nil || *got.JSON200 != c {
		t.Fatal("invalid wire request changed the collection", err)
	}
	listed, err := f.client.ListEnvironmentsWithResponse(t.Context(), f.project, &controlv1.ListEnvironmentsParams{TeamId: f.team})
	if err != nil || listed == nil || listed.JSON200 == nil || len(*listed.JSON200) != 1 || (*listed.JSON200)[0].Id != installed.Id {
		t.Fatal("invalid wire request materialized an environment", err)
	}
}
