package public

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func assertCollectionHTTPNoStore(t *testing.T, response *http.Response) {
	t.Helper()
	if response == nil || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("collection management success or problem response may be cached")
	}
}

func createCollectionHTTP(t *testing.T, f environmentHTTPFixture, name string, revision int64) controlv1.Collection {
	t.Helper()
	result, err := f.client.CreateCollectionWithResponse(t.Context(), f.project, controlv1.CreateCollectionRequest{TeamId: f.team, Name: name, DefaultDefinitionRevision: revision})
	if err != nil || result == nil || result.JSON200 == nil {
		t.Fatal("create collection", err, result)
	}
	assertCollectionHTTPNoStore(t, result.HTTPResponse)
	if result.JSON200.Ref.Server != "https://control.example.test" || result.JSON200.Ref.ProjectKey != f.project || result.JSON200.Ref.CollectionId != result.JSON200.CollectionId {
		t.Fatal("collection response lost its server-qualified reference")
	}
	return *result.JSON200
}

func collectionHTTPEnvironmentRequest(f environmentHTTPFixture, c controlv1.Collection, name, host, port string) controlv1.CreateEnvironmentRequest {
	return controlv1.CreateEnvironmentRequest{TeamId: f.team, SourceFingerprint: f.source, Name: name, Targets: environmentHTTPTargets(host, port), IdempotencyKey: "collection/" + name, CollectionId: new(c.CollectionId), ExpectedCollectionRevision: new(c.MutationRevision)}
}

func createCollectionHTTPEnvironment(t *testing.T, f environmentHTTPFixture, request controlv1.CreateEnvironmentRequest) controlv1.Environment {
	t.Helper()
	result, err := f.client.CreateEnvironmentWithResponse(t.Context(), f.project, request)
	if err != nil || result == nil || result.JSON200 == nil {
		t.Fatal("create collection environment", err, result)
	}
	assertCollectionHTTPNoStore(t, result.HTTPResponse)
	return *result.JSON200
}

func collectionHTTPInspect(t *testing.T, f environmentHTTPFixture) *pgx.Conn {
	t.Helper()
	inspect, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := inspect.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return inspect
}

func TestIntegrationCollectionHTTPDefaultsAndExactCreationIntent(t *testing.T) {
	f := newEnvironmentHTTPFixture(t)
	d1 := f.definition(controlv1.Postgres)
	c := createCollectionHTTP(t, f, "Customer previews", d1.Revision)
	if c.MutationRevision != 1 {
		t.Fatal("new collection has no independent mutation revision")
	}
	request := collectionHTTPEnvironmentRequest(f, c, "old member", "db.old.internal", "5432")
	installed := createCollectionHTTPEnvironment(t, f, request)
	if installed.CollectionId == nil || *installed.CollectionId != c.CollectionId || installed.AppliedDefinitionRevision != d1.Revision {
		t.Fatal("default selection did not save membership and a pinned definition")
	}
	inspect := collectionHTTPInspect(t, f)
	run := startCollectionHTTPRun(t, f, inspect, installed)
	visitor, err := f.database.CreateServiceGrant(t.Context(), run.ServiceID, f.session.Identity.Identity.ID, "collection-revoked-visitor", "identity", f.session.Identity.Identity.ID, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.database.RevokeServiceGrant(t.Context(), run.ServiceID, f.session.Identity.Identity.ID, visitor.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	d2 := f.definition(controlv1.Mysql)
	snapshot := func() string {
		t.Helper()
		var value string
		if err := inspect.QueryRow(t.Context(), `WITH owned AS (SELECT service_id FROM control.applied_project_services WHERE group_id=(SELECT group_id FROM control.environments WHERE id=$1))
			SELECT jsonb_build_array(
			(SELECT to_jsonb(e) FROM control.environments e WHERE id=$1),
			(SELECT jsonb_agg(s ORDER BY id) FROM control.services s WHERE id IN (SELECT service_id FROM owned)),
			(SELECT jsonb_agg(r ORDER BY id) FROM control.service_runs r WHERE environment_id=$1),
			(SELECT jsonb_agg(g ORDER BY id) FROM control.publisher_grants g WHERE service_id IN (SELECT service_id FROM owned)),
			(SELECT jsonb_agg(g ORDER BY id) FROM control.visitor_grants g WHERE service_id IN (SELECT service_id FROM owned)),
			(SELECT to_jsonb(b) FROM control.publisher_group_bindings b WHERE group_id=(SELECT group_id FROM control.environments WHERE id=$1)))::text`, installed.Id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	update := controlv1.UpdateCollectionDefaultRequest{TeamId: f.team, ExpectedRevision: c.MutationRevision, DefinitionRevision: d2.Revision}
	updated, err := f.client.UpdateCollectionDefaultWithResponse(t.Context(), f.project, c.CollectionId, update)
	if err != nil || updated == nil || updated.JSON200 == nil || updated.JSON200.MutationRevision != c.MutationRevision+1 || updated.JSON200.DefaultDefinitionRevision != d2.Revision {
		t.Fatal("update collection default", updated, err)
	}
	assertCollectionHTTPNoStore(t, updated.HTTPResponse)
	if snapshot() != before || !reflect.DeepEqual(f.get(installed.Id), installed) {
		t.Fatal("default update changed installed targets, revisions, IDs, grants, or runs")
	}
	if _, err := f.database.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, time.Now(), controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("default update invalidated an installed publisher run", err)
	}
	replayed := createCollectionHTTPEnvironment(t, f, request)
	if !reflect.DeepEqual(replayed, installed) {
		t.Fatal("exact creation retry followed a changed collection default")
	}
	changed := request
	changed.ExpectedCollectionRevision = new(updated.JSON200.MutationRevision)
	assertCollectionHTTPCreateConflict(t, f, changed)
	changed = request
	changed.DefinitionRevision = new(d1.Revision)
	assertCollectionHTTPCreateConflict(t, f, changed)
	stale := collectionHTTPEnvironmentRequest(f, c, "stale member", "db.stale.internal", "5432")
	assertCollectionHTTPCreateConflict(t, f, stale)
	stale.DefinitionRevision = new(d1.Revision)
	assertCollectionHTTPCreateConflict(t, f, stale)
	current := collectionHTTPEnvironmentRequest(f, *updated.JSON200, "new member", "db.new.internal", "3306")
	newMember := createCollectionHTTPEnvironment(t, f, current)
	if newMember.AppliedDefinitionRevision != d2.Revision || newMember.MutationRevision != 1 || newMember.Services[0].ServiceId == installed.Services[0].ServiceId {
		t.Fatal("new member did not pin the new default independently")
	}
	override := collectionHTTPEnvironmentRequest(f, *updated.JSON200, "explicit member", "db.override.internal", "5432")
	override.DefinitionRevision = new(d1.Revision)
	explicit := createCollectionHTTPEnvironment(t, f, override)
	if explicit.AppliedDefinitionRevision != d1.Revision || explicit.CollectionId == nil || *explicit.CollectionId != c.CollectionId {
		t.Fatal("explicit definition did not override the collection default")
	}
	if replay := createCollectionHTTP(t, f, c.Name, d1.Revision); !reflect.DeepEqual(replay, *updated.JSON200) {
		t.Fatal("collection creation retry did not use its original default intent")
	}
	conflict, err := f.client.CreateCollectionWithResponse(t.Context(), f.project, controlv1.CreateCollectionRequest{TeamId: f.team, Name: c.Name, DefaultDefinitionRevision: d2.Revision})
	if err != nil || conflict == nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, conflict.StatusCode(), conflict.Body, 409, controlv1.Conflict)
	assertCollectionHTTPNoStore(t, conflict.HTTPResponse)
	staleUpdate, err := f.client.UpdateCollectionDefaultWithResponse(t.Context(), f.project, c.CollectionId, update)
	if err != nil || staleUpdate == nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, staleUpdate.StatusCode(), staleUpdate.Body, 409, controlv1.Conflict)
	assertCollectionHTTPNoStore(t, staleUpdate.HTTPResponse)
	got, err := f.client.GetCollectionWithResponse(t.Context(), f.project, c.CollectionId, &controlv1.GetCollectionParams{TeamId: f.team}, func(_ context.Context, request *http.Request) error {
		request.Host = "untrusted-host.example.test"
		return nil
	})
	if err != nil || got == nil || got.JSON200 == nil || !reflect.DeepEqual(*got.JSON200, *updated.JSON200) {
		t.Fatal("get collection changed scope, reference origin or saved state", got, err)
	}
	assertCollectionHTTPNoStore(t, got.HTTPResponse)
	listed, err := f.client.ListCollectionsWithResponse(t.Context(), f.project, &controlv1.ListCollectionsParams{TeamId: f.team})
	if err != nil || listed == nil || listed.JSON200 == nil || !reflect.DeepEqual(*listed.JSON200, []controlv1.Collection{*updated.JSON200}) {
		t.Fatal("list collections did not return the saved closed resources", listed, err)
	}
	assertCollectionHTTPNoStore(t, listed.HTTPResponse)
	other := createCollectionHTTP(t, f, "other collection", d1.Revision)
	changed = request
	changed.CollectionId = new(other.CollectionId)
	assertCollectionHTTPCreateConflict(t, f, changed)
	plain := f.create("independent", d1.Revision, request.Targets)
	changed = request
	changed.Name, changed.IdempotencyKey = plain.Name, "environment:"+plain.Name
	assertCollectionHTTPCreateConflict(t, f, changed)
	for _, membershipField := range []string{"collection_id", "expected_collection_revision"} {
		body := map[string]any{"team_id": f.team, "expected_revision": installed.MutationRevision, "definition_revision": d1.Revision, membershipField: c.CollectionId}
		encoded, _ := json.Marshal(body)
		denied, err := f.client.ApplyEnvironmentWithBodyWithResponse(t.Context(), f.project, installed.Id, "application/json", strings.NewReader(string(encoded)))
		if err != nil || denied == nil {
			t.Fatal(err)
		}
		assertEnvironmentHTTPProblem(t, denied.StatusCode(), denied.Body, 400, controlv1.InvalidRequest)
		assertCollectionHTTPNoStore(t, denied.HTTPResponse)
	}
	batch, err := f.client.ApplyEnvironmentsWithBodyWithResponse(t.Context(), f.project, "application/json", strings.NewReader(`{"team_id":"`+f.team+`","environments":[{"environment_id":"`+installed.Id+`","expected_revision":1,"definition_revision":1,"collection_id":"`+other.CollectionId+`"}]}`))
	if err != nil || batch == nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, batch.StatusCode(), batch.Body, 400, controlv1.InvalidRequest)
	if !reflect.DeepEqual(f.get(installed.Id), installed) {
		t.Fatal("rejected membership edits changed the installed environment")
	}
}

func assertCollectionHTTPCreateConflict(t *testing.T, f environmentHTTPFixture, request controlv1.CreateEnvironmentRequest) {
	t.Helper()
	response, err := f.client.CreateEnvironmentWithResponse(t.Context(), f.project, request)
	if err != nil || response == nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, response.StatusCode(), response.Body, 409, controlv1.Conflict)
	assertCollectionHTTPNoStore(t, response.HTTPResponse)
}

func startCollectionHTTPRun(t *testing.T, f environmentHTTPFixture, inspect *pgx.Conn, environment controlv1.Environment) controlstate.ServiceRunState {
	t.Helper()
	var group string
	if err := inspect.QueryRow(t.Context(), `SELECT group_id FROM control.environments WHERE id=$1`, environment.Id).Scan(&group); err != nil {
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
	const leaseAudience = "https://control.example.test/v1/publisher-groups/lease"
	assertion, err := publisherproof.Sign(member.PublisherIdentityID, member.KeyID, group, leaseAudience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.database.AcquirePublisherGroupLease(t.Context(), member.PublisherIdentityID, group, assertion, leaseAudience, now)
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := f.database.GetPublisherGroupAssignments(t.Context(), lease.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"collection-a", "collection-b"} {
		if _, err := f.database.RegisterRelay(t.Context(), controlstate.RelayRegistration{RelayServiceID: name, RelayID: name, RelayRunID: name + "-run", ProtocolVersion: 1, RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test", InternalRelayAddress: "127.0.0.1:8443", ConnectionCapacity: 20, StreamCapacity: 20}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	for _, assignment := range assignments.Services {
		if assignment.Service != "api" {
			continue
		}
		const audience = "https://control.example.test/v1/publishers/assertions"
		assertion, err := publisherproof.Sign(member.PublisherIdentityID, member.KeyID, assignment.GrantID, audience, private, now)
		if err != nil {
			t.Fatal(err)
		}
		access, err := f.database.ExchangePublisherAssertion(t.Context(), member.PublisherIdentityID, assignment.GrantID, audience, assertion, "", now)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := f.database.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "collection-installed-run", now, controlstate.ServiceMetadata{Protocol: "http", PublisherPool: true, TrustRevision: assignment.TrustRevision}, assignment.Environment)
		if err != nil {
			t.Fatal(err)
		}
		run, err := f.database.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	t.Fatal("missing installed HTTP service assignment")
	return controlstate.ServiceRunState{}
}

func TestIntegrationCollectionHTTPCurrentManagerAndScope(t *testing.T) {
	f := newEnvironmentHTTPFixture(t)
	owner := f.session.Identity.Identity.ID
	now := time.Now()
	team, err := f.database.CreateTeam(t.Context(), controlstate.CreateTeamRequest{IdentityID: owner, DisplayName: "collections", IdempotencyKey: "collection-team", RequestDigest: sha256.Sum256([]byte("collection-team"))}, now)
	if err != nil {
		t.Fatal(err)
	}
	f.team = team.ID
	definition := f.definition(controlv1.Postgres)
	c := createCollectionHTTP(t, f, "managed collection", definition.Revision)
	request := collectionHTTPEnvironmentRequest(f, c, "managed member", "db.managed.internal", "5432")
	installed := createCollectionHTTPEnvironment(t, f, request)
	var digest [32]byte
	if _, err := rand.Read(digest[:]); err != nil {
		t.Fatal(err)
	}
	session, err := f.database.CreateOIDCControlSession(t.Context(), "example.test", controlstate.OIDCIdentity{Issuer: "https://identity.fixture.test", Subject: "collection-reviewer", DisplayName: "reviewer", AssertionDigest: digest, AssertionExpiry: now.Add(time.Hour)}, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := f.database.CreateTeamInvitation(t.Context(), controlstate.CreateInvitationRequest{IdentityID: owner, TeamID: f.team, IdempotencyKey: "collection-reviewer", RequestDigest: sha256.Sum256([]byte("collection-reviewer")), MemberSlug: "reviewer", InitialRole: controlstate.TeamRoleMember, ExpiresAt: now.Add(time.Hour), RetrySecret: digest[:]}, now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.database.AcceptInvitation(t.Context(), session.Identity.Identity.ID, credentials.InvitationToken(invitation.Secret), now)
	if err != nil {
		t.Fatal(err)
	}
	reviewer := f.as(session)
	checkAll := func(client *controlv1.ClientWithResponses, status int, code controlv1.ProblemCode, editors ...controlv1.RequestEditorFn) {
		t.Helper()
		create, e := client.CreateCollectionWithResponse(t.Context(), f.project, controlv1.CreateCollectionRequest{TeamId: f.team, Name: c.Name, DefaultDefinitionRevision: definition.Revision}, editors...)
		if e != nil || create == nil {
			t.Fatal(e)
		}
		assertEnvironmentHTTPProblem(t, create.StatusCode(), create.Body, status, code)
		assertCollectionHTTPNoStore(t, create.HTTPResponse)
		get, e := client.GetCollectionWithResponse(t.Context(), f.project, c.CollectionId, &controlv1.GetCollectionParams{TeamId: f.team}, editors...)
		if e != nil || get == nil {
			t.Fatal(e)
		}
		assertEnvironmentHTTPProblem(t, get.StatusCode(), get.Body, status, code)
		assertCollectionHTTPNoStore(t, get.HTTPResponse)
		list, e := client.ListCollectionsWithResponse(t.Context(), f.project, &controlv1.ListCollectionsParams{TeamId: f.team}, editors...)
		if e != nil || list == nil {
			t.Fatal(e)
		}
		assertEnvironmentHTTPProblem(t, list.StatusCode(), list.Body, status, code)
		assertCollectionHTTPNoStore(t, list.HTTPResponse)
		update, e := client.UpdateCollectionDefaultWithResponse(t.Context(), f.project, c.CollectionId, controlv1.UpdateCollectionDefaultRequest{TeamId: f.team, ExpectedRevision: 1, DefinitionRevision: definition.Revision}, editors...)
		if e != nil || update == nil {
			t.Fatal(e)
		}
		assertEnvironmentHTTPProblem(t, update.StatusCode(), update.Body, status, code)
		assertCollectionHTTPNoStore(t, update.HTTPResponse)
		replay, e := client.CreateEnvironmentWithResponse(t.Context(), f.project, request, editors...)
		if e != nil || replay == nil {
			t.Fatal(e)
		}
		assertEnvironmentHTTPProblem(t, replay.StatusCode(), replay.Body, status, code)
		assertCollectionHTTPNoStore(t, replay.HTTPResponse)
		for _, body := range [][]byte{create.Body, get.Body, list.Body, update.Body, replay.Body} {
			if strings.Contains(string(body), c.Name) || strings.Contains(string(body), "db.managed.internal") {
				t.Fatal("denied manager operation disclosed saved state")
			}
		}
	}
	checkAll(f.client, 401, controlv1.Unauthenticated, func(_ context.Context, r *http.Request) error { r.Header.Del("Authorization"); return nil })
	checkAll(reviewer.client, 403, controlv1.Forbidden)
	if _, err := f.database.SetMembershipRole(t.Context(), owner, f.team, member.ID, controlstate.TeamRoleAdmin, time.Now()); err != nil {
		t.Fatal(err)
	}
	createCollectionHTTP(t, reviewer, "created while manager", definition.Revision)
	if _, err := f.database.SetMembershipRole(t.Context(), owner, f.team, member.ID, controlstate.TeamRoleMember, time.Now()); err != nil {
		t.Fatal(err)
	}
	checkAll(reviewer.client, 403, controlv1.Forbidden)
	outsider := f.as(session)
	outsider.team = f.session.Identity.PersonalTeamID
	foreign, err := outsider.client.GetCollectionWithResponse(t.Context(), f.project, c.CollectionId, &controlv1.GetCollectionParams{TeamId: outsider.team})
	if err != nil || foreign == nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, foreign.StatusCode(), foreign.Body, 404, controlv1.NotFound)
	otherProject, otherTeam := f, f
	otherProject.project, otherTeam.team = "other-project", f.session.Identity.PersonalTeamID
	for _, scope := range []environmentHTTPFixture{otherProject, otherTeam} {
		get, err := scope.client.GetCollectionWithResponse(t.Context(), scope.project, c.CollectionId, &controlv1.GetCollectionParams{TeamId: scope.team})
		if err != nil || get == nil {
			t.Fatal(err)
		}
		assertEnvironmentHTTPProblem(t, get.StatusCode(), get.Body, 404, controlv1.NotFound)
		update, err := scope.client.UpdateCollectionDefaultWithResponse(t.Context(), scope.project, c.CollectionId, controlv1.UpdateCollectionDefaultRequest{TeamId: scope.team, ExpectedRevision: 1, DefinitionRevision: definition.Revision})
		if err != nil || update == nil {
			t.Fatal(err)
		}
		assertEnvironmentHTTPProblem(t, update.StatusCode(), update.Body, 404, controlv1.NotFound)
		bad := collectionHTTPEnvironmentRequest(scope, c, "foreign member", "db.foreign.internal", "5432")
		creation, err := scope.client.CreateEnvironmentWithResponse(t.Context(), scope.project, bad)
		if err != nil || creation == nil {
			t.Fatal(err)
		}
		assertEnvironmentHTTPProblem(t, creation.StatusCode(), creation.Body, 404, controlv1.NotFound)
	}
	missing, err := f.client.CreateCollectionWithResponse(t.Context(), "no-definition-project", controlv1.CreateCollectionRequest{TeamId: f.team, Name: "must not create project", DefaultDefinitionRevision: definition.Revision})
	if err != nil || missing == nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, missing.StatusCode(), missing.Body, 404, controlv1.NotFound)
	empty, err := f.client.ListCollectionsWithResponse(t.Context(), "no-definition-project", &controlv1.ListCollectionsParams{TeamId: f.team})
	if err != nil || empty == nil || empty.JSON200 == nil || len(*empty.JSON200) != 0 || strings.TrimSpace(string(empty.Body)) != "[]" {
		t.Fatal("empty collection list changed its existing project semantics", empty, err)
	}
	if !reflect.DeepEqual(f.get(installed.Id), installed) {
		t.Fatal("rejected authority or scope operation changed an environment")
	}
}
