package public

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type environmentHTTPFixture struct {
	t           *testing.T
	client      *controlv1.ClientWithResponses
	team        string
	project     string
	source      string
	database    *controlstate.Database
	session     controlstate.ControlSession
	transport   *runtimeHTTPTransport
	databaseURL string
}

func newEnvironmentHTTPFixture(t *testing.T) environmentHTTPFixture {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	dsn := testutil.NewDisposablePostgresDatabaseURL(t, "environments_http")
	if err := controlstate.Migrate(t.Context(), dsn); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), dsn, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	session, err := controltest.Session(t.Context(), database, "example.test", time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const server = "https://control.example.test"
	handler, err := NewHandler(Config{ControlURL: server}, DatabaseStores(database), database, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &runtimeHTTPTransport{handler: handler, peer: "10.0.0.2:1234", source: "8.8.8.8"}
	client, err := controlv1.NewClientWithResponses(server, controlv1.WithHTTPClient(&http.Client{Transport: transport}), controlv1.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
		request.Header.Set("Authorization", "Bearer "+string(session.AccessToken))
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return environmentHTTPFixture{t: t, client: client, team: session.Identity.Memberships[0].TeamID, project: "accounts", source: strings.Repeat("a", 64), database: database, session: session, transport: transport, databaseURL: dsn}
}

func (f environmentHTTPFixture) as(session controlstate.ControlSession) environmentHTTPFixture {
	f.t.Helper()
	client, err := controlv1.NewClientWithResponses("https://control.example.test", controlv1.WithHTTPClient(&http.Client{Transport: f.transport}), controlv1.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
		request.Header.Set("Authorization", "Bearer "+string(session.AccessToken))
		return nil
	}))
	if err != nil {
		f.t.Fatal(err)
	}
	f.client, f.session = client, session
	return f
}

func assertEnvironmentHTTPProblem(t *testing.T, status int, body []byte, expectedStatus int, expectedCode controlv1.ProblemCode) {
	t.Helper()
	var problem controlv1.Problem
	if err := json.Unmarshal(body, &problem); err != nil || status != expectedStatus || problem.Code != expectedCode {
		t.Fatal("unexpected environment problem contract", status, problem.Code, err)
	}
}

func (f environmentHTTPFixture) definition(protocol controlv1.ServiceProtocol) controlv1.ServiceDefinitionRevision {
	f.t.Helper()
	result, err := f.client.CreateServiceDefinitionWithResponse(f.t.Context(), f.project, controlv1.CreateServiceDefinitionRequest{
		TeamId: f.team, SourceFingerprint: f.source,
		Definition: controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{
			"database": {Protocol: protocol}, "api": {Protocol: controlv1.ServiceProtocol("http")},
		}},
	})
	if err != nil || result == nil || result.JSON200 == nil {
		f.t.Fatal("publish service definition", result, err)
	}
	if result.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
		f.t.Fatal("service definition response may be cached")
	}
	return *result.JSON200
}

func environmentHTTPTargets(host string, port string) controlv1.EnvironmentTargets {
	return controlv1.EnvironmentTargets{
		"database": {Address: new(host + ":" + port), Tls: &controlv1.EnvironmentTargetTLS{}},
		"api":      {Address: new("http://127.0.0.1:8080")},
	}
}

func (f environmentHTTPFixture) create(name string, definition int64, targets controlv1.EnvironmentTargets) controlv1.Environment {
	f.t.Helper()
	result, err := f.client.CreateEnvironmentWithResponse(f.t.Context(), f.project, controlv1.CreateEnvironmentRequest{
		TeamId: f.team, SourceFingerprint: f.source, Name: name, DefinitionRevision: new(definition),
		Targets: targets, IdempotencyKey: "environment:" + name,
	})
	if err != nil || result == nil || result.JSON200 == nil {
		f.t.Fatal("create environment", result, err)
	}
	if result.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
		f.t.Fatal("environment creation response may be cached")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(result.Body, &fields); err != nil {
		f.t.Fatal(err)
	}
	for _, private := range []string{"group_id", "members", "publisher_identity_id", "key_id", "retired"} {
		if _, ok := fields[private]; ok {
			f.t.Fatal("environment response exposed internal publisher state", private)
		}
	}
	environment := *result.JSON200
	if environment.Ref.Server != "https://control.example.test" || environment.Ref.ProjectKey != f.project || environment.Ref.EnvironmentId != environment.Id {
		f.t.Fatal("environment reference is not server-qualified", environment.Ref)
	}
	return environment
}

func (f environmentHTTPFixture) get(id string) controlv1.Environment {
	f.t.Helper()
	result, err := f.client.GetEnvironmentWithResponse(f.t.Context(), f.project, id, &controlv1.GetEnvironmentParams{TeamId: f.team})
	if err != nil || result == nil || result.JSON200 == nil {
		f.t.Fatal("get environment", result, err)
	}
	if result.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
		f.t.Fatal("environment management response may be cached")
	}
	return *result.JSON200
}

func TestIntegrationEnvironmentHTTPPinnedApply(t *testing.T) {
	f := newEnvironmentHTTPFixture(t)
	for _, invalid := range []string{
		`{"services":{"database":{"protocol":"postgres","target":"sensitive-marker"}}}`,
		`{"services":{"database":{"protocol":"postgres"}},"targets":{"database":{"address":"sensitive-marker"}}}`,
		`{"services":{"database":{"protocol":"postgres"}},"workloads":{"sensitive-marker":{}}}`,
		`{"services":{"database":{"protocol":"postgres"}},"collections":{"sensitive-marker":{}}}`,
	} {
		body := `{"team_id":"` + f.team + `","source_fingerprint":"` + f.source + `","definition":` + invalid + `}`
		result, err := f.client.CreateServiceDefinitionWithBodyWithResponse(t.Context(), f.project, "application/json", strings.NewReader(body))
		if err != nil || result == nil || result.StatusCode() != http.StatusBadRequest || strings.Contains(string(result.Body), "sensitive-marker") {
			t.Fatal("definition accepted or disclosed targets or authority", result, err)
		}
	}
	d1 := f.definition(controlv1.ServiceProtocol("postgres"))
	stagingTargets := environmentHTTPTargets("db.staging.internal", "5432")
	staging := f.create("staging", d1.Revision, stagingTargets)
	production := f.create("production", d1.Revision, environmentHTTPTargets("db.production.internal", "5432"))
	for _, environment := range []controlv1.Environment{staging, production} {
		if len(environment.Services) != 2 || environment.AppliedDefinitionRevision != d1.Revision || environment.MutationRevision < 1 {
			t.Fatal("missing applied environment facts", environment)
		}
		trust := environment.Targets["database"].Tls
		if trust == nil || trust.Hostname == nil || trust.Digest == nil || *trust.Digest == "" {
			t.Fatal("explicit empty TLS object did not capture verified target trust")
		}
	}
	stagingIDs := make(map[controlv1.ServiceID]bool, len(staging.Services))
	for _, service := range staging.Services {
		stagingIDs[service.ServiceId] = true
	}
	for _, service := range production.Services {
		if service.ServiceId == "" || stagingIDs[service.ServiceId] {
			t.Fatal("separate environments share resource identities")
		}
	}
	d2 := f.definition(controlv1.ServiceProtocol("mysql"))
	if d2.Revision == d1.Revision || !reflect.DeepEqual(f.get(production.Id), production) || !reflect.DeepEqual(f.get(staging.Id), staging) {
		t.Fatal("publishing a definition changed an existing environment")
	}
	denied, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, staging.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: staging.MutationRevision, DefinitionRevision: d2.Revision})
	if err != nil || denied == nil || denied.StatusCode() != http.StatusBadRequest || !reflect.DeepEqual(f.get(staging.Id), staging) {
		t.Fatal("protocol changed without explicit target approval", denied, err)
	}
	replacement := environmentHTTPTargets("mysql.staging.internal", "3306")
	applied, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, staging.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: staging.MutationRevision, DefinitionRevision: d2.Revision, Targets: &replacement})
	if err != nil || applied == nil || applied.JSON200 == nil {
		t.Fatal("apply staging", applied, err)
	}
	next := *applied.JSON200
	if next.MutationRevision <= staging.MutationRevision || next.AppliedDefinitionRevision != d2.Revision || next.ConfigurationHash == staging.ConfigurationHash {
		t.Fatal("staging application did not advance its own state", next)
	}
	assertEnvironmentHTTPResourceIdentity(t, staging, next)
	if !reflect.DeepEqual(f.get(production.Id), production) {
		t.Fatal("applying staging changed production")
	}
	rolled, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, staging.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: next.MutationRevision, DefinitionRevision: d1.Revision, Targets: &stagingTargets})
	if err != nil || rolled == nil || rolled.JSON200 == nil || rolled.JSON200.MutationRevision <= next.MutationRevision || rolled.JSON200.AppliedDefinitionRevision != d1.Revision {
		t.Fatal("rollback did not advance the environment application revision", rolled, err)
	}
	assertEnvironmentHTTPResourceIdentity(t, staging, *rolled.JSON200)
	if !reflect.DeepEqual(f.get(production.Id), production) {
		t.Fatal("rolling back staging changed production")
	}
	wrongProject, err := f.client.GetEnvironmentWithResponse(t.Context(), "another-project", production.Id, &controlv1.GetEnvironmentParams{TeamId: f.team})
	if err != nil || wrongProject == nil || wrongProject.StatusCode() != http.StatusNotFound || strings.Contains(string(wrongProject.Body), "db.production.internal") {
		t.Fatal("environment escaped its project scope", wrongProject, err)
	}
	unauthorized, err := f.client.GetEnvironmentWithResponse(t.Context(), f.project, production.Id, &controlv1.GetEnvironmentParams{TeamId: f.team}, func(_ context.Context, request *http.Request) error {
		request.Header.Del("Authorization")
		return nil
	})
	if err != nil || unauthorized == nil || unauthorized.StatusCode() != http.StatusUnauthorized || strings.Contains(string(unauthorized.Body), "db.production.internal") {
		t.Fatal("unauthorized environment read disclosed management state", unauthorized, err)
	}
}

func assertEnvironmentHTTPResourceIdentity(t *testing.T, before, after controlv1.Environment) {
	t.Helper()
	if before.Id != after.Id || len(before.Services) != len(after.Services) {
		t.Fatal("apply replaced the environment or its resource set")
	}
	previous := make(map[string]controlv1.EnvironmentService, len(before.Services))
	for _, service := range before.Services {
		previous[service.Service] = service
	}
	for _, service := range after.Services {
		old, ok := previous[service.Service]
		if !ok || old.ServiceId != service.ServiceId || old.Hostname != service.Hostname || old.Port != service.Port || old.Public != service.Public {
			t.Fatal("apply replaced a retained service identity or endpoint", old, service)
		}
	}
}

func TestIntegrationEnvironmentHTTPAtomicRollout(t *testing.T) {
	f := newEnvironmentHTTPFixture(t)
	d1 := f.definition(controlv1.ServiceProtocol("postgres"))
	staging := f.create("staging", d1.Revision, environmentHTTPTargets("db.staging.internal", "5432"))
	production := f.create("production", d1.Revision, environmentHTTPTargets("db.production.internal", "5432"))
	d2 := f.definition(controlv1.ServiceProtocol("mysql"))
	stagingTargets := environmentHTTPTargets("mysql.staging.internal", "3306")
	productionTargets := environmentHTTPTargets("mysql.production.internal", "3306")
	request := controlv1.ApplyEnvironmentsRequest{TeamId: f.team, Environments: []controlv1.EnvironmentApplication{
		{EnvironmentId: staging.Id, ExpectedRevision: staging.MutationRevision, DefinitionRevision: d2.Revision, Targets: &stagingTargets},
		{EnvironmentId: production.Id, ExpectedRevision: production.MutationRevision + 1, DefinitionRevision: d2.Revision, Targets: &productionTargets},
	}}
	stale, err := f.client.ApplyEnvironmentsWithResponse(t.Context(), f.project, request)
	if err != nil || stale == nil || stale.StatusCode() != http.StatusConflict {
		t.Fatal("batch accepted a stale environment precondition", stale, err)
	}
	if !reflect.DeepEqual(f.get(staging.Id), staging) || !reflect.DeepEqual(f.get(production.Id), production) {
		t.Fatal("failed batch partially applied an environment")
	}
	request.Environments[1].ExpectedRevision = production.MutationRevision
	applied, err := f.client.ApplyEnvironmentsWithResponse(t.Context(), f.project, request)
	if err != nil || applied == nil || applied.JSON200 == nil || len(*applied.JSON200) != 2 {
		t.Fatal("atomic rollout", applied, err)
	}
	for _, previous := range []controlv1.Environment{staging, production} {
		next := f.get(previous.Id)
		if next.AppliedDefinitionRevision != d2.Revision || next.MutationRevision <= previous.MutationRevision {
			t.Fatal("batch did not update the selected environment", next)
		}
		assertEnvironmentHTTPResourceIdentity(t, previous, next)
	}
}

func TestIntegrationEnvironmentHTTPIdempotencyAndRetirement(t *testing.T) {
	f := newEnvironmentHTTPFixture(t)
	d1 := f.definition(controlv1.ServiceProtocol("postgres"))
	if reused := f.definition(controlv1.ServiceProtocol("postgres")); reused.Revision != d1.Revision || reused.ConfigurationHash != d1.ConfigurationHash {
		t.Fatal("identical service definition allocated a new revision", reused)
	}
	targets := environmentHTTPTargets("db.customer.internal", "5432")
	created := f.create("customer_42", d1.Revision, targets)
	replayed := f.create("customer_42", d1.Revision, targets)
	if !reflect.DeepEqual(created, replayed) {
		t.Fatal("identical create did not return the same environment")
	}
	list, err := f.client.ListEnvironmentsWithResponse(t.Context(), f.project, &controlv1.ListEnvironmentsParams{TeamId: f.team})
	if err != nil || list == nil || list.JSON200 == nil || len(*list.JSON200) != 1 {
		t.Fatal("creation replay allocated another environment", list, err)
	}
	changed, err := f.client.CreateEnvironmentWithResponse(t.Context(), f.project, controlv1.CreateEnvironmentRequest{TeamId: f.team, SourceFingerprint: f.source, Name: "different-customer", DefinitionRevision: new(d1.Revision), Targets: targets, IdempotencyKey: "environment:customer_42"})
	if err != nil || changed == nil {
		t.Fatal("changed creation retry failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, changed.StatusCode(), changed.Body, http.StatusConflict, controlv1.Conflict)
	stale, err := f.client.RetireEnvironmentWithResponse(t.Context(), f.project, created.Id, &controlv1.RetireEnvironmentParams{TeamId: f.team, ExpectedRevision: created.MutationRevision + 1})
	if err != nil || stale == nil {
		t.Fatal("stale retirement failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, stale.StatusCode(), stale.Body, http.StatusConflict, controlv1.Conflict)
	if !reflect.DeepEqual(f.get(created.Id), created) {
		t.Fatal("stale retirement changed the environment")
	}
	retired, err := f.client.RetireEnvironmentWithResponse(t.Context(), f.project, created.Id, &controlv1.RetireEnvironmentParams{TeamId: f.team, ExpectedRevision: created.MutationRevision})
	if err != nil || retired == nil || retired.StatusCode() != http.StatusNoContent {
		t.Fatal("retire environment", retired, err)
	}
	conflict, err := f.client.CreateEnvironmentWithResponse(t.Context(), f.project, controlv1.CreateEnvironmentRequest{TeamId: f.team, SourceFingerprint: f.source, Name: "customer_42", DefinitionRevision: new(d1.Revision), Targets: targets, IdempotencyKey: "environment:customer_42"})
	if err != nil || conflict == nil || conflict.StatusCode() != http.StatusConflict || conflict.JSON200 != nil {
		t.Fatal("retired creation key recreated an environment", conflict, err)
	}
	get, err := f.client.GetEnvironmentWithResponse(t.Context(), f.project, created.Id, &controlv1.GetEnvironmentParams{TeamId: f.team})
	if err != nil || get == nil {
		t.Fatal("retired lookup failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, get.StatusCode(), get.Body, http.StatusNotFound, controlv1.NotFound)
	list, err = f.client.ListEnvironmentsWithResponse(t.Context(), f.project, &controlv1.ListEnvironmentsParams{TeamId: f.team})
	if err != nil || list == nil || list.JSON200 == nil || len(*list.JSON200) != 0 {
		t.Fatal("retired environment remained active in the list", err)
	}
}

func TestIntegrationEnvironmentHTTPRejectsNullAndPartialConversion(t *testing.T) {
	f := newEnvironmentHTTPFixture(t)
	definition := f.definition(controlv1.ServiceProtocol("postgres"))
	staging := f.create("staging", definition.Revision, environmentHTTPTargets("db.staging.internal", "5432"))
	production := f.create("production", definition.Revision, environmentHTTPTargets("db.production.internal", "5432"))
	encode := func(value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	unchanged := func() {
		t.Helper()
		if !reflect.DeepEqual(f.get(staging.Id), staging) || !reflect.DeepEqual(f.get(production.Id), production) {
			t.Fatal("rejected JSON or partial conversion changed an environment")
		}
	}
	for _, tls := range []any{nil, map[string]any{"hostname": nil}, map[string]any{"digest": nil}, map[string]any{"ca_pem": nil}} {
		body := map[string]any{
			"team_id": f.team, "expected_revision": staging.MutationRevision, "definition_revision": definition.Revision,
			"targets": map[string]any{"database": map[string]any{"address": "db.staging.internal:5432", "tls": tls}, "api": map[string]any{"address": "http://127.0.0.1:8080"}},
		}
		result, err := f.client.ApplyEnvironmentWithBodyWithResponse(t.Context(), f.project, staging.Id, "application/json", strings.NewReader(encode(body)))
		if err != nil || result == nil {
			t.Fatal("null TLS request failed without an HTTP response", err)
		}
		assertEnvironmentHTTPProblem(t, result.StatusCode(), result.Body, http.StatusBadRequest, controlv1.InvalidRequest)
		unchanged()
	}
	nullTargets := encode(map[string]any{"team_id": f.team, "expected_revision": staging.MutationRevision, "definition_revision": definition.Revision, "targets": nil})
	result, err := f.client.ApplyEnvironmentWithBodyWithResponse(t.Context(), f.project, staging.Id, "application/json", strings.NewReader(nullTargets))
	if err != nil || result == nil {
		t.Fatal("null targets request failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, result.StatusCode(), result.Body, http.StatusBadRequest, controlv1.InvalidRequest)
	unchanged()
	first := map[string]any{"environment_id": staging.Id, "expected_revision": staging.MutationRevision, "definition_revision": definition.Revision, "targets": environmentHTTPTargets("replacement.staging.internal", "5432")}
	second := map[string]any{"environment_id": production.Id, "expected_revision": production.MutationRevision, "definition_revision": definition.Revision}
	for _, badTargets := range []any{
		nil,
		map[string]any{"database": map[string]any{"address": "replacement.production.internal:5432", "tls": map[string]any{"ca_pem": "not a CA certificate"}}},
	} {
		second["targets"] = badTargets
		batch := encode(map[string]any{"team_id": f.team, "environments": []any{first, second}})
		rolled, err := f.client.ApplyEnvironmentsWithBodyWithResponse(t.Context(), f.project, "application/json", strings.NewReader(batch))
		if err != nil || rolled == nil {
			t.Fatal("invalid batch conversion failed without an HTTP response", err)
		}
		assertEnvironmentHTTPProblem(t, rolled.StatusCode(), rolled.Body, http.StatusBadRequest, controlv1.InvalidRequest)
		unchanged()
	}
	oversized := strings.Repeat(" ", int(environmentRequestBodyLimit)+1) + nullTargets
	result, err = f.client.ApplyEnvironmentWithBodyWithResponse(t.Context(), f.project, staging.Id, "application/json", strings.NewReader(oversized))
	if err != nil || result == nil {
		t.Fatal("oversized request failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, result.StatusCode(), result.Body, http.StatusBadRequest, controlv1.InvalidRequest)
	unchanged()
	items := make([]controlv1.EnvironmentApplication, 129)
	for index := range items {
		items[index] = controlv1.EnvironmentApplication{EnvironmentId: staging.Id, ExpectedRevision: staging.MutationRevision, DefinitionRevision: definition.Revision}
	}
	tooMany, err := f.client.ApplyEnvironmentsWithResponse(t.Context(), f.project, controlv1.ApplyEnvironmentsRequest{TeamId: f.team, Environments: items})
	if err != nil || tooMany == nil {
		t.Fatal("oversized batch failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, tooMany.StatusCode(), tooMany.Body, http.StatusBadRequest, controlv1.InvalidRequest)
	unchanged()
	targets := make(controlv1.EnvironmentTargets, 129)
	for index := range 129 {
		targets["service"+strconv.Itoa(index)] = controlv1.EnvironmentTarget{Address: new("127.0.0.1:8080")}
	}
	tooManyTargets, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, staging.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: staging.MutationRevision, DefinitionRevision: definition.Revision, Targets: &targets})
	if err != nil || tooManyTargets == nil {
		t.Fatal("oversized target map failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, tooManyTargets.StatusCode(), tooManyTargets.Body, http.StatusBadRequest, controlv1.InvalidRequest)
	unchanged()
	missingKey, err := f.client.CreateEnvironmentWithBodyWithResponse(t.Context(), f.project, "application/json", strings.NewReader(encode(map[string]any{"team_id": f.team, "source_fingerprint": f.source, "name": "without-key", "definition_revision": definition.Revision, "targets": environmentHTTPTargets("db.unapproved.internal", "5432")})))
	if err != nil || missingKey == nil {
		t.Fatal("missing creation key failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, missingKey.StatusCode(), missingKey.Body, http.StatusBadRequest, controlv1.InvalidRequest)
	list, err := f.client.ListEnvironmentsWithResponse(t.Context(), f.project, &controlv1.ListEnvironmentsParams{TeamId: f.team})
	if err != nil || list == nil || list.JSON200 == nil || len(*list.JSON200) != 2 {
		t.Fatal("invalid creation allocated another environment", err)
	}
}

func TestIntegrationEnvironmentHTTPUsesCurrentManagerAuthority(t *testing.T) {
	f := newEnvironmentHTTPFixture(t)
	owner := f.session.Identity.Identity.ID
	now := time.Now()
	team, err := f.database.CreateTeam(t.Context(), controlstate.CreateTeamRequest{IdentityID: owner, DisplayName: "environments", IdempotencyKey: "environment-team", RequestDigest: sha256.Sum256([]byte("environment-team"))}, now)
	if err != nil {
		t.Fatal(err)
	}
	f.team = team.ID
	definition := f.definition(controlv1.ServiceProtocol("postgres"))
	production := f.create("production", definition.Revision, environmentHTTPTargets("db.production.internal", "5432"))
	var digest [32]byte
	if _, err := rand.Read(digest[:]); err != nil {
		t.Fatal(err)
	}
	memberSession, err := f.database.CreateOIDCControlSession(t.Context(), "example.test", controlstate.OIDCIdentity{Issuer: "https://identity.fixture.test", Subject: "environment-reviewer", DisplayName: "reviewer", AssertionDigest: digest, AssertionExpiry: now.Add(time.Hour)}, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := f.database.CreateTeamInvitation(t.Context(), controlstate.CreateInvitationRequest{IdentityID: owner, TeamID: f.team, IdempotencyKey: "environment-reviewer", RequestDigest: sha256.Sum256([]byte("environment-reviewer")), MemberSlug: "reviewer", InitialRole: controlstate.TeamRoleMember, ExpiresAt: now.Add(time.Hour), RetrySecret: digest[:]}, now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.database.AcceptInvitation(t.Context(), memberSession.Identity.Identity.ID, credentials.InvitationToken(invitation.Secret), now)
	if err != nil {
		t.Fatal(err)
	}
	reviewer := f.as(memberSession)
	checkDenied := func() {
		t.Helper()
		get, err := reviewer.client.GetEnvironmentWithResponse(t.Context(), f.project, production.Id, &controlv1.GetEnvironmentParams{TeamId: f.team})
		if err != nil || get == nil {
			t.Fatal("non-manager lookup failed without an HTTP response", err)
		}
		assertEnvironmentHTTPProblem(t, get.StatusCode(), get.Body, http.StatusForbidden, controlv1.Forbidden)
		apply, err := reviewer.client.ApplyEnvironmentWithResponse(t.Context(), f.project, production.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: production.MutationRevision, DefinitionRevision: definition.Revision})
		if err != nil || apply == nil {
			t.Fatal("non-manager mutation failed without an HTTP response", err)
		}
		assertEnvironmentHTTPProblem(t, apply.StatusCode(), apply.Body, http.StatusForbidden, controlv1.Forbidden)
		if strings.Contains(string(get.Body), "db.production.internal") || !reflect.DeepEqual(f.get(production.Id), production) {
			t.Fatal("non-manager accessed or changed protected environment state")
		}
	}
	checkDenied()
	if _, err := f.database.SetMembershipRole(t.Context(), owner, f.team, member.ID, controlstate.TeamRoleAdmin, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reviewer.get(production.Id), production) {
		t.Fatal("current manager could not read the environment")
	}
	if _, err := f.database.SetMembershipRole(t.Context(), owner, f.team, member.ID, controlstate.TeamRoleMember, time.Now()); err != nil {
		t.Fatal(err)
	}
	checkDenied()
	foreign, err := reviewer.client.GetEnvironmentWithResponse(t.Context(), f.project, production.Id, &controlv1.GetEnvironmentParams{TeamId: f.session.Identity.PersonalTeamID})
	if err != nil || foreign == nil {
		t.Fatal("foreign-team lookup failed without an HTTP response", err)
	}
	assertEnvironmentHTTPProblem(t, foreign.StatusCode(), foreign.Body, http.StatusNotFound, controlv1.NotFound)
}
