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

type environmentPublisherGrantHTTPFixture struct {
	environmentHTTPFixture
	environment  controlv1.Environment
	member       controlstate.EnvironmentPublisher
	lease        controlstate.EnvironmentPublisherLease
	inspect      *pgx.Conn
	api, metrics string
}

func newEnvironmentPublisherGrantHTTPFixture(t *testing.T) environmentPublisherGrantHTTPFixture {
	t.Helper()
	f := newEnvironmentHTTPFixture(t)
	now := time.Now()
	team, err := f.database.CreateTeam(t.Context(), controlstate.CreateTeamRequest{IdentityID: f.session.Identity.Identity.ID, DisplayName: "http-grant-team", IdempotencyKey: "http-grant-team", RequestDigest: sha256.Sum256([]byte("http-grant-team"))}, now)
	if err != nil {
		t.Fatal(err)
	}
	f.team = team.ID
	definition := func(services map[string]controlv1.ServiceDefinitionService) controlv1.ServiceDefinitionRevision {
		t.Helper()
		result, err := f.client.CreateServiceDefinitionWithResponse(t.Context(), f.project, controlv1.CreateServiceDefinitionRequest{TeamId: f.team, SourceFingerprint: f.source, Definition: controlv1.ServiceDefinition{Services: services}})
		if err != nil || result.JSON200 == nil {
			t.Fatal("create HTTP grant definition", result, err)
		}
		return *result.JSON200
	}
	initial := definition(map[string]controlv1.ServiceDefinitionService{"api": {Protocol: "http"}})
	environment := f.create("production", initial.Revision, controlv1.EnvironmentTargets{"api": {Address: new("api.internal:3000")}})
	inspect, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := inspect.Close(finish); err != nil {
			t.Error(err)
		}
	})
	manager, err := f.database.AuthenticateEnvironmentPublisherManager(t.Context(), f.session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := f.database.IssueEnvironmentPublisherEnrollment(t.Context(), controlstate.IssueEnvironmentPublisherEnrollmentRequest{
		EnvironmentPublisherSelection: controlstate.EnvironmentPublisherSelection{TeamID: f.team, ProjectKey: f.project, EnvironmentID: environment.Id, Manager: manager},
		ExpectedRevision:              environment.MutationRevision, ExpectedConfigurationHash: environment.ConfigurationHash, Services: []string{"api"}, MaxMembers: 1, Lifetime: time.Hour, Now: now,
	})
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
	assertion, err := publisherproof.Sign(member.PublisherIdentityID, member.KeyID, member.EnvironmentID, audience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.database.AcquireEnvironmentPublisherLease(t.Context(), member.PublisherIdentityID, member.EnvironmentID, assertion, audience, now)
	if err != nil {
		t.Fatal(err)
	}
	next := definition(map[string]controlv1.ServiceDefinitionService{"api": {Protocol: "http"}, "metrics": {Protocol: "http"}})
	targets := controlv1.EnvironmentTargets{"api": {Address: new("api.internal:3000")}, "metrics": {Address: new("metrics.internal:9090")}}
	updated, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: environment.MutationRevision, DefinitionRevision: next.Revision, Targets: &targets})
	if err != nil || updated.JSON200 == nil {
		t.Fatal("apply added service", updated, err)
	}
	result := environmentPublisherGrantHTTPFixture{environmentHTTPFixture: f, environment: *updated.JSON200, member: member, lease: lease, inspect: inspect}
	for _, service := range result.environment.Services {
		if service.Service == "api" {
			result.api = service.ServiceId
		} else if service.Service == "metrics" {
			result.metrics = service.ServiceId
		}
	}
	if result.api != environment.Services[0].ServiceId || result.metrics == "" {
		t.Fatal("growth changed retained service identity or failed to add metrics")
	}
	return result
}

func (f environmentPublisherGrantHTTPFixture) body(key string) controlv1.AuthorizeEnvironmentPublisherServiceRequest {
	return controlv1.AuthorizeEnvironmentPublisherServiceRequest{TeamId: f.team, ExpectedRevision: f.environment.MutationRevision, ExpectedConfigurationHash: f.environment.ConfigurationHash, ExpectedPreviousGrantId: nil, IdempotencyKey: key}
}

func (f environmentPublisherGrantHTTPFixture) revokeParams() *controlv1.RevokeEnvironmentPublisherGrantParams {
	return &controlv1.RevokeEnvironmentPublisherGrantParams{TeamId: f.team, ExpectedRevision: f.environment.MutationRevision, ExpectedConfigurationHash: f.environment.ConfigurationHash}
}

func assertEnvironmentPublisherGrantHTTPNoStore(t *testing.T, header http.Header) {
	t.Helper()
	if header.Get("Cache-Control") != "no-store" {
		t.Fatal("environment publisher grant response may be cached")
	}
}

func (f environmentPublisherGrantHTTPFixture) get(t *testing.T, service string) controlv1.EnvironmentPublisherGrantState {
	t.Helper()
	response, err := f.client.GetEnvironmentPublisherGrantWithResponse(t.Context(), f.project, f.environment.Id, f.member.PublisherIdentityID, service, &controlv1.GetEnvironmentPublisherGrantParams{TeamId: f.team})
	if err != nil || response.JSON200 == nil {
		t.Fatal("inspect exact environment publisher grant", response, err)
	}
	assertEnvironmentPublisherGrantHTTPNoStore(t, response.HTTPResponse.Header)
	return *response.JSON200
}

func (f environmentPublisherGrantHTTPFixture) assertAbsent(t *testing.T) {
	t.Helper()
	var grants, receipts int
	err := f.inspect.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1 AND service_id=$2),
		(SELECT count(*) FROM control.environment_publisher_grant_requests WHERE environment_id=$3)`, f.member.PublisherIdentityID, f.metrics, f.environment.Id).Scan(&grants, &receipts)
	if err != nil || grants != 0 || receipts != 0 {
		t.Fatal("denied HTTP request saved grants or intent", grants, receipts, err)
	}
}

func TestIntegrationEnvironmentPublisherGrantHTTPRoundTrip(t *testing.T) {
	f := newEnvironmentPublisherGrantHTTPFixture(t)
	f.assertAbsent(t)
	before := f.get(t, f.api)
	absent := f.get(t, f.metrics)
	encoded, err := json.Marshal(absent)
	if err != nil || absent.Grant != nil || !strings.Contains(string(encoded), `"grant":null`) {
		t.Fatal("inspect did not preserve the explicit null mapping", absent, err)
	}
	body := f.body("metrics-first-intent")
	post := func(body controlv1.AuthorizeEnvironmentPublisherServiceRequest) *controlv1.AuthorizeEnvironmentPublisherServiceResponse {
		t.Helper()
		response, err := f.client.AuthorizeEnvironmentPublisherServiceWithResponse(t.Context(), f.project, f.environment.Id, f.member.PublisherIdentityID, f.metrics, body, func(_ context.Context, request *http.Request) error {
			request.Host = "untrusted-origin.invalid"
			return nil
		})
		if err != nil || response == nil {
			t.Fatal(err)
		}
		assertEnvironmentPublisherGrantHTTPNoStore(t, response.HTTPResponse.Header)
		for _, private := range []string{"untrusted-origin.invalid", `"group_id"`, `"key_id"`, `"access_token"`, "metrics.internal"} {
			if strings.Contains(string(response.Body), private) {
				t.Fatal("grant response exposed unrelated origin or private runtime facts", private)
			}
		}
		return response
	}
	created := post(body)
	if created.StatusCode() != http.StatusCreated || created.JSON201 == nil || created.JSON201.Grant == nil {
		t.Fatal("explicit authorization did not create a grant", created)
	}
	first := *created.JSON201
	if first.EnvironmentId != f.environment.Id || first.PublisherIdentityId != f.member.PublisherIdentityID || first.ServiceId != f.metrics || first.TeamId != f.team || first.ProjectKey != f.project || first.MutationRevision != f.environment.MutationRevision || first.ConfigurationHash != f.environment.ConfigurationHash || first.Grant.CreatedByIdentityId == nil || *first.Grant.CreatedByIdentityId != f.session.Identity.Identity.ID {
		t.Fatal("wire scope, provenance or application fence was wrong", first)
	}
	replay := post(body)
	if replay.StatusCode() != http.StatusOK || replay.JSON200 == nil || !reflect.DeepEqual(*replay.JSON200, first) {
		t.Fatal("active receipt did not return stable 200 facts", replay)
	}
	if err := f.database.AcknowledgeEnvironmentPublisher(t.Context(), f.lease.AccessToken, controlstate.EnvironmentPublication{EnvironmentID: f.environment.Id, MutationRevision: f.environment.MutationRevision, ConfigurationHash: f.environment.ConfigurationHash}, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	noop := f.body("active-noop-intent")
	noop.ExpectedPreviousGrantId = &first.Grant.Id
	active := post(noop)
	if active.StatusCode() != http.StatusOK || active.JSON200 == nil || !reflect.DeepEqual(*active.JSON200, first) {
		t.Fatal("fresh active no-op changed issuer or grant", active)
	}
	var healthy bool
	if err := f.inspect.QueryRow(t.Context(), `SELECT healthy FROM control.publisher_group_members WHERE publisher_identity_id=$1`, f.member.PublisherIdentityID).Scan(&healthy); err != nil || !healthy {
		t.Fatal("active HTTP no-op invalidated publisher health", err)
	}
	changed := body
	changed.ExpectedPreviousGrantId = &first.Grant.Id
	conflict := post(changed)
	assertEnvironmentHTTPProblem(t, conflict.StatusCode(), conflict.Body, http.StatusConflict, controlv1.Conflict)
	stale := f.body("stale-application")
	stale.ExpectedRevision--
	conflict = post(stale)
	assertEnvironmentHTTPProblem(t, conflict.StatusCode(), conflict.Body, http.StatusConflict, controlv1.Conflict)
	deleteGrant := func(id string) {
		t.Helper()
		response, err := f.client.RevokeEnvironmentPublisherGrantWithResponse(t.Context(), f.project, f.environment.Id, f.member.PublisherIdentityID, f.metrics, id, f.revokeParams())
		if err != nil || response.StatusCode() != http.StatusNoContent || len(response.Body) != 0 {
			t.Fatal("revoke exact grant", response, err)
		}
		assertEnvironmentPublisherGrantHTTPNoStore(t, response.HTTPResponse.Header)
	}
	deleteGrant(first.Grant.Id)
	tombstone := f.get(t, f.metrics)
	if tombstone.Grant == nil || tombstone.Grant.Id != first.Grant.Id || tombstone.Grant.RevokedAt == nil {
		t.Fatal("inspect lost the exact revoked tombstone", tombstone)
	}
	conflict = post(body)
	assertEnvironmentHTTPProblem(t, conflict.StatusCode(), conflict.Body, http.StatusConflict, controlv1.Conflict)
	fresh := f.body("metrics-second-intent")
	conflict = post(fresh)
	assertEnvironmentHTTPProblem(t, conflict.StatusCode(), conflict.Body, http.StatusConflict, controlv1.Conflict)
	fresh.ExpectedPreviousGrantId = &first.Grant.Id
	second := post(fresh)
	if second.JSON201 == nil || second.JSON201.Grant == nil || second.JSON201.Grant.Id == first.Grant.Id {
		t.Fatal("new deliberate intent did not create a fresh grant", second)
	}
	deleteGrant(first.Grant.Id)
	if current := f.get(t, f.metrics); !reflect.DeepEqual(current, *second.JSON201) || current.Grant.RevokedAt != nil {
		t.Fatal("old DELETE changed the replacement grant", current)
	}
	if after := f.get(t, f.api); !reflect.DeepEqual(after, before) {
		t.Fatal("metrics operations changed unrelated api grant facts", after, before)
	}
	conflict = post(body)
	assertEnvironmentHTTPProblem(t, conflict.StatusCode(), conflict.Body, http.StatusConflict, controlv1.Conflict)
	assignments, err := f.database.GetEnvironmentPublisherAssignments(t.Context(), f.lease.AccessToken, time.Now())
	if err != nil || assignments.Publisher != f.member || len(assignments.Services) != 2 {
		t.Fatal("HTTP authorization replaced publisher identity/key or lost assignments", err)
	}
}

func (f environmentPublisherGrantHTTPFixture) sessionForRole(t *testing.T, role controlstate.TeamRole) controlstate.ControlSession {
	t.Helper()
	name, now := rand.Text(), time.Now()
	digest := sha256.Sum256([]byte(name))
	session, err := f.database.CreateOIDCControlSession(t.Context(), "example.test", controlstate.OIDCIdentity{Issuer: "https://identity.fixture.test", Subject: name, DisplayName: name, AssertionDigest: digest, AssertionExpiry: now.Add(time.Hour)}, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := f.database.CreateTeamInvitation(t.Context(), controlstate.CreateInvitationRequest{IdentityID: f.session.Identity.Identity.ID, TeamID: f.team, IdempotencyKey: name, RequestDigest: digest,
		MemberSlug: strings.ToLower(name[:12]), InitialRole: role, ExpiresAt: now.Add(time.Hour), RetrySecret: digest[:]}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AcceptInvitation(t.Context(), session.Identity.Identity.ID, credentials.InvitationToken(invitation.Secret), now); err != nil {
		t.Fatal(err)
	}
	return session
}

func TestIntegrationEnvironmentPublisherGrantHTTPAuthAndScope(t *testing.T) {
	f := newEnvironmentPublisherGrantHTTPFixture(t)
	for _, authorization := range []string{"", "Bearer mpc_not-a-manager", "Bearer pgl_not-a-manager", "Bearer sensitive-marker"} {
		response, err := f.client.AuthorizeEnvironmentPublisherServiceWithResponse(t.Context(), f.project, f.environment.Id, f.member.PublisherIdentityID, f.metrics, f.body("unauthenticated"), func(_ context.Context, request *http.Request) error {
			request.Header.Set("Authorization", authorization)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		assertEnvironmentHTTPProblem(t, response.StatusCode(), response.Body, http.StatusUnauthorized, controlv1.Unauthenticated)
		assertEnvironmentPublisherGrantHTTPNoStore(t, response.HTTPResponse.Header)
		if response.HTTPResponse.Header.Get("WWW-Authenticate") == "" || strings.Contains(string(response.Body), "sensitive-marker") {
			t.Fatal("authentication problem omitted challenge or leaked a credential")
		}
	}
	member := f.as(f.sessionForRole(t, controlstate.TeamRoleMember))
	denied, err := member.client.AuthorizeEnvironmentPublisherServiceWithResponse(t.Context(), f.project, f.environment.Id, f.member.PublisherIdentityID, f.metrics, f.body("not-a-manager"))
	if err != nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, denied.StatusCode(), denied.Body, http.StatusForbidden, controlv1.Forbidden)
	foreign, err := f.client.GetEnvironmentPublisherGrantWithResponse(t.Context(), "another-project", f.environment.Id, f.member.PublisherIdentityID, f.metrics, &controlv1.GetEnvironmentPublisherGrantParams{TeamId: f.team})
	if err != nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, foreign.StatusCode(), foreign.Body, http.StatusNotFound, controlv1.NotFound)
	foreign, err = f.client.GetEnvironmentPublisherGrantWithResponse(t.Context(), f.project, f.environment.Id, f.member.PublisherIdentityID, f.metrics, &controlv1.GetEnvironmentPublisherGrantParams{TeamId: f.session.Identity.PersonalTeamID})
	if err != nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, foreign.StatusCode(), foreign.Body, http.StatusNotFound, controlv1.NotFound)
	f.assertAbsent(t)
	retired, err := f.client.RetireEnvironmentWithResponse(t.Context(), f.project, f.environment.Id, &controlv1.RetireEnvironmentParams{TeamId: f.team, ExpectedRevision: f.environment.MutationRevision})
	if err != nil || retired.StatusCode() != http.StatusNoContent {
		t.Fatal(retired, err)
	}
	response, err := f.client.GetEnvironmentPublisherGrantWithResponse(t.Context(), f.project, f.environment.Id, f.member.PublisherIdentityID, f.metrics, &controlv1.GetEnvironmentPublisherGrantParams{TeamId: f.team})
	if err != nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, response.StatusCode(), response.Body, http.StatusConflict, controlv1.Conflict)
}

func TestIntegrationEnvironmentPublisherGrantHTTPAuthorityAfterWait(t *testing.T) {
	for _, change := range []string{"manager-demoted", "session-rotated", "session-revoked", "fixed-deadline"} {
		t.Run(change, func(t *testing.T) {
			f := newEnvironmentPublisherGrantHTTPFixture(t)
			actor := f.session
			if change == "manager-demoted" {
				actor = f.sessionForRole(t, controlstate.TeamRoleAdmin)
			}
			client := f.as(actor).client
			deadline := time.Now().Add(2 * time.Second).Truncate(time.Microsecond)
			if change == "fixed-deadline" {
				if _, err := f.inspect.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, actor.SessionID, deadline); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			connection, err := pgx.Connect(ctx, f.databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				finish, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_ = connection.Close(finish)
			}()
			gate, err := connection.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				finish, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_ = gate.Rollback(finish)
			}()
			if change == "manager-demoted" {
				_, err = gate.Exec(ctx, `SELECT id FROM control.teams WHERE id=$1 FOR UPDATE`, f.team)
			} else {
				_, err = gate.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, f.metrics)
			}
			if err != nil {
				t.Fatal(err)
			}
			type outcome struct {
				response *controlv1.AuthorizeEnvironmentPublisherServiceResponse
				err      error
			}
			done, joined := make(chan outcome, 1), make(chan struct{})
			go func() {
				defer close(joined)
				response, err := client.AuthorizeEnvironmentPublisherServiceWithResponse(ctx, f.project, f.environment.Id, f.member.PublisherIdentityID, f.metrics, f.body("blocked-http-intent"))
				done <- outcome{response, err}
			}()
			defer func() {
				cancel()
				select {
				case <-joined:
				case <-time.After(5 * time.Second):
					t.Error("HTTP worker did not join")
				}
			}()
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				var blocked bool
				err := f.inspect.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))`, int32(connection.PgConn().PID())).Scan(&blocked)
				if err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				select {
				case <-tick.C:
				case result := <-done:
					t.Fatal("HTTP request finished before its observed lock wait", result.response, result.err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			switch change {
			case "manager-demoted":
				_, err = gate.Exec(ctx, `UPDATE control.team_memberships SET role='member' WHERE team_id=$1 AND identity_id=$2`, f.team, actor.Identity.Identity.ID)
			case "session-rotated":
				_, err = f.database.RefreshControlSession(ctx, actor.RefreshToken, time.Hour, time.Now())
			case "session-revoked":
				err = f.database.RevokeControlSession(ctx, controlstate.ControlPrincipal{SessionID: actor.SessionID, IdentityID: actor.Identity.Identity.ID}, time.Now())
			case "fixed-deadline":
				_, err = f.inspect.Exec(ctx, `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, actor.SessionID, time.Now().Add(time.Hour))
				timer := time.NewTimer(time.Until(deadline))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var result outcome
			select {
			case result = <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if result.err != nil || result.response == nil {
				t.Fatal(result.err)
			}
			status, code := http.StatusUnauthorized, controlv1.Unauthenticated
			if change == "manager-demoted" {
				status, code = http.StatusForbidden, controlv1.Forbidden
			}
			assertEnvironmentHTTPProblem(t, result.response.StatusCode(), result.response.Body, status, code)
			assertEnvironmentPublisherGrantHTTPNoStore(t, result.response.HTTPResponse.Header)
			f.assertAbsent(t)
		})
	}
}
