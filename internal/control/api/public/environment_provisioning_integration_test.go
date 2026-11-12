package public

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type environmentProvisioningHTTPFixture struct {
	environmentHTTPFixture
	machine    controlstate.MachineIdentity
	grant      controlstate.ProvisioningGrant
	key        ed25519.PrivateKey
	collection controlstate.Collection
	definition controlv1.ServiceDefinitionRevision
	inspect    *pgx.Conn
}

func newEnvironmentProvisioningHTTPFixture(t *testing.T) environmentProvisioningHTTPFixture {
	t.Helper()
	f := newEnvironmentHTTPFixture(t)
	definition, err := f.client.CreateServiceDefinitionWithResponse(t.Context(), f.project, controlv1.CreateServiceDefinitionRequest{TeamId: f.team, SourceFingerprint: f.source, Definition: controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{"api": {Protocol: "http"}}}})
	if err != nil || definition.JSON200 == nil {
		t.Fatal(definition, err)
	}
	collection, err := f.database.CreateCollection(t.Context(), controlstate.CreateCollectionRequest{TeamID: f.team, ProjectKey: f.project, ActorID: f.session.Identity.Identity.ID, Name: "customers", DefaultDefinitionRevision: definition.JSON200.Revision, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := f.database.RegisterMachineIdentity(t.Context(), controlstate.RegisterMachineRequest{TeamID: f.team, ActorID: f.session.Identity.Identity.ID, Name: "onboarding", ProofKind: "signing_key", KeyID: "first", PublicKey: public}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.database.CreateProvisioningGrant(t.Context(), controlstate.ProvisioningGrant{MachineID: machine.ID, TeamID: f.team, ProjectKey: f.project, Scope: controlstate.EnvironmentPermissionScope{CollectionID: collection.ID, IncludeFutureEnvironments: new(true)}, Services: []string{"api"}, Operations: []controlstate.ProvisioningOperation{controlstate.ProvisioningCreate, controlstate.ProvisioningRead, controlstate.ProvisioningUpdate, controlstate.ProvisioningEnroll, controlstate.ProvisioningRevokeMember, controlstate.ProvisioningRetire}, MaxEnrollmentMembers: 2, MaxEnrollmentSeconds: 600, EnrollmentBudget: 3, ExpiresAt: time.Now().Add(time.Hour)}, f.session.Identity.Identity.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
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
	return environmentProvisioningHTTPFixture{environmentHTTPFixture: f, machine: machine, grant: grant, key: private, collection: collection, definition: *definition.JSON200, inspect: inspect}
}

func (f environmentProvisioningHTTPFixture) token(op controlstate.ProvisioningOperation) string {
	f.t.Helper()
	const audience = "https://control.example.test/v1/provisioning-sessions/exchange"
	now := time.Now()
	assertion, err := publisherproof.Sign(f.machine.ID, "first", machineproof.Provisioning(f.grant.ID, string(op)), audience, f.key, now)
	if err != nil {
		f.t.Fatal(err)
	}
	session, err := f.database.ExchangeProvisioning(f.t.Context(), f.machine.ID, f.grant.ID, op, controlstate.MachineProof{Assertion: assertion}, audience, now)
	if err != nil {
		f.t.Fatal(err)
	}
	return session.Credential
}

func provisioningBearer(token string) controlv1.RequestEditorFn {
	return func(_ context.Context, request *http.Request) error {
		request.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
}

func (f environmentProvisioningHTTPFixture) creation(name string) controlv1.CreateEnvironmentRequest {
	return controlv1.CreateEnvironmentRequest{TeamId: f.team, SourceFingerprint: f.source, Name: name, IdempotencyKey: "customer/" + name, CollectionId: new(f.collection.ID), ExpectedCollectionRevision: new(f.collection.MutationRevision), Targets: controlv1.EnvironmentTargets{"api": {Address: new("api.customer.internal:3000")}}}
}

func (f environmentProvisioningHTTPFixture) createMachine(name string) controlv1.Environment {
	f.t.Helper()
	r, err := f.client.CreateEnvironmentWithResponse(f.t.Context(), f.project, f.creation(name), provisioningBearer(f.token(controlstate.ProvisioningCreate)))
	if err != nil || r.JSON200 == nil {
		f.t.Fatal("machine create", r, err)
	}
	assertEnvironmentPublisherGrantHTTPNoStore(f.t, r.HTTPResponse.Header)
	return *r.JSON200
}

func (f environmentProvisioningHTTPFixture) used() int {
	f.t.Helper()
	var used int
	if err := f.inspect.QueryRow(f.t.Context(), `SELECT enrollment_used FROM control.machine_provisioning_grants WHERE id=$1`, f.grant.ID).Scan(&used); err != nil {
		f.t.Fatal(err)
	}
	return used
}

func TestIntegrationEnvironmentProvisioningHTTPExactScopeAndIndependentProduction(t *testing.T) {
	f := newEnvironmentProvisioningHTTPFixture(t)
	production := f.create("production", f.definition.Revision, controlv1.EnvironmentTargets{"api": {Address: new("production.internal:3000")}})
	created := f.createMachine("one")
	if created.CollectionId == nil || *created.CollectionId != f.collection.ID || created.AppliedDefinitionRevision != f.definition.Revision {
		t.Fatal("default or durable collection selection lost", created)
	}
	var identity, machine, grant string
	if err := f.inspect.QueryRow(t.Context(), `SELECT COALESCE(created_by_identity_id,''),created_by_machine_id,provisioning_grant_id FROM control.environments WHERE id=$1`, created.Id).Scan(&identity, &machine, &grant); err != nil || identity != "" || machine != f.machine.ID || grant != f.grant.ID {
		t.Fatal("machine impersonated manager", identity, machine, grant, err)
	}
	read := provisioningBearer(f.token(controlstate.ProvisioningRead))
	list, err := f.client.ListEnvironmentsWithResponse(t.Context(), f.project, &controlv1.ListEnvironmentsParams{TeamId: f.team}, read)
	if err != nil || list.JSON200 == nil || len(*list.JSON200) != 1 || (*list.JSON200)[0].Id != created.Id {
		t.Fatal("machine list escaped collection", list, err)
	}
	outside, err := f.client.GetEnvironmentWithResponse(t.Context(), f.project, production.Id, &controlv1.GetEnvironmentParams{TeamId: f.team}, read)
	if err != nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, outside.StatusCode(), outside.Body, http.StatusForbidden, controlv1.Forbidden)
	collection, err := f.client.GetCollectionWithResponse(t.Context(), f.project, f.collection.ID, &controlv1.GetCollectionParams{TeamId: f.team}, read)
	if err != nil || collection.JSON200 == nil || collection.JSON200.MutationRevision != f.collection.MutationRevision {
		t.Fatal("machine could not read exact creation precondition", collection, err)
	}
	bad := f.creation("outside")
	bad.CollectionId, bad.ExpectedCollectionRevision, bad.DefinitionRevision = nil, nil, new(f.definition.Revision)
	rejected, err := f.client.CreateEnvironmentWithResponse(t.Context(), f.project, bad, provisioningBearer(f.token(controlstate.ProvisioningCreate)))
	if err != nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, rejected.StatusCode(), rejected.Body, http.StatusForbidden, controlv1.Forbidden)
	targets := controlv1.EnvironmentTargets{"api": {Address: new("updated.customer.internal:3001")}}
	updated, err := f.client.ApplyEnvironmentWithResponse(t.Context(), f.project, created.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: created.MutationRevision, DefinitionRevision: f.definition.Revision, Targets: &targets}, provisioningBearer(f.token(controlstate.ProvisioningUpdate)))
	if err != nil || updated.JSON200 == nil || updated.JSON200.MutationRevision != created.MutationRevision+1 {
		t.Fatal("machine update failed", updated, err)
	}
	if !reflect.DeepEqual(production, f.get(production.Id)) {
		t.Fatal("customer provisioning changed production")
	}
	var wrongAudit int
	if err := f.inspect.QueryRow(t.Context(), `SELECT count(*) FROM control.service_audit_events WHERE service_id=$1 AND (actor_identity_id IS NOT NULL OR actor_machine_id IS DISTINCT FROM $2 OR actor_provisioning_grant_id IS DISTINCT FROM $3)`, created.Services[0].ServiceId, f.machine.ID, f.grant.ID).Scan(&wrongAudit); err != nil || wrongAudit != 0 {
		t.Fatal("machine audit provenance lost", wrongAudit, err)
	}
	// definitions and collection defaults remain human-only even with update.
	deniedDefault, err := f.client.UpdateCollectionDefaultWithResponse(t.Context(), f.project, f.collection.ID, controlv1.UpdateCollectionDefaultRequest{TeamId: f.team, ExpectedRevision: f.collection.MutationRevision, DefinitionRevision: f.definition.Revision}, provisioningBearer(f.token(controlstate.ProvisioningUpdate)))
	if err != nil || deniedDefault.StatusCode() != http.StatusUnauthorized {
		t.Fatal("machine changed collection default", deniedDefault, err)
	}
	retired, err := f.client.RetireEnvironmentWithResponse(t.Context(), f.project, created.Id, &controlv1.RetireEnvironmentParams{TeamId: f.team, ExpectedRevision: updated.JSON200.MutationRevision}, provisioningBearer(f.token(controlstate.ProvisioningRetire)))
	if err != nil || retired.StatusCode() != http.StatusNoContent {
		t.Fatal("machine retirement failed", retired, err)
	}
	retry, err := f.client.CreateEnvironmentWithResponse(t.Context(), f.project, f.creation("one"), provisioningBearer(f.token(controlstate.ProvisioningCreate)))
	if err != nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, retry.StatusCode(), retry.Body, http.StatusConflict, controlv1.Conflict)
}

func TestIntegrationEnvironmentProvisioningHTTPEnrollmentBudgetAndRevocation(t *testing.T) {
	f := newEnvironmentProvisioningHTTPFixture(t)
	environment := f.createMachine("one")
	token := f.token(controlstate.ProvisioningEnroll)
	body := controlv1.CreateEnvironmentPublisherEnrollmentRequest{TeamId: f.team, ExpectedRevision: environment.MutationRevision, ConfigurationHash: environment.ConfigurationHash, Services: []string{"api"}, MaxMembers: 2, ExpiresIn: 300}
	issue := func(key string, request controlv1.CreateEnvironmentPublisherEnrollmentRequest) *controlv1.CreateEnvironmentPublisherEnrollmentResponse {
		t.Helper()
		r, err := f.client.CreateEnvironmentPublisherEnrollmentWithResponse(t.Context(), f.project, environment.Id, &controlv1.CreateEnvironmentPublisherEnrollmentParams{IdempotencyKey: new(key)}, request, provisioningBearer(token))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, params := range []*controlv1.CreateEnvironmentPublisherEnrollmentParams{nil, {}, {IdempotencyKey: new("")}, {IdempotencyKey: new(strings.Repeat("a", 129))}, {IdempotencyKey: new(" unsafe")}} {
		r, err := f.client.CreateEnvironmentPublisherEnrollmentWithResponse(t.Context(), f.project, environment.Id, params, body, provisioningBearer(token))
		if err != nil || r.StatusCode() != http.StatusBadRequest || f.used() != 0 {
			t.Fatal("missing or invalid typed enrollment key spent budget", r, f.used(), err)
		}
	}
	for _, edit := range []func(*controlv1.CreateEnvironmentPublisherEnrollmentRequest){func(r *controlv1.CreateEnvironmentPublisherEnrollmentRequest) { r.MaxMembers = 3 }, func(r *controlv1.CreateEnvironmentPublisherEnrollmentRequest) { r.ExpiresIn = 601 }, func(r *controlv1.CreateEnvironmentPublisherEnrollmentRequest) { r.Services = []string{"not-allowed"} }} {
		bad := body
		edit(&bad)
		r := issue("denied", bad)
		if r.StatusCode() < 400 || f.used() != 0 {
			t.Fatal("denied enrollment spent budget", r.StatusCode(), f.used())
		}
	}
	first := issue("first", body)
	if first.JSON201 == nil || f.used() != 2 {
		t.Fatal("exact enrollment failed", first, f.used())
	}
	retry := issue("first", body)
	if retry.JSON201 == nil || !reflect.DeepEqual(first.JSON201, retry.JSON201) || f.used() != 2 {
		t.Fatal("retry widened or double-spent enrollment", retry, f.used())
	}
	widened := body
	widened.MaxMembers = 1
	if r := issue("first", widened); r.StatusCode() != http.StatusConflict || f.used() != 2 {
		t.Fatal("key reused for different intent", r.StatusCode(), f.used())
	}
	if r := issue("second", body); r.StatusCode() != http.StatusForbidden || f.used() != 2 {
		t.Fatal("cumulative budget exceeded", r.StatusCode(), f.used())
	}
	second := issue("second", widened)
	if second.JSON201 == nil || f.used() != 3 {
		t.Fatal("remaining budget unavailable", second, f.used())
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	redeem := func(key string, public ed25519.PublicKey) *controlv1.RedeemEnvironmentPublisherEnrollmentResponse {
		t.Helper()
		r, err := f.client.RedeemEnvironmentPublisherEnrollmentWithResponse(t.Context(), controlv1.RedeemEnvironmentPublisherEnrollmentRequest{EnrollmentKey: key, PublicKey: base64.RawURLEncoding.EncodeToString(public)})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	member := redeem(first.JSON201.EnrollmentKey, public)
	if member.JSON200 == nil {
		t.Fatal("machine enrollment not redeemable", member)
	}
	if replay := redeem(first.JSON201.EnrollmentKey, public); replay.JSON200 == nil || *replay.JSON200 != *member.JSON200 {
		t.Fatal("exact-key replay changed publisher identity", replay)
	}
	if err := f.database.RevokeProvisioningGrant(t.Context(), f.team, f.grant.ID, f.session.Identity.Identity.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if denied := redeem(second.JSON201.EnrollmentKey, other); denied.StatusCode() < 400 {
		t.Fatal("revoked grant redeemed pending enrollment", denied)
	}
	// installed publisher authority is independent of later issuer revocation.
	const audience = "https://control.example.test/v1/environment-publishers/lease"
	assertion, err := publisherproof.Sign(member.JSON200.PublisherIdentityId, member.JSON200.KeyId, environment.Id, audience, private, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.client.AcquireEnvironmentPublisherLeaseWithResponse(t.Context(), controlv1.EnvironmentPublisherProof{PublisherIdentityId: member.JSON200.PublisherIdentityId, EnvironmentId: environment.Id, Assertion: assertion})
	if err != nil || lease.JSON200 == nil {
		t.Fatal("issuer revocation disabled installed publisher", lease, err)
	}
	if denied := issue("first", body); denied.StatusCode() < 400 || f.used() != 3 {
		t.Fatal("retry bypassed revoked grant", denied)
	}
}

func TestIntegrationEnvironmentProvisioningHTTPDefaultDoesNotWidenServices(t *testing.T) {
	f := newEnvironmentProvisioningHTTPFixture(t)
	original := f.createMachine("one")
	next, err := f.client.CreateServiceDefinitionWithResponse(t.Context(), f.project, controlv1.CreateServiceDefinitionRequest{TeamId: f.team, SourceFingerprint: f.source, Definition: controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{"api": {Protocol: "http"}, "metrics": {Protocol: "http"}}}})
	if err != nil || next.JSON200 == nil {
		t.Fatal(next, err)
	}
	collection, err := f.database.UpdateCollectionDefault(t.Context(), controlstate.UpdateCollectionDefaultRequest{TeamID: f.team, ProjectKey: f.project, ActorID: f.session.Identity.Identity.ID, CollectionID: f.collection.ID, ExpectedRevision: f.collection.MutationRevision, DefinitionRevision: next.JSON200.Revision, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.client.CreateEnvironmentWithResponse(t.Context(), f.project, f.creation("one"), provisioningBearer(f.token(controlstate.ProvisioningCreate)))
	if err != nil || retry.JSON200 == nil || retry.JSON200.Id != original.Id {
		t.Fatal("default drift changed creation retry", retry, err)
	}
	body := f.creation("two")
	body.ExpectedCollectionRevision = new(collection.MutationRevision)
	body.Targets["metrics"] = controlv1.EnvironmentTarget{Address: new("metrics.internal:9090")}
	denied, err := f.client.CreateEnvironmentWithResponse(t.Context(), f.project, body, provisioningBearer(f.token(controlstate.ProvisioningCreate)))
	if err != nil {
		t.Fatal(err)
	}
	assertEnvironmentHTTPProblem(t, denied.StatusCode(), denied.Body, http.StatusForbidden, controlv1.Forbidden)
	// explicit old shape is safe and does not mutate the collection default.
	body.DefinitionRevision = new(f.definition.Revision)
	delete(body.Targets, "metrics")
	allowed, err := f.client.CreateEnvironmentWithResponse(t.Context(), f.project, body, provisioningBearer(f.token(controlstate.ProvisioningCreate)))
	if err != nil || allowed.JSON200 == nil || allowed.JSON200.AppliedDefinitionRevision != f.definition.Revision {
		t.Fatal(allowed, err)
	}
	if !reflect.DeepEqual(original, f.get(original.Id)) {
		t.Fatal("new default changed existing customer")
	}
}

func TestIntegrationEnvironmentProvisioningHTTPFixedExpiryAfterServiceLock(t *testing.T) {
	for _, boundary := range []string{"team", "service"} {
		t.Run(boundary, func(t *testing.T) {
			f := newEnvironmentProvisioningHTTPFixture(t)
			environment := f.createMachine("one")
			token := f.token(controlstate.ProvisioningUpdate)
			digest := sha256.Sum256([]byte(token))
			deadline := time.Now().Add(2 * time.Second).Truncate(time.Microsecond)
			if _, err := f.inspect.Exec(t.Context(), `UPDATE control.machine_provisioning_sessions SET expires_at=$2 WHERE credential_digest=$1`, digest[:], deadline); err != nil {
				t.Fatal(err)
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
			query, id := `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, environment.Services[0].ServiceId
			if boundary == "team" {
				query, id = `SELECT id FROM control.teams WHERE id=$1 FOR UPDATE`, f.team
			}
			if _, err := gate.Exec(ctx, query, id); err != nil {
				t.Fatal(err)
			}
			type outcome struct {
				response *controlv1.ApplyEnvironmentResponse
				err      error
			}
			done, joined := make(chan outcome, 1), make(chan struct{})
			go func() {
				defer close(joined)
				targets := controlv1.EnvironmentTargets{"api": {Address: new("changed.internal:3001")}}
				r, err := f.client.ApplyEnvironmentWithResponse(ctx, f.project, environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: environment.MutationRevision, DefinitionRevision: f.definition.Revision, Targets: &targets}, provisioningBearer(token))
				done <- outcome{r, err}
			}()
			defer func() {
				cancel()
				select {
				case <-joined:
				case <-time.After(5 * time.Second):
					t.Error("provisioning worker did not join")
				}
			}()
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				var blocked bool
				if err := f.inspect.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))`, int32(connection.PgConn().PID())).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				select {
				case <-tick.C:
				case result := <-done:
					t.Fatal("operation finished before observed service lock", result)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			// before the team guard the session is not yet locked; extending its row
			// must not extend the capability already captured by HTTP. after the guard,
			// exact authorization pins it through the later service-lock wait.
			if boundary == "team" {
				if _, err := f.inspect.Exec(ctx, `UPDATE control.machine_provisioning_sessions SET expires_at=$2 WHERE credential_digest=$1`, digest[:], time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			timer := time.NewTimer(time.Until(deadline))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case result := <-done:
				if result.err != nil || result.response == nil {
					t.Fatal(result.err)
				}
				if result.response.StatusCode() < 400 {
					data, _ := json.Marshal(result.response.JSON200)
					t.Fatal("expired request committed", string(data))
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if !reflect.DeepEqual(environment, f.get(environment.Id)) {
				t.Fatal("expired mutation changed environment")
			}
		})
	}
}
