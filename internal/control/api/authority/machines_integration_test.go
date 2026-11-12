package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type machineAPIFixture struct {
	d                             *controlstate.Database
	client                        *authorityv1.ClientWithResponses
	server                        *httptest.Server
	issuer                        *githubtest.Issuer
	team, actor, human            string
	databaseURL                   string
	collection                    controlstate.Collection
	environment, otherEnvironment controlstate.Environment
	trust                         oidc.WorkloadTrust
	now                           time.Time
}

func newMachineAPIFixture(t *testing.T) machineAPIFixture {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "machine_api")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC().Truncate(time.Second)
	human, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	f := machineAPIFixture{d: d, databaseURL: url, team: human.Identity.Memberships[0].TeamID, actor: human.Identity.Identity.ID, human: string(human.AccessToken), now: now,
		trust: oidc.WorkloadTrust{Provider: "oidc", Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/keys", Audience: "tnl-machine", Claims: map[string]string{"sub": "service:machine"}}}
	f.issuer = githubtest.NewKeySet(t, f.trust.JWKSURL)
	definition, err := d.CreateServiceDefinition(ctx, controlstate.CreateServiceDefinitionRequest{TeamID: f.team, ProjectKey: "equipment", ActorID: f.actor, SourceFingerprint: strings.Repeat("a", 64), Definition: controlstate.ServiceDefinition{Services: map[string]controlstate.ServiceDefinitionService{"api": {Protocol: "http"}, "secret": {Protocol: "tcp"}}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	f.collection, err = d.CreateCollection(ctx, controlstate.CreateCollectionRequest{TeamID: f.team, ProjectKey: "equipment", ActorID: f.actor, Name: "customers", DefaultDefinitionRevision: definition.Revision, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		environment, err := d.CreateEnvironment(ctx, controlstate.CreateEnvironmentRequest{TeamID: f.team, ProjectKey: "equipment", ActorID: f.actor, SourceFingerprint: strings.Repeat("a", 64),
			Name: name, CollectionID: f.collection.ID, ExpectedCollectionRevision: f.collection.MutationRevision, IdempotencyKey: "create/" + name,
			Targets: controlstate.EnvironmentTargets{"api": {Address: "private-api.internal:3000"}, "secret": {Address: "private-secret.internal:22"}}, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if name == "one" {
			f.environment = environment
		} else {
			f.otherEnvironment = environment
		}
	}
	mux := http.NewServeMux()
	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)
	if _, err = Register(mux, Config{ControlURL: f.server.URL, HTTPClient: f.issuer.Client, Machines: d, Publications: d}, d); err != nil {
		t.Fatal(err)
	}
	f.client, err = authorityv1.NewClientWithResponses(f.server.URL, authorityv1.WithHTTPClient(f.server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func machineBearer(token string) authorityv1.RequestEditorFn {
	return func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
}

func (f machineAPIFixture) claims() map[string]any {
	return map[string]any{"iss": f.trust.Issuer, "aud": f.trust.Audience, "sub": f.trust.Claims["sub"], "iat": f.now.Unix(), "exp": f.now.Add(20 * time.Minute).Unix()}
}

func (f machineAPIFixture) register(t *testing.T, kind authorityv1.RegisterMachineRequestProofKind) (string, ed25519.PrivateKey) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := authorityv1.RegisterMachineRequest{Name: "machine", ProofKind: kind}
	if kind == "oidc" {
		request.Trust = &authorityv1.MachineTrust{Provider: "oidc", Issuer: f.trust.Issuer, JwksUrl: f.trust.JWKSURL, Audience: f.trust.Audience, Claims: f.trust.Claims}
	} else {
		request.KeyId, request.PublicKey = new("first"), new(base64.RawURLEncoding.EncodeToString(public))
	}
	r, err := f.client.RegisterMachineIdentityWithResponse(t.Context(), f.team, request, machineBearer(f.human))
	if err != nil || r.JSON201 == nil {
		t.Fatal("register", r, err)
	}
	return r.JSON201.Id, key
}

func machineEnvironmentScope(ids ...string) authorityv1.EnvironmentPermissionScope {
	return authorityv1.EnvironmentPermissionScope{EnvironmentIds: &ids}
}

func (f machineAPIFixture) permission(t *testing.T, machine string, scope authorityv1.EnvironmentPermissionScope) string {
	t.Helper()
	r, err := f.client.CreateEnvironmentVisitorPermissionWithResponse(t.Context(), f.team, machine, authorityv1.EnvironmentVisitorPermissionRequest{ProjectKey: "equipment", Scope: scope, Services: []string{"api"}, MaxDurationSeconds: 3600, ExpiresAt: f.now.Add(time.Hour)}, machineBearer(f.human))
	if err != nil || r.JSON201 == nil {
		t.Fatal("permission", r, err)
	}
	return r.JSON201.Id
}

func (f machineAPIFixture) prepareBody(t *testing.T, permission, environment, operation, nonce, machine string, sourceKey, ephemeral ed25519.PrivateKey) authorityv1.EnvironmentVisitorPrepareRequest {
	t.Helper()
	services := map[string]string{"api": "http"}
	public := base64.RawURLEncoding.EncodeToString(ephemeral.Public().(ed25519.PublicKey))
	raw := f.issuer.Sign(t, f.claims())
	if sourceKey != nil {
		var err error
		raw, err = publisherproof.Sign(machine, "first", machineproof.EnvironmentVisitor(permission, environment, operation, public, nonce, services), f.server.URL+"/v1/projects/equipment/environments/"+environment+"/visitors/prepare", sourceKey, f.now)
		if err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256([]byte(raw))
	return authorityv1.EnvironmentVisitorPrepareRequest{PermissionId: permission, Nonce: nonce, PublicKey: public, Assertion: raw, Services: map[string]controlv1.ServiceProtocol{"api": "http"},
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ephemeral, machineproof.EnvironmentVisitorPossession("equipment", permission, environment, operation, public, nonce, services, digest)))}
}

func TestIntegrationMachineAuthorityOIDCVerificationAndReusableToken(t *testing.T) {
	f := newMachineAPIFixture(t)
	ctx := t.Context()
	machine, _ := f.register(t, "oidc")
	scope := authorityv1.EnvironmentPermissionScope{CollectionId: new(f.collection.ID), IncludeFutureEnvironments: new(true)}
	grant, err := f.client.CreateProvisioningGrantWithResponse(ctx, f.team, machine, authorityv1.ProvisioningGrantRequest{ProjectKey: "equipment", Scope: scope, Services: []string{"api"}, Operations: []authorityv1.ProvisioningOperation{authorityv1.ProvisioningCreate, authorityv1.ProvisioningRead, authorityv1.ProvisioningEnroll}, MaxEnrollmentMembers: 2, MaxEnrollmentSeconds: 300, EnrollmentBudget: 4, ExpiresAt: f.now.Add(time.Hour)}, machineBearer(f.human))
	if err != nil || grant.JSON201 == nil {
		t.Fatal("grant", grant, err)
	}
	raw := f.issuer.Sign(t, f.claims())
	for _, op := range []authorityv1.ProvisioningOperation{authorityv1.ProvisioningCreate, authorityv1.ProvisioningRead, authorityv1.ProvisioningEnroll, authorityv1.ProvisioningRead} {
		r, err := f.client.ExchangeProvisioningWithResponse(ctx, authorityv1.ProvisioningExchange{GrantId: grant.JSON201.Id, Operation: op, Assertion: raw})
		if err != nil || r.JSON200 == nil {
			t.Fatal("grant-derived identity with reusable projected token", r, err)
		}
		if r.JSON200.TokenType != "Bearer" || r.JSON200.TeamId != f.team || r.JSON200.ProjectKey != "equipment" || !reflect.DeepEqual(r.JSON200.Services, []string{"api"}) || !reflect.DeepEqual(r.JSON200.Scope, scope) || r.JSON200.AccessToken == "" || r.JSON200.ExpiresAt.After(time.Now().Add(5*time.Minute)) {
			t.Fatal("incomplete authoritative scope")
		}
		denied, err := f.client.RegisterMachineIdentityWithResponse(ctx, f.team, authorityv1.RegisterMachineRequest{Name: "escalate", ProofKind: "signing_key"}, machineBearer(r.JSON200.AccessToken))
		if err != nil || denied.StatusCode() != 401 {
			t.Fatal("provisioning became human admin", denied, err)
		}
		if r.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("credential response cacheable")
		}
	}
	bad, err := f.client.ExchangeProvisioningWithResponse(ctx, authorityv1.ProvisioningExchange{MachineId: "mci_other", GrantId: grant.JSON201.Id, Operation: authorityv1.ProvisioningRead, Assertion: raw})
	if err != nil || bad.StatusCode() != 403 {
		t.Fatal("explicit identity overrode the grant's saved identity", bad, err)
	}
	for _, field := range []string{"iss", "aud", "sub", "exp"} {
		t.Run(field, func(t *testing.T) {
			claims := f.claims()
			claims[field] = "wrong"
			if field == "exp" {
				claims[field] = f.now.Add(-time.Second).Unix()
			}
			r, err := f.client.ExchangeProvisioningWithResponse(t.Context(), authorityv1.ProvisioningExchange{GrantId: grant.JSON201.Id, Operation: authorityv1.ProvisioningRead, Assertion: f.issuer.Sign(t, claims)})
			if err != nil || r.StatusCode() != 403 {
				t.Fatal("invalid provider proof accepted", r, err)
			}
		})
	}
	foreign := githubtest.NewKeySet(t, f.trust.JWKSURL)
	bad, err = f.client.ExchangeProvisioningWithResponse(ctx, authorityv1.ProvisioningExchange{GrantId: grant.JSON201.Id, Operation: authorityv1.ProvisioningRead, Assertion: foreign.Sign(t, f.claims())})
	if err != nil || bad.StatusCode() != 403 {
		t.Fatal("unregistered provider key accepted", bad, err)
	}
	bad, err = f.client.ExchangeProvisioningWithResponse(ctx, authorityv1.ProvisioningExchange{GrantId: grant.JSON201.Id, Operation: authorityv1.ProvisioningRetire, Assertion: raw})
	if err != nil || bad.StatusCode() != 403 {
		t.Fatal("ungranted operation accepted", bad, err)
	}
	permission := f.permission(t, machine, machineEnvironmentScope(f.environment.ID))
	_, ephemeral, _ := ed25519.GenerateKey(rand.Reader)
	for _, environment := range []string{f.environment.ID, f.otherEnvironment.ID, "env_unknown"} {
		body := f.prepareBody(t, permission, environment, "prepare", rand.Text(), machine, nil, ephemeral)
		r, err := f.client.PrepareEnvironmentVisitorWithResponse(ctx, "equipment", environment, body)
		if err != nil {
			t.Fatal(err)
		}
		if environment != f.environment.ID {
			if r.StatusCode() != 403 && r.StatusCode() != 400 {
				t.Fatal("unauthorized environment disclosed", r)
			}
			continue
		}
		if r.JSON200 == nil || r.JSON200.Environment.EnvironmentId != environment || len(r.JSON200.Services) != 1 || r.JSON200.Services["api"].Protocol != "http" {
			t.Fatal("permission-only discovery failed", r)
		}
		for _, private := range []string{"private-", "secret", "target", "group", "trust"} {
			if strings.Contains(string(r.Body), private) {
				t.Fatal("discovery disclosed private state", private)
			}
		}
	}
	revoked, err := f.client.RevokeProvisioningGrantWithResponse(ctx, f.team, grant.JSON201.Id, machineBearer(f.human))
	if err != nil || revoked.StatusCode() != 204 {
		t.Fatal(revoked, err)
	}
	bad, err = f.client.ExchangeProvisioningWithResponse(ctx, authorityv1.ProvisioningExchange{GrantId: grant.JSON201.Id, Operation: authorityv1.ProvisioningRead, Assertion: raw})
	if err != nil || bad.StatusCode() != 403 {
		t.Fatal("current revocation bypassed by reused platform token", bad, err)
	}
}

func TestIntegrationMachineAuthorityWorkloadExchangeAndAttach(t *testing.T) {
	for _, kind := range []authorityv1.RegisterMachineRequestProofKind{"oidc", "signing_key"} {
		t.Run(string(kind), func(t *testing.T) {
			f := newMachineAPIFixture(t)
			machine, sourceKey := f.register(t, kind)
			if kind == "oidc" {
				sourceKey = nil
			}
			_, ephemeral, _ := ed25519.GenerateKey(rand.Reader)
			denied, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.environment.ID, f.prepareBody(t, machine, f.environment.ID, "prepare", rand.Text(), machine, sourceKey, ephemeral))
			if err != nil || denied.StatusCode() != 403 {
				t.Fatal("identity gained visitor rights without a separate permission", denied, err)
			}
			permission := f.permission(t, machine, machineEnvironmentScope(f.environment.ID))
			body := f.prepareBody(t, permission, f.environment.ID, "prepare", rand.Text(), machine, sourceKey, ephemeral)
			prepared, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.environment.ID, body)
			if err != nil || prepared.JSON200 == nil {
				t.Fatal(prepared, err)
			}
			session := prepared.JSON200.Session
			replay, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.environment.ID, body)
			if err != nil || replay.JSON200 == nil || !reflect.DeepEqual(replay.JSON200.Session, session) {
				t.Fatal("exact retry changed session", replay, err)
			}
			public := body.PublicKey
			services := map[string]string{"api": "http"}
			raw := f.issuer.Sign(t, f.claims())
			if kind == "signing_key" {
				raw, err = publisherproof.Sign(machine, "first", machineproof.EnvironmentVisitor(permission, f.environment.ID, "attach", public, session.Id, services), f.server.URL+"/v1/environment-visitor-sessions/"+session.Id+"/assertions", sourceKey, f.now)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				claims := f.claims()
				claims["exp"] = f.now.Add(40 * time.Minute).Unix()
				raw = f.issuer.Sign(t, claims)
			}
			digest := sha256.Sum256([]byte(raw))
			attachment := authorityv1.EnvironmentVisitorAssertion{Assertion: raw, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ephemeral, machineproof.EnvironmentVisitorPossession("equipment", permission, f.environment.ID, "attach", public, session.Id, services, digest)))}
			attached, err := f.client.AttachEnvironmentVisitorAssertionWithResponse(t.Context(), session.Id, attachment, machineBearer(session.Credential))
			if err != nil || attached.JSON200 == nil || attached.JSON200.Id != session.Id || !reflect.DeepEqual(attached.JSON200.ServiceIds, session.ServiceIds) || !attached.JSON200.ExpiresAt.Equal(*session.ExpiresAt) {
				t.Fatal("attachment changed immutable session", attached, err)
			}
			renewal := authorityv1.EnvironmentVisitorRenewal{Sequence: 1, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ephemeral, workloadproof.Renew(session.Id, 1)))}
			renewed, err := f.client.RenewEnvironmentVisitorSessionWithResponse(t.Context(), session.Id, renewal, machineBearer(session.Credential))
			if err != nil || renewed.JSON200 == nil || renewed.JSON200.RenewalSequence != 1 {
				t.Fatal("renew", renewed, err)
			}
			revoked, err := f.client.RevokeEnvironmentVisitorPermissionWithResponse(t.Context(), f.team, permission, machineBearer(f.human))
			if err != nil || revoked.StatusCode() != 204 {
				t.Fatal(revoked, err)
			}
			attached, err = f.client.AttachEnvironmentVisitorAssertionWithResponse(t.Context(), session.Id, attachment, machineBearer(session.Credential))
			if err != nil || attached.StatusCode() != 403 {
				t.Fatal("revoked permission attached assertion", attached, err)
			}
			denied, err = f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.environment.ID, body)
			if err != nil || denied.StatusCode() != 403 {
				t.Fatal("retry restored revoked permission", denied, err)
			}
		})
	}
}

func TestMachineStoreRequiresExplicitDependency(t *testing.T) {
	mux, err := NewHandler(Config{ControlURL: "https://control.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/provisioning-sessions/exchange", strings.NewReader(`{}`)))
	if w.Code != 503 {
		t.Fatalf("missing explicit machine dependency: %d %s", w.Code, w.Body.String())
	}
	var problem authorityv1.Problem
	if err = json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationMachineAuthorityWorkloadProofBindsBodyGroup(t *testing.T) {
	f := newMachineAPIFixture(t)
	machine, key := f.register(t, "signing_key")
	permission := f.permission(t, machine, machineEnvironmentScope(f.environment.ID, f.otherEnvironment.ID))
	_, ephemeral, _ := ed25519.GenerateKey(rand.Reader)
	nonceA, nonceB := rand.Text(), rand.Text()
	body := f.prepareBody(t, permission, f.environment.ID, "prepare", nonceA, machine, key, ephemeral)
	initial, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.environment.ID, body)
	if err != nil || initial.JSON200 == nil || len(initial.JSON200.Session.ServiceIds) != 1 {
		t.Fatal("valid initial environment A session", initial, err)
	}
	serviceB := ""
	for _, service := range f.otherEnvironment.Services {
		if service.Service == "api" {
			serviceB = service.ServiceID
		}
	}
	for _, operation := range []string{"prepare", "attach"} {
		for _, nonce := range []string{nonceA, nonceB} {
			wrong := f.prepareBody(t, permission, f.environment.ID, operation, nonce, machine, key, ephemeral)
			// re-sign possession for B: even a valid ephemeral signature cannot
			// change the source proof's selected environment or operation.
			digest := sha256.Sum256([]byte(wrong.Assertion))
			wrong.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ephemeral, machineproof.EnvironmentVisitorPossession("equipment", permission, f.otherEnvironment.ID, "prepare", wrong.PublicKey, nonce, map[string]string{"api": "http"}, digest)))
			denied, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.otherEnvironment.ID, wrong)
			if err != nil || denied.StatusCode() != 403 {
				t.Fatal("environment B accepted source proof for A or another operation", denied, err)
			}
			services, err := f.d.ListWorkloadServices(t.Context(), initial.JSON200.Session.Credential, time.Now())
			if err != nil || len(services) != 1 || services[0].ID != initial.JSON200.Session.ServiceIds[0] {
				t.Fatal("denial widened existing session", err)
			}
			if _, err := f.d.CheckWorkloadService(t.Context(), initial.JSON200.Session.Credential, serviceB, time.Now()); err == nil {
				t.Fatal("environment A session reached service B")
			}
		}
	}
	valid, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.otherEnvironment.ID, f.prepareBody(t, permission, f.otherEnvironment.ID, "prepare", nonceB, machine, key, ephemeral))
	if err != nil || valid.JSON200 == nil || valid.JSON200.Session.Id == initial.JSON200.Session.Id || !reflect.DeepEqual(valid.JSON200.Session.ServiceIds, []string{serviceB}) {
		t.Fatal("correctly scoped environment B proof failed", valid, err)
	}
}

func TestIntegrationMachineOIDCLegacyEndpointCannotBypassRegistration(t *testing.T) {
	f := newMachineAPIFixture(t)
	for _, path := range []string{"/v1/workload-sessions/exchange", "/v1/workload-sessions/identity", "/v1/machine-workload-sessions/exchange", "/v1/publisher-groups/retired/resolve"} {
		response, err := f.server.Client().Post(f.server.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != 404 {
			t.Fatal("retired authentication path remains available", path, response.StatusCode, readErr, closeErr)
		}
	}
	machine, _ := f.register(t, "oidc")
	permission := f.permission(t, machine, machineEnvironmentScope(f.environment.ID))
	_, ephemeral, _ := ed25519.GenerateKey(rand.Reader)
	body := f.prepareBody(t, permission, f.environment.ID, "prepare", rand.Text(), machine, nil, ephemeral)
	prepared, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.environment.ID, body)
	if err != nil || prepared.JSON200 == nil {
		t.Fatal(prepared, err)
	}
	session := prepared.JSON200.Session
	revoked, err := f.client.RevokeMachineIdentityWithResponse(t.Context(), f.team, machine, machineBearer(f.human))
	if err != nil || revoked.StatusCode() != 204 {
		t.Fatal(revoked, err)
	}
	denied, err := f.client.PrepareEnvironmentVisitorWithResponse(t.Context(), "equipment", f.environment.ID, body)
	if err != nil || denied.StatusCode() != 403 {
		t.Fatal("prepare bypassed machine revocation", denied, err)
	}
	renewed, err := f.client.RenewEnvironmentVisitorSessionWithResponse(t.Context(), session.Id, authorityv1.EnvironmentVisitorRenewal{Sequence: 1, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ephemeral, workloadproof.Renew(session.Id, 1)))}, machineBearer(session.Credential))
	if err != nil || renewed.StatusCode() != 403 {
		t.Fatal("linked visitor credential bypassed revocation", renewed, err)
	}
}
