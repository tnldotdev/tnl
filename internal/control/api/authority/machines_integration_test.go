package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
)

type machineAPIFixture struct {
	d                                     *controlstate.Database
	client                                *authorityv1.ClientWithResponses
	server                                *httptest.Server
	issuer                                *githubtest.Issuer
	team, actor, group, otherGroup, human string
	trust                                 oidc.WorkloadTrust
	now                                   time.Time
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
	team := human.Identity.Memberships[0].TeamID
	actor := human.Identity.Identity.ID
	trust := oidc.WorkloadTrust{Provider: "oidc", Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/keys", Audience: "tnl-machine", Claims: map[string]string{"sub": "service:machine"}}
	issuer := githubtest.NewKeySet(t, trust.JWKSURL)
	configuration := controlstate.ProjectConfiguration{PublisherGroups: map[string]controlstate.ProjectPublisherGroup{"equipment": {Template: true}, "other": {Template: true}}, Services: map[string]controlstate.ProjectServiceConfiguration{"api": {PublisherGroup: "equipment", Target: "private-api.internal:3000"}, "secret": {PublisherGroup: "equipment", Protocol: "tcp", Target: "private-secret.internal:22"}, "other": {PublisherGroup: "other", Target: "other.internal:3000"}}, Workloads: map[string]controlstate.ProjectWorkload{"worker": {Provider: "oidc", Trust: trust, Services: []string{"api"}, MaxDurationSeconds: 3600}}}
	current, err := d.ApplyProjectConfiguration(ctx, controlstate.ApplyProjectConfigurationRequest{TeamID: team, ProjectKey: "equipment", ActorID: actor, SourceFingerprint: strings.Repeat("a", 64), Configuration: configuration, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		template := "equipment"
		if name == "two" {
			template = "other"
		}
		current, err = d.CreatePublisherGroup(ctx, team, "equipment", name, template, actor, current.Revision, false, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	groups := map[string]string{}
	for _, g := range current.Groups {
		groups[g.Name] = g.ID
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	if _, err = Register(mux, Config{ControlURL: server.URL, HTTPClient: issuer.Client, Machines: d, Publications: d}, d); err != nil {
		t.Fatal(err)
	}
	client, err := authorityv1.NewClientWithResponses(server.URL, authorityv1.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return machineAPIFixture{d: d, client: client, server: server, issuer: issuer, team: team, actor: actor, group: groups["one"], otherGroup: groups["two"], human: string(human.AccessToken), trust: trust, now: now}
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

func TestIntegrationMachineAuthorityOIDCVerificationAndReusableToken(t *testing.T) {
	f := newMachineAPIFixture(t)
	ctx := t.Context()
	trust := authorityv1.MachineTrust{Provider: "oidc", Issuer: f.trust.Issuer, JwksUrl: f.trust.JWKSURL, Audience: f.trust.Audience, Claims: f.trust.Claims}
	registered, err := f.client.RegisterMachineIdentityWithResponse(ctx, f.team, authorityv1.RegisterMachineRequest{Name: "machine", ProofKind: "oidc", Trust: &trust}, machineBearer(f.human))
	if err != nil || registered.JSON201 == nil {
		t.Fatal("register", registered, err)
	}
	machine := registered.JSON201.Id
	grant, err := f.client.CreateProvisioningGrantWithResponse(ctx, f.team, machine, authorityv1.ProvisioningGrantRequest{ProjectKey: "equipment", Templates: []string{"equipment"}, Operations: []authorityv1.ProvisioningOperation{authorityv1.ProvisioningCreate, authorityv1.ProvisioningRead, authorityv1.ProvisioningEnroll}, MaxEnrollmentMembers: 2, MaxEnrollmentSeconds: 300, EnrollmentBudget: 4, ExpiresAt: f.now.Add(time.Hour)}, machineBearer(f.human))
	if err != nil || grant.JSON201 == nil {
		t.Fatal("grant", grant, err)
	}
	claims := f.claims()
	raw := f.issuer.Sign(t, claims)
	for _, op := range []authorityv1.ProvisioningOperation{authorityv1.ProvisioningCreate, authorityv1.ProvisioningRead, authorityv1.ProvisioningEnroll, authorityv1.ProvisioningRead} {
		// ordinary OIDC callers know the grant, not the registered identity ID.
		r, err := f.client.ExchangeProvisioningWithResponse(ctx, authorityv1.ProvisioningExchange{GrantId: grant.JSON201.Id, Operation: op, Assertion: raw})
		if err != nil || r.JSON200 == nil {
			t.Fatal("grant-derived identity with reusable projected token", r, err)
		}
		if r.JSON200.TokenType != "Bearer" || r.JSON200.TeamId != f.team || r.JSON200.ProjectKey != "equipment" || !reflect.DeepEqual(r.JSON200.Templates, []string{"equipment"}) || r.JSON200.ProjectRevision != 3 || r.JSON200.AccessToken == "" {
			t.Fatal("incomplete authoritative scope", r.JSON200)
		}
		// provisioning credentials cannot administer machines or start visitors.
		denied, err := f.client.RegisterMachineIdentityWithResponse(ctx, f.team, authorityv1.RegisterMachineRequest{Name: "escalate", ProofKind: "oidc", Trust: &trust}, machineBearer(r.JSON200.AccessToken))
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
			bad := f.claims()
			bad[field] = "wrong"
			if field == "exp" {
				bad[field] = f.now.Add(-time.Second).Unix()
			}
			r, err := f.client.ExchangeProvisioningWithResponse(ctx, authorityv1.ProvisioningExchange{GrantId: grant.JSON201.Id, Operation: authorityv1.ProvisioningRead, Assertion: f.issuer.Sign(t, bad)})
			if err != nil || r.StatusCode() != 403 {
				t.Fatal("invalid provider proof accepted", r, err)
			}
		})
	}
	foreign := githubtest.NewKeySet(t, f.trust.JWKSURL)
	bad, err = f.client.ExchangeProvisioningWithResponse(ctx, authorityv1.ProvisioningExchange{GrantId: grant.JSON201.Id, Operation: authorityv1.ProvisioningRead, Assertion: foreign.Sign(t, claims)})
	if err != nil || bad.StatusCode() != 403 {
		t.Fatal("unregistered provider key accepted", bad, err)
	}
	bad, err = f.client.ExchangeProvisioningWithResponse(ctx, authorityv1.ProvisioningExchange{MachineId: machine, GrantId: grant.JSON201.Id, Operation: authorityv1.ProvisioningRetire, Assertion: raw})
	if err != nil || bad.StatusCode() != 403 {
		t.Fatal("ungranted operation accepted", bad, err)
	}
	permission, err := f.client.CreateMachineWorkloadPermissionWithResponse(ctx, f.team, machine, authorityv1.MachineWorkloadPermissionRequest{ProjectKey: "equipment", Workload: "worker", Templates: []string{"equipment"}, ExpiresAt: f.now.Add(time.Hour)}, machineBearer(f.human))
	if err != nil || permission.JSON201 == nil {
		t.Fatal(permission, err)
	}
	for _, group := range []string{f.group, f.otherGroup, "pgrp_unknown"} {
		r, err := f.client.ResolvePublisherGroupWorkloadWithResponse(ctx, group, authorityv1.ResolvePublisherGroupWorkload{Workload: "worker", Assertion: raw})
		if err != nil {
			t.Fatal(err)
		}
		if group != f.group {
			if r.StatusCode() != 403 {
				t.Fatal("unauthorized group disclosed", r)
			}
			continue
		}
		if r.JSON200 == nil || r.JSON200.PublisherGroup != "equipment" || r.JSON200.Connection.GroupName != "one" || len(r.JSON200.Connection.Services) != 1 || r.JSON200.Connection.Services["api"] != "http" {
			t.Fatal("workload-only bootstrap failed", r)
		}
		if strings.Contains(string(r.Body), "private-") || strings.Contains(string(r.Body), "secret") || strings.Contains(string(r.Body), "target") {
			t.Fatal("resolution disclosed targets or unapproved services", string(r.Body))
		}
	}
	revoked, err := f.client.RevokeProvisioningGrantWithResponse(ctx, f.team, grant.JSON201.Id, machineBearer(f.human))
	if err != nil || revoked.StatusCode() != 204 {
		t.Fatal(err)
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
			ctx := t.Context()
			public, key, _ := ed25519.GenerateKey(rand.Reader)
			registration := authorityv1.RegisterMachineRequest{Name: "machine", ProofKind: kind}
			if kind == "oidc" {
				registration.Trust = &authorityv1.MachineTrust{Provider: "oidc", Issuer: f.trust.Issuer, JwksUrl: f.trust.JWKSURL, Audience: f.trust.Audience, Claims: f.trust.Claims}
			} else {
				registration.KeyId = new("first")
				registration.PublicKey = new(base64.RawURLEncoding.EncodeToString(public))
			}
			registered, err := f.client.RegisterMachineIdentityWithResponse(ctx, f.team, registration, machineBearer(f.human))
			if err != nil || registered.JSON201 == nil {
				t.Fatal(registered, err)
			}
			machine := registered.JSON201.Id
			resolveAudience := f.server.URL + "/v1/publisher-groups/" + f.group + "/resolve"
			raw := f.issuer.Sign(t, f.claims())
			if kind == "signing_key" {
				raw, err = publisherproof.Sign(machine, "first", machineproof.Workload(f.group, "worker", "resolve", "", "", nil), resolveAudience, key, f.now)
				if err != nil {
					t.Fatal(err)
				}
			}
			resolve := authorityv1.ResolvePublisherGroupWorkload{Workload: "worker", Assertion: raw, MachineId: &machine}
			denied, err := f.client.ResolvePublisherGroupWorkloadWithResponse(ctx, f.group, resolve)
			if err != nil || denied.StatusCode() != 403 {
				t.Fatal("machine gained visitor rights without separate permission", denied, err)
			}
			permission, err := f.client.CreateMachineWorkloadPermissionWithResponse(ctx, f.team, machine, authorityv1.MachineWorkloadPermissionRequest{ProjectKey: "equipment", Workload: "worker", Templates: []string{"equipment"}, ExpiresAt: f.now.Add(time.Hour)}, machineBearer(f.human))
			if err != nil || permission.JSON201 == nil {
				t.Fatal(permission, err)
			}
			resolved, err := f.client.ResolvePublisherGroupWorkloadWithResponse(ctx, f.group, resolve)
			if err != nil || resolved.JSON200 == nil {
				t.Fatal(resolved, err)
			}
			ephemeral, ephemeralKey, _ := ed25519.GenerateKey(rand.Reader)
			nonce := rand.Text()
			services := []string{f.group + "/api"}
			encoded := base64.RawURLEncoding.EncodeToString(ephemeral)
			if kind == "signing_key" {
				raw, err = publisherproof.Sign(machine, "first", machineproof.Workload(f.group, "worker", "exchange", encoded, nonce, services), f.server.URL+"/v1/machine-workload-sessions/exchange", key, f.now)
				if err != nil {
					t.Fatal(err)
				}
			}
			digest := sha256.Sum256([]byte(raw))
			connection := resolved.JSON200.Connection
			signature := ed25519.Sign(ephemeralKey, workloadproof.Exchange(connection.TeamId, connection.ProjectKey, "worker", connection.SourceFingerprint, nonce, digest, services))
			exchange, err := f.client.ExchangeMachineWorkloadWithResponse(ctx, authorityv1.MachineWorkloadExchange{MachineId: machine, GroupId: f.group, Exchange: authorityv1.WorkloadExchange{TeamId: connection.TeamId, ProjectKey: connection.ProjectKey, Workload: "worker", SourceFingerprint: connection.SourceFingerprint, Assertion: raw, Nonce: nonce, PublicKey: encoded, Signature: base64.RawURLEncoding.EncodeToString(signature), Services: &services}})
			if err != nil || exchange.JSON200 == nil {
				t.Fatal(exchange, err)
			}
			session := exchange.JSON200
			audience := f.server.URL + "/v1/machine-workload-sessions/" + session.Id + "/assertions"
			if kind == "signing_key" {
				raw, err = publisherproof.Sign(machine, "first", machineproof.Workload(f.group, "worker", "attach", encoded, session.Id, nil), audience, key, f.now)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				claims := f.claims()
				claims["exp"] = f.now.Add(40 * time.Minute).Unix()
				raw = f.issuer.Sign(t, claims)
			}
			digest = sha256.Sum256([]byte(raw))
			signature = ed25519.Sign(ephemeralKey, workloadproof.Attach(session.Id, digest))
			attached, err := f.client.AttachMachineWorkloadAssertionWithResponse(ctx, session.Id, authorityv1.WorkloadAssertion{Assertion: raw, Signature: base64.RawURLEncoding.EncodeToString(signature)}, machineBearer(session.Credential))
			if err != nil || attached.JSON200 == nil {
				t.Fatal(attached, err)
			}
			if attached.JSON200.Id != session.Id || !reflect.DeepEqual(attached.JSON200.ServiceIds, session.ServiceIds) || !attached.JSON200.ExpiresAt.Equal(*session.ExpiresAt) {
				t.Fatal("attachment changed immutable session", attached.JSON200)
			}
			revoked, err := f.client.RevokeMachineWorkloadPermissionWithResponse(ctx, f.team, permission.JSON201.Id, machineBearer(f.human))
			if err != nil || revoked.StatusCode() != 204 {
				t.Fatal(revoked, err)
			}
			attached, err = f.client.AttachMachineWorkloadAssertionWithResponse(ctx, session.Id, authorityv1.WorkloadAssertion{Assertion: raw, Signature: base64.RawURLEncoding.EncodeToString(signature)}, machineBearer(session.Credential))
			if err != nil || attached.StatusCode() != 403 {
				t.Fatal("revoked permission attached assertion", attached, err)
			}
		})
	}
}

func TestMachineStoreRequiresExplicitDependency(t *testing.T) {
	mux, err := NewHandler(Config{ControlURL: "https://control.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/provisioning-sessions/exchange", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("missing explicit machine dependency: %d %s", w.Code, w.Body.String())
	}
	var p authorityv1.Problem
	if err = json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationMachineAuthorityWorkloadProofBindsBodyGroup(t *testing.T) {
	f := newMachineAPIFixture(t)
	ctx := t.Context()
	current, err := f.d.GetProjectConfiguration(ctx, f.team, "equipment", f.actor)
	if err != nil {
		t.Fatal(err)
	}
	current, err = f.d.CreatePublisherGroup(ctx, f.team, "equipment", "another", "equipment", f.actor, current.Revision, false, f.now)
	if err != nil {
		t.Fatal(err)
	}
	var groupB, serviceB string
	for _, group := range current.Groups {
		if group.Name == "another" {
			groupB = group.ID
		}
	}
	for _, service := range current.Services {
		if service.PublisherGroup == "another" && service.Service == "api" {
			serviceB = service.ServiceID
		}
	}
	if groupB == "" || serviceB == "" {
		t.Fatal("missing second existing same-template group")
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := f.d.RegisterMachineIdentity(ctx, controlstate.RegisterMachineRequest{TeamID: f.team, ActorID: f.actor, Name: "scope-bound", ProofKind: "signing_key", KeyID: "first", PublicKey: public}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.CreateMachineWorkloadPermission(ctx, controlstate.MachineWorkloadPermission{TeamID: f.team, MachineID: machine.ID, ProjectKey: "equipment", Workload: "worker", Templates: []string{"equipment"}, ExpiresAt: f.now.Add(time.Hour)}, f.actor, f.now); err != nil {
		t.Fatal(err)
	}
	resolveAudience := f.server.URL + "/v1/publisher-groups/" + groupB + "/resolve"
	for _, scope := range []string{machineproof.Workload(f.group, "worker", "resolve", "", "", nil), machineproof.Workload(groupB, "worker", "exchange", "", "", nil)} {
		raw, e := publisherproof.Sign(machine.ID, "first", scope, resolveAudience, key, f.now)
		if e != nil {
			t.Fatal(e)
		}
		denied, e := f.client.ResolvePublisherGroupWorkloadWithResponse(ctx, groupB, authorityv1.ResolvePublisherGroupWorkload{MachineId: &machine.ID, Workload: "worker", Assertion: raw})
		if e != nil || denied.StatusCode() != 403 {
			t.Fatal("HTTP group/operation selection accepted another valid proof scope", e)
		}
	}
	raw, err := publisherproof.Sign(machine.ID, "first", machineproof.Workload(groupB, "worker", "resolve", "", "", nil), resolveAudience, key, f.now)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := f.client.ResolvePublisherGroupWorkloadWithResponse(ctx, groupB, authorityv1.ResolvePublisherGroupWorkload{MachineId: &machine.ID, Workload: "worker", Assertion: raw})
	if err != nil || resolved.JSON200 == nil || resolved.JSON200.Connection.GroupId != groupB {
		t.Fatal("otherwise eligible B group failed resolution", err)
	}
	ephemeral, ephemeralKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(ephemeral)
	body := func(proofGroup, bodyGroup, nonce string) authorityv1.MachineWorkloadExchange {
		t.Helper()
		services := []string{bodyGroup + "/api"}
		audience := f.server.URL + "/v1/machine-workload-sessions/exchange"
		scope := machineproof.Workload(proofGroup, "worker", "exchange", encoded, nonce, services)
		raw, e := publisherproof.Sign(machine.ID, "first", scope, audience, key, f.now)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = publisherproof.Verify(raw, machine.ID, "first", scope, audience, public, f.now); e != nil {
			t.Fatal("invalid fixture machine signature", e)
		}
		digest := sha256.Sum256([]byte(raw))
		message := workloadproof.Exchange(f.team, "equipment", "worker", strings.Repeat("a", 64), nonce, digest, services)
		signature := ed25519.Sign(ephemeralKey, message)
		if !ed25519.Verify(ephemeral, message, signature) {
			t.Fatal("invalid fixture ephemeral signature")
		}
		return authorityv1.MachineWorkloadExchange{MachineId: machine.ID, GroupId: bodyGroup, Exchange: authorityv1.WorkloadExchange{TeamId: f.team, ProjectKey: "equipment", Workload: "worker", SourceFingerprint: strings.Repeat("a", 64), Nonce: nonce, PublicKey: encoded, Services: &services, Assertion: raw, Signature: base64.RawURLEncoding.EncodeToString(signature)}}
	}
	nonceA := rand.Text()
	initial, err := f.client.ExchangeMachineWorkloadWithResponse(ctx, body(f.group, f.group, nonceA))
	if err != nil || initial.JSON200 == nil || len(initial.JSON200.ServiceIds) != 1 {
		t.Fatal("valid initial A session", err)
	}
	nonceB := rand.Text()
	for _, nonce := range []string{nonceB, nonceA} {
		denied, e := f.client.ExchangeMachineWorkloadWithResponse(ctx, body(f.group, groupB, nonce))
		if e != nil || denied.StatusCode() != 403 {
			t.Fatal("body group B accepted A proof with correctly signed exact B service", e)
		}
		services, e := f.d.ListWorkloadServices(ctx, initial.JSON200.Credential, time.Now())
		if e != nil || len(services) != 1 || services[0].ID != initial.JSON200.ServiceIds[0] {
			t.Fatal("HTTP denial widened existing session", e)
		}
		if _, e = f.d.CheckWorkloadService(ctx, initial.JSON200.Credential, serviceB, time.Now()); e == nil {
			t.Fatal("A session reached service B")
		}
	}
	valid, err := f.client.ExchangeMachineWorkloadWithResponse(ctx, body(groupB, groupB, nonceB))
	if err != nil || valid.JSON200 == nil || valid.JSON200.Id == initial.JSON200.Id || !reflect.DeepEqual(valid.JSON200.ServiceIds, []string{serviceB}) {
		t.Fatal("correctly scoped B proof failed independent exchange", err)
	}
}

func TestIntegrationMachineOIDCLegacyEndpointCannotBypassRegistration(t *testing.T) {
	f := newMachineAPIFixture(t)
	ctx := t.Context()
	raw := f.issuer.Sign(t, f.claims())
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	services := []string{f.group + "/api"}
	exchangeBody := func() authorityv1.WorkloadExchange {
		nonce := rand.Text()
		digest := sha256.Sum256([]byte(raw))
		body := authorityv1.WorkloadExchange{TeamId: f.team, ProjectKey: "equipment", SourceFingerprint: strings.Repeat("a", 64), Workload: "worker", Assertion: raw, Nonce: nonce, PublicKey: base64.RawURLEncoding.EncodeToString(public), Services: &services}
		body.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, workloadproof.Exchange(body.TeamId, body.ProjectKey, body.Workload, body.SourceFingerprint, nonce, digest, services)))
		return body
	}
	legacy, err := f.client.ExchangeWorkloadWithResponse(ctx, exchangeBody())
	if err != nil || legacy.JSON200 == nil {
		t.Fatal("legacy provider workload", legacy, err)
	}
	registered, err := f.client.RegisterMachineIdentityWithResponse(ctx, f.team, authorityv1.RegisterMachineRequest{Name: "machine", ProofKind: "oidc", Trust: &authorityv1.MachineTrust{Provider: "oidc", Issuer: f.trust.Issuer, JwksUrl: f.trust.JWKSURL, Audience: f.trust.Audience, Claims: f.trust.Claims}}, machineBearer(f.human))
	if err != nil || registered.JSON201 == nil {
		t.Fatal(registered, err)
	}
	machine := registered.JSON201.Id
	sequence := legacy.JSON200.RenewalSequence + 1
	renewed, err := f.client.RenewWorkloadSessionWithResponse(ctx, legacy.JSON200.Id, authorityv1.WorkloadRenewal{Sequence: sequence, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, workloadproof.Renew(legacy.JSON200.Id, sequence)))}, machineBearer(legacy.JSON200.Credential))
	if err != nil || renewed.StatusCode() != 403 {
		t.Fatal("registration left unlinked visitor session live", renewed, err)
	}
	denied, err := f.client.ExchangeWorkloadWithResponse(ctx, exchangeBody())
	if err != nil || denied.StatusCode() != 403 {
		t.Fatal("omitting machine_id bypassed separate visitor permission", denied, err)
	}
	resolved, err := f.client.ResolvePublisherGroupWorkloadWithResponse(ctx, f.group, authorityv1.ResolvePublisherGroupWorkload{Workload: "worker", Assertion: raw})
	if err != nil || resolved.StatusCode() != 403 {
		t.Fatal("omitting machine_id bypassed group resolution permission", resolved, err)
	}
	permission, err := f.client.CreateMachineWorkloadPermissionWithResponse(ctx, f.team, machine, authorityv1.MachineWorkloadPermissionRequest{ProjectKey: "equipment", Workload: "worker", Templates: []string{"equipment"}, ExpiresAt: f.now.Add(time.Hour)}, machineBearer(f.human))
	if err != nil || permission.JSON201 == nil {
		t.Fatal(permission, err)
	}
	linked, err := f.client.ExchangeWorkloadWithResponse(ctx, exchangeBody())
	if err != nil || linked.JSON200 == nil {
		t.Fatal("approved legacy exchange", linked, err)
	}
	revoked, err := f.client.RevokeMachineIdentityWithResponse(ctx, f.team, machine, machineBearer(f.human))
	if err != nil || revoked.StatusCode() != 204 {
		t.Fatal(revoked, err)
	}
	denied, err = f.client.ExchangeWorkloadWithResponse(ctx, exchangeBody())
	if err != nil || denied.StatusCode() != 403 {
		t.Fatal("legacy endpoint bypassed machine revocation", denied, err)
	}
	sequence = linked.JSON200.RenewalSequence + 1
	renewed, err = f.client.RenewWorkloadSessionWithResponse(ctx, linked.JSON200.Id, authorityv1.WorkloadRenewal{Sequence: sequence, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, workloadproof.Renew(linked.JSON200.Id, sequence)))}, machineBearer(linked.JSON200.Credential))
	if err != nil || renewed.StatusCode() != 403 {
		t.Fatal("auto-linked visitor credential bypassed revocation", renewed, err)
	}
	resolved, err = f.client.ResolvePublisherGroupWorkloadWithResponse(ctx, f.group, authorityv1.ResolvePublisherGroupWorkload{Workload: "worker", Assertion: raw})
	if err != nil || resolved.StatusCode() != 403 {
		t.Fatal("resolver bypassed revocation", resolved, err)
	}
}
