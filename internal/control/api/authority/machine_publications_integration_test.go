package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestIntegrationMachinePublicationNativeCleanupWithoutSource(t *testing.T) {
	f := newMachineAPIFixture(t)
	ctx := t.Context()
	app := f.application(t)
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	registered, err := f.client.RegisterMachineIdentityWithResponse(ctx, f.team, authorityv1.RegisterMachineRequest{Name: "cleanup", ProofKind: "oidc", Trust: &authorityv1.MachineTrust{Provider: "oidc", Issuer: f.trust.Issuer, JwksUrl: f.trust.JWKSURL, Audience: f.trust.Audience, Claims: f.trust.Claims}}, machineBearer(f.human))
	if err != nil || registered.JSON201 == nil {
		t.Fatal(registered, err)
	}
	namespace := "cleanup." + app.Namespace
	permission, err := f.client.CreateMachinePublicationPermissionWithResponse(ctx, f.team, registered.JSON201.Id, authorityv1.MachinePublicationPermissionRequest{Namespace: namespace, DomainId: app.DomainID, ExpiresAt: f.now.Add(time.Hour)}, machineBearer(f.human))
	if err != nil || permission.JSON201 == nil {
		t.Fatal(permission, err)
	}
	raw, nonce, encoded := f.issuer.Sign(t, f.claims()), rand.Text(), base64.RawURLEncoding.EncodeToString(public)
	signature := ed25519.Sign(key, machineproof.PublicationPossession("", namespace, "exchange", encoded, nonce, sha256.Sum256([]byte(raw))))
	exchanged, err := f.client.ExchangeMachinePublicationWithResponse(ctx, authorityv1.MachinePublicationExchange{Namespace: namespace, Nonce: nonce, PublicKey: encoded, Assertion: raw, Signature: base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil || exchanged.JSON200 == nil {
		t.Fatal(exchanged, err)
	}
	session := exchanged.JSON200
	p, err := f.d.AuthenticatePublisherAccess(ctx, session.AccessToken, "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	u, err := f.d.AllocatePublisherPublicURL(ctx, p, invocation, "http://127.0.0.1:3000", nil, nil, f.now, controlstate.PublisherPublicURLOptions{AccessMode: controlstate.VisitorAccessRestricted})
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := f.client.RevokeMachinePublicationPermissionWithResponse(ctx, f.team, permission.JSON201.Id, machineBearer(f.human)); err != nil || revoked.StatusCode() != 204 {
		t.Fatal(revoked, err)
	}
	audience := f.server.URL + "/v1/machine-publication-sessions/" + session.Id + "/cleanup"
	proof, err := publisherproof.Sign(p.ID, session.Publisher.KeyId, machineproof.PublicationCleanup(session.Id, invocation), audience, key, f.now)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongKey, _ := ed25519.GenerateKey(rand.Reader)
	badProof, err := publisherproof.Sign(p.ID, session.Publisher.KeyId, machineproof.PublicationCleanup(session.Id, invocation), audience, wrongKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := f.client.CleanupMachinePublicationWithResponse(ctx, session.Id, authorityv1.MachinePublicationCleanup{InvocationId: invocation, Assertion: badProof})
	if err != nil || denied.StatusCode() != 403 {
		t.Fatal("foreign native key removed allocation", denied, err)
	}
	for range 2 {
		response, err := f.client.CleanupMachinePublicationWithResponse(ctx, session.Id, authorityv1.MachinePublicationCleanup{InvocationId: invocation, Assertion: proof})
		if err != nil || response.StatusCode() != 204 || response.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cleanup required revoked source authority or failed retry", response, err)
		}
	}
	u, err = f.d.GetPublicURLForAuthorization(ctx, u.ID)
	if !errors.Is(err, controlstate.ErrPublicURLNotFound) {
		t.Fatal("native cleanup did not remove original allocation", err)
	}
}

func (f machineAPIFixture) application(t *testing.T) controlstate.PublicURL {
	t.Helper()
	identity, err := f.d.IdentityContext(t.Context(), f.actor)
	if err != nil {
		t.Fatal(err)
	}
	var member controlstate.Membership
	for _, m := range identity.Memberships {
		if m.TeamID == f.team {
			member = m
		}
	}
	domains, err := f.d.ListTeamDomains(t.Context(), f.actor, f.team)
	if err != nil || len(domains) != 1 {
		t.Fatal(domains, err)
	}
	domain := domains[0]
	ns, _ := naming.PublicURLNamespace(naming.NamespaceFacts{Domain: domain.CanonicalDomain, Managed: domain.Kind == controlstate.DomainKindManaged, Mode: naming.ManagedURLModeSimple, Personal: member.TeamKind == controlstate.TeamKindPersonal, TeamName: member.TeamDisplayName, MemberSlug: member.MemberSlug, ManagedLabel: member.ManagedLabel})
	scope := controlstate.PublicURLScopeMember
	membership := member.ID
	// simple personal namespaces are team-owned, as in regular tnl publish.
	_, direct := naming.PublicURLNamespace(naming.NamespaceFacts{Domain: domain.CanonicalDomain, Managed: domain.Kind == controlstate.DomainKindManaged, Mode: naming.ManagedURLModeSimple, Personal: member.TeamKind == controlstate.TeamKindPersonal, TeamName: member.TeamDisplayName, MemberSlug: member.MemberSlug, ManagedLabel: member.ManagedLabel})
	if direct {
		scope = controlstate.PublicURLScopeShared
		membership = ""
	}
	u, err := f.d.CreatePublicURL(t.Context(), controlstate.CreatePublicURLRequest{TeamID: f.team, DomainID: domain.ID, MembershipID: membership, ActingIdentityID: f.actor, CanonicalHostname: "app." + ns, Target: "http://127.0.0.1:3000", PublicURLScope: scope, Purpose: controlstate.PublicURLPurposeApp, IdempotencyKey: "application", DNSState: controlstate.PublicURLDNSUnmanaged, ManagedURLMode: naming.ManagedURLModeSimple}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestIntegrationMachinePublicationAuthorityWithoutOIDCIdentitySelector(t *testing.T) {
	for _, kind := range []authorityv1.RegisterMachineRequestProofKind{"oidc", "signing_key"} {
		t.Run(string(kind), func(t *testing.T) {
			f := newMachineAPIFixture(t)
			ctx := t.Context()
			app := f.application(t)
			identityPublic, identityKey, _ := ed25519.GenerateKey(rand.Reader)
			registration := authorityv1.RegisterMachineRequest{Name: "publisher", ProofKind: kind}
			if kind == "oidc" {
				registration.Trust = &authorityv1.MachineTrust{Provider: "oidc", Issuer: f.trust.Issuer, JwksUrl: f.trust.JWKSURL, Audience: f.trust.Audience, Claims: f.trust.Claims}
			} else {
				registration.KeyId = new("first")
				registration.PublicKey = new(base64.RawURLEncoding.EncodeToString(identityPublic))
			}
			registered, err := f.client.RegisterMachineIdentityWithResponse(ctx, f.team, registration, machineBearer(f.human))
			if err != nil || registered.JSON201 == nil {
				t.Fatal(registered, err)
			}
			machine := registered.JSON201.Id
			permission, err := f.client.CreateMachinePublicationPermissionWithResponse(ctx, f.team, machine, authorityv1.MachinePublicationPermissionRequest{Resource: app.ID, ExpiresAt: f.now.Add(time.Hour)}, machineBearer(f.human))
			if err != nil || permission.JSON201 == nil {
				t.Fatal(permission, err)
			}
			public, key, _ := ed25519.GenerateKey(rand.Reader)
			encoded := base64.RawURLEncoding.EncodeToString(public)
			nonce := rand.Text()
			raw := f.issuer.Sign(t, f.claims())
			request := authorityv1.MachinePublicationExchange{Resource: app.ID, Nonce: nonce, PublicKey: encoded}
			if kind == "signing_key" {
				request.MachineId = machine
				raw, err = publisherproof.Sign(machine, "first", machineproof.Publication(app.ID, "", "exchange", encoded, nonce), f.server.URL+"/v1/machine-publication-sessions/exchange", identityKey, f.now)
				if err != nil {
					t.Fatal(err)
				}
			}
			sign := func() {
				digest := sha256.Sum256([]byte(raw))
				request.Assertion = raw
				request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, machineproof.PublicationPossession(request.Resource, request.Namespace, "exchange", encoded, request.Nonce, digest)))
			}
			sign()
			session, err := f.client.ExchangeMachinePublicationWithResponse(ctx, request)
			if err != nil || session.JSON200 == nil {
				t.Fatal("publication auth requires no OIDC identity or grant selector", session, err)
			}
			if session.JSON200.Publisher.ClientId == "" || session.JSON200.Publisher.PublicUrlId == nil || *session.JSON200.Publisher.PublicUrlId != app.ID || session.JSON200.TokenType != "Bearer" {
				t.Fatal("incorrect publisher response", session.JSON200)
			}
			if strings.Contains(string(session.Body), "target") || strings.Contains(string(session.Body), f.trust.Issuer) {
				t.Fatal("publication response leaked target or candidate trust")
			}
			if kind == "oidc" {
				// the exact same platform assertion can authenticate a separately
				// approved provisioning purpose; neither API requires machine_id.
				grant, e := f.client.CreateProvisioningGrantWithResponse(ctx, f.team, machine, authorityv1.ProvisioningGrantRequest{ProjectKey: "equipment", Templates: []string{"equipment"}, Operations: []authorityv1.ProvisioningOperation{authorityv1.ProvisioningRead}, ExpiresAt: f.now.Add(time.Hour)}, machineBearer(f.human))
				if e != nil || grant.JSON201 == nil {
					t.Fatal(grant, e)
				}
				provisioned, e := f.client.ExchangeProvisioningWithResponse(ctx, authorityv1.ProvisioningExchange{GrantId: grant.JSON201.Id, Operation: authorityv1.ProvisioningRead, Assertion: raw})
				if e != nil || provisioned.JSON200 == nil {
					t.Fatal("same OIDC proof or missing identity selector rejected", provisioned, e)
				}
				request.Nonce = rand.Text()
				sign()
				again, e := f.client.ExchangeMachinePublicationWithResponse(ctx, request)
				if e != nil || again.JSON200 == nil {
					t.Fatal("reusable platform assertion consumed", again, e)
				}
			}
			bad := request
			bad.Resource = "public_url_unknown"
			denied, err := f.client.ExchangeMachinePublicationWithResponse(ctx, bad)
			if err != nil || denied.StatusCode() != 403 || strings.Contains(string(denied.Body), machine) || strings.Contains(string(denied.Body), f.trust.Issuer) {
				t.Fatal("unknown resource leaked policy", denied, err)
			}
			id := session.JSON200.Id
			if kind == "signing_key" {
				raw, err = publisherproof.Sign(machine, "first", machineproof.Publication(app.ID, "", "refresh", encoded, id), f.server.URL+"/v1/machine-publication-sessions/"+id+"/refresh", identityKey, f.now)
				if err != nil {
					t.Fatal(err)
				}
			}
			digest := sha256.Sum256([]byte(raw))
			signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, machineproof.PublicationPossession(app.ID, "", "refresh", encoded, id, digest)))
			refreshed, err := f.client.RefreshMachinePublicationWithResponse(ctx, id, authorityv1.MachinePublicationRefresh{Assertion: raw, Signature: signature})
			if err != nil || refreshed.JSON200 == nil || refreshed.JSON200.Publisher.ClientId != session.JSON200.Publisher.ClientId {
				t.Fatal("fresh proof changed publisher", refreshed, err)
			}
			revoked, err := f.client.RevokeMachinePublicationPermissionWithResponse(ctx, f.team, permission.JSON201.Id, machineBearer(f.human))
			if err != nil || revoked.StatusCode() != 204 {
				t.Fatal(revoked, err)
			}
			deniedRefresh, err := f.client.RefreshMachinePublicationWithResponse(ctx, id, authorityv1.MachinePublicationRefresh{Assertion: raw, Signature: signature})
			if err != nil || deniedRefresh.StatusCode() != 403 {
				t.Fatal("revoked permission refreshed", deniedRefresh, err)
			}
		})
	}
}

func TestIntegrationMachinePublicationBoundedSavedTrustLookup(t *testing.T) {
	f := newMachineAPIFixture(t)
	app := f.application(t)
	ctx := t.Context()
	var first string
	for i := 0; i < 9; i++ {
		subject := "candidate-" + string(rune('a'+i))
		trust := authorityv1.MachineTrust{Provider: "oidc", Issuer: f.trust.Issuer, JwksUrl: f.trust.JWKSURL, Audience: f.trust.Audience, Claims: map[string]string{"sub": subject}}
		registered, err := f.client.RegisterMachineIdentityWithResponse(ctx, f.team, authorityv1.RegisterMachineRequest{Name: subject, ProofKind: "oidc", Trust: &trust}, machineBearer(f.human))
		if err != nil || registered.JSON201 == nil {
			t.Fatal(registered, err)
		}
		p, err := f.client.CreateMachinePublicationPermissionWithResponse(ctx, f.team, registered.JSON201.Id, authorityv1.MachinePublicationPermissionRequest{Resource: app.ID, ExpiresAt: f.now.Add(time.Hour)}, machineBearer(f.human))
		if err != nil || p.JSON201 == nil {
			t.Fatal(p, err)
		}
		if i == 0 {
			first = subject
		}
	}
	claims := f.claims()
	claims["sub"] = first
	raw := f.issuer.Sign(t, claims)
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	encoded := base64.RawURLEncoding.EncodeToString(public)
	nonce := rand.Text()
	digest := sha256.Sum256([]byte(raw))
	r, err := f.client.ExchangeMachinePublicationWithResponse(ctx, authorityv1.MachinePublicationExchange{Resource: app.ID, Assertion: raw, Nonce: nonce, PublicKey: encoded, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, machineproof.PublicationPossession(app.ID, "", "exchange", encoded, nonce, digest)))})
	if err != nil || r.JSON200 == nil {
		t.Fatal("saved hints did not narrow a multi-identity scope", r, err)
	}
	parts := strings.Split(raw, ".")
	parts[2] = "AAAA"
	forged := strings.Join(parts, ".")
	nonce = rand.Text()
	digest = sha256.Sum256([]byte(forged))
	r, err = f.client.ExchangeMachinePublicationWithResponse(ctx, authorityv1.MachinePublicationExchange{Resource: app.ID, Assertion: forged, Nonce: nonce, PublicKey: encoded, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, machineproof.PublicationPossession(app.ID, "", "exchange", encoded, nonce, digest)))})
	if err != nil || r.StatusCode() != 403 {
		t.Fatal("lookup hints were accepted as verified identity", r, err)
	}
}
