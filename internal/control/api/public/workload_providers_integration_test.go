package public

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationWorkloadProviderSessions(t *testing.T) {
	for _, provider := range []string{"github", "vercel", "fly", "oidc", "google", "kubernetes", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			trust := oidc.WorkloadTrust{Provider: provider, Issuer: "https://oidc.vercel.com/acme", Audience: "https://vercel.com/acme", Claims: map[string]string{"owner": "acme", "owner_id": "team_one", "project": "storefront", "project_id": "prj_store", "environment": "production"}}
			claims := map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": "owner:acme:project:storefront:environment:production", "owner": "acme", "owner_id": "team_one", "project": "storefront", "project_id": "prj_store", "environment": "production"}
			if provider == "fly" {
				trust.Issuer, trust.Audience = "https://oidc.fly.io/acme", "https://control.example"
				trust.Claims = map[string]string{"org_name": "acme", "org_id": "123", "app_name": "store", "app_id": "456", "machine_id": "148e21ea7e46e8"}
				claims = map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": "acme:store:store-one", "org_name": "acme", "org_id": "123", "app_name": "store", "app_id": "456", "machine_name": "store-one", "machine_id": "148e21ea7e46e8"}
			}
			if provider == "oidc" {
				trust.Issuer, trust.Audience = "https://issuer.example/workloads", "tnl-store"
				trust.Claims = map[string]string{"sub": "service:store", "tenant": "acme"}
				claims = map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": "service:store", "tenant": "acme"}
			}
			trust.JWKSURL = trust.Issuer + "/.well-known/jwks"
			if provider == "google" {
				trust.Issuer, trust.JWKSURL, trust.Audience = config.GoogleWorkloadIssuer, config.GoogleWorkloadJWKS, "https://control.example"
				trust.Claims = map[string]string{"sub": "112010400000000710080"}
				claims = map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": trust.Claims["sub"]}
			}
			if provider == "kubernetes" {
				trust.Issuer, trust.JWKSURL, trust.Audience = "https://oidc.eks.us-west-2.amazonaws.com/id/example", "https://oidc.eks.us-west-2.amazonaws.com/id/example/keys", "https://control.example"
				trust.Claims = map[string]string{"sub": "system:serviceaccount:production:orders", "service_account_uid": "11111111-1111-4111-8111-111111111111"}
				claims = map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": trust.Claims["sub"], "kubernetes.io": map[string]any{"namespace": "production", "serviceaccount": map[string]any{"name": "orders", "uid": trust.Claims["service_account_uid"]}, "pod": map[string]any{"name": "orders-one", "uid": "22222222-2222-4222-8222-222222222222"}}}
			}
			if provider == "gitlab" {
				trust.Issuer, trust.JWKSURL, trust.Audience = "https://gitlab.example", "https://gitlab.example/oauth/discovery/keys", "https://control.example"
				trust.Claims = map[string]string{"job_project_id": "123", "job_namespace_id": "456", "job_project_path": "shop/storefront", "job_namespace_path": "shop", "ref_path": "refs/heads/trunk", "pipeline_source": "push"}
				claims = map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": "project_path:shop/storefront:ref_type:branch:ref:trunk", "project_id": "123", "project_path": "shop/storefront", "namespace_id": "456", "namespace_path": "shop", "job_project_id": "123", "job_project_path": "shop/storefront", "job_namespace_id": "456", "job_namespace_path": "shop", "pipeline_id": "1001", "job_id": "2001", "pipeline_source": "push", "ref": "trunk", "ref_type": "branch", "ref_path": "refs/heads/trunk", "sha": strings.Repeat("a", 40)}
			}
			if provider == "github" {
				trust = oidc.WorkloadTrust{Provider: "github", Issuer: oidc.GitHubIssuer, JWKSURL: oidc.GitHubIssuer + "/.well-known/jwks", Events: []string{"push", "workflow_dispatch"}, Claims: map[string]string{"repository": "example/repository", "repository_id": "12345", "repository_owner_id": "6789", "workflow_ref": "example/repository/.github/workflows/test.yml@refs/heads/main", "ref": "refs/heads/main", "environment": "ci", "job_workflow_ref": "example/shared/.github/workflows/reuse.yml@refs/tags/v1"}}
			}
			f := newRetainedVisitorHTTPFixture(t, trust, map[string]controlv1.ServiceDefinitionService{"inventory": {Protocol: "http"}, "models": {Protocol: "postgres"}}, controlv1.EnvironmentTargets{"inventory": {Address: new("inventory.internal:3000")}, "models": {Address: new("models.internal:5432")}})
			trust = f.trust
			t.Run("manager approval", func(t *testing.T) {
				f.rejectInvalidProviderTrust(t)
			})
			if t.Failed() {
				return
			}
			proofExpiry, nextProofExpiry := now.Add(10*time.Minute), now.Add(11*time.Minute)
			if provider == "github" {
				claims = githubtest.Claims(f.server.URL, now)
				claims["environment"], claims["job_workflow_ref"] = trust.Claims["environment"], trust.Claims["job_workflow_ref"]
				proofExpiry, nextProofExpiry = now.Add(5*time.Minute), now.Add(6*time.Minute)
			}
			claims["iat"], claims["nbf"], claims["exp"] = now.Unix(), now.Unix(), proofExpiry.Unix()
			ctx := t.Context()
			verifier, err := oidc.NewWorkloadVerifier(f.server.URL, f.issuer.Client)
			if err != nil {
				t.Fatal(err)
			}
			token := f.issuer.Sign(t, claims)
			verified, err := verifier.Verify(ctx, trust, token)
			if err != nil || (verified.GitHub != nil) != (provider == "github") {
				t.Fatal("provider verification lost its source identity", err)
			}
			job, err := workload.New(f.server.URL, f.server.Client())
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := job.Prepare(ctx, f.environment.Ref, f.permission, token, f.services)
			if err != nil {
				t.Fatal(err)
			}
			session := prepared.Session
			var savedProvider string
			var savedClaims []byte
			if err := f.inspect.QueryRow(ctx, `SELECT provider,claims FROM control.workload_sessions WHERE id=$1`, session.Id).Scan(&savedProvider, &savedClaims); err != nil {
				t.Fatal(err)
			}
			var admitted oidc.WorkloadExecution
			if err := json.Unmarshal(savedClaims, &admitted); err != nil || savedProvider != provider || admitted.Validate(time.Now()) != nil || admitted.IdentityDigest() != verified.IdentityDigest() || !admitted.Matches(trust) {
				t.Fatal("HTTP admission did not retain the verified provider execution", err)
			}
			binding := job.Binding()
			if len(session.ServiceIds) != 2 || session.ExpiresAt == nil || !session.ExpiresAt.After(now.Add(59*time.Minute)) || session.LeaseExpiresAt.After(time.Now().Add(91*time.Second)) || session.IdentityExpiresAt.Unix() != proofExpiry.Unix() {
				t.Fatal("incorrect session/proof bounds")
			}
			claims["iat"], claims["nbf"], claims["exp"] = now.Add(time.Second).Unix(), now.Add(time.Second).Unix(), nextProofExpiry.Unix()
			if provider == "github" {
				claims["jti"] = "rotated-job-proof"
			}
			rotated := f.issuer.Sign(t, claims)
			if current, err := verifier.Verify(ctx, trust, rotated); err != nil || current.IdentityDigest() != verified.IdentityDigest() {
				t.Fatal("rotating assertion changed verified owner identity", err)
			}
			if attached, err := job.Attach(ctx, rotated); err != nil || attached.Id != session.Id || job.Binding() != binding || !attached.ExpiresAt.Equal(*session.ExpiresAt) || attached.IdentityExpiresAt.Unix() != nextProofExpiry.Unix() {
				t.Fatal("same-identity attachment changed session or omitted verified expiry", err)
			}
			if provider == "github" || provider == "kubernetes" || provider == "gitlab" {
				execution, key, next := claims, "job_id", "2002"
				if provider == "github" {
					key, next = "check_run_id", "223"
				}
				if provider == "kubernetes" {
					execution, key, next = claims["kubernetes.io"].(map[string]any)["pod"].(map[string]any), "uid", "33333333-3333-4333-8333-333333333333"
				}
				original := execution[key]
				execution[key] = next
				replacementToken := f.issuer.Sign(t, claims)
				replaced, err := verifier.Verify(ctx, trust, replacementToken)
				if err != nil || replaced.IdentityDigest() == verified.IdentityDigest() {
					t.Fatal("replacement execution reused verified source binding", err)
				}
				before := f.providerAuthority(t)
				if _, err := job.Attach(ctx, replacementToken); err == nil {
					t.Fatal("replacement execution attached to original session")
				}
				if _, err := job.Prepare(ctx, f.environment.Ref, f.permission, replacementToken, f.services); err == nil {
					t.Fatal("replacement execution reused original nonce")
				}
				if !reflect.DeepEqual(before, f.providerAuthority(t)) {
					t.Fatal("rejected replacement execution wrote authority")
				}
				replacement, err := workload.New(f.server.URL, f.server.Client())
				if err != nil {
					t.Fatal(err)
				}
				separate, err := replacement.Prepare(ctx, f.environment.Ref, f.permission, replacementToken, f.services)
				if err != nil || separate.Session.Id == session.Id {
					t.Fatal("replacement execution did not receive separate authority", err)
				}
				if err := replacement.Revoke(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := job.ListServices(ctx); err != nil {
					t.Fatal("replacement cleanup revoked original execution", err)
				}
				execution[key] = original
			}
			encoded, err := json.Marshal(session)
			if err != nil {
				t.Fatal(err)
			}
			var returned map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &returned); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"github", "run_id", "run_attempt", "check_run_id", "binding", "assertion"} {
				if _, found := returned[field]; found {
					t.Fatal("native session exposed provider metadata", provider, field)
				}
			}
			retry, err := job.Prepare(ctx, f.environment.Ref, f.permission, token, f.services)
			if err != nil || retry.Session.Id != session.Id || retry.Session.Credential != session.Credential || !retry.Session.ExpiresAt.Equal(*session.ExpiresAt) {
				t.Fatal("nonce retry changed fixed session", err)
			}
			other, err := workload.New(f.server.URL, f.server.Client())
			if err != nil {
				t.Fatal(err)
			}
			second, err := other.Prepare(ctx, f.environment.Ref, f.permission, token, f.services)
			if err != nil || second.Session.Id == session.Id {
				t.Fatal("reusable provider token did not create separately key-bound session", err)
			}
			wrongRef := f.environment.Ref
			wrongRef.ProjectKey = "another"
			if _, err := job.Prepare(ctx, wrongRef, f.permission, token, f.services); err == nil {
				t.Fatal("assertion crossed project boundary")
			}
			if _, err := job.Prepare(ctx, f.environment.Ref, f.machine, token, f.services); err == nil {
				t.Fatal("identity reference granted visitor access without permission")
			}
			for field := range trust.Claims {
				selected, key := claims, field
				if provider == "kubernetes" && field == "service_account_uid" {
					selected, key = claims["kubernetes.io"].(map[string]any)["serviceaccount"].(map[string]any), "uid"
				}
				original := selected[key]
				selected[key] = "another"
				if field == "service_account_uid" {
					selected[key] = "44444444-4444-4444-8444-444444444444"
				}
				bad := f.issuer.Sign(t, claims)
				if _, err := verifier.Verify(ctx, trust, bad); err == nil {
					t.Fatal("verifier accepted wrong provider claim", field)
				}
				f.rejectProviderProof(t, job, bad)
				selected[key] = original
			}
			if provider == "kubernetes" {
				for _, test := range []struct {
					name string
					edit func(map[string]any)
				}{
					{"unbound account", func(k map[string]any) { delete(k, "pod") }},
					{"missing namespace", func(k map[string]any) { delete(k, "namespace") }},
					{"wrong namespace", func(k map[string]any) { k["namespace"] = "another" }},
					{"wrong account name", func(k map[string]any) { k["serviceaccount"].(map[string]any)["name"] = "another" }},
					{"malformed account uid", func(k map[string]any) { k["serviceaccount"].(map[string]any)["uid"] = 123 }},
					{"missing pod name", func(k map[string]any) { delete(k["pod"].(map[string]any), "name") }},
					{"invalid pod name", func(k map[string]any) { k["pod"].(map[string]any)["name"] = "../other" }},
					{"missing pod uid", func(k map[string]any) { delete(k["pod"].(map[string]any), "uid") }},
					{"malformed pod uid", func(k map[string]any) { k["pod"].(map[string]any)["uid"] = "not-a-uid" }},
				} {
					t.Run(test.name, func(t *testing.T) {
						encoded, _ := json.Marshal(claims)
						var invalid map[string]any
						if err := json.Unmarshal(encoded, &invalid); err != nil {
							t.Fatal(err)
						}
						test.edit(invalid["kubernetes.io"].(map[string]any))
						f.rejectProviderProof(t, job, f.issuer.Sign(t, invalid))
					})
				}
			}
			if provider == "github" {
				for _, field := range []string{"run_id", "run_attempt", "check_run_id", "event_name"} {
					original := claims[field]
					claims[field] = "999"
					if field == "event_name" {
						claims[field] = "pull_request"
					}
					before := f.providerAuthority(t)
					if _, err := job.Attach(ctx, f.issuer.Sign(t, claims)); err == nil {
						t.Fatal("different GitHub execution attached to original session", field)
					}
					if !reflect.DeepEqual(before, f.providerAuthority(t)) {
						t.Fatal("rejected GitHub execution wrote authority", field)
					}
					if field == "event_name" {
						f.rejectProviderProof(t, job, f.issuer.Sign(t, claims))
					}
					claims[field] = original
				}
				for _, field := range []string{"run_id", "run_attempt", "check_run_id", "jti"} {
					original := claims[field]
					delete(claims, field)
					f.rejectProviderProof(t, job, f.issuer.Sign(t, claims))
					claims[field] = 123
					f.rejectProviderProof(t, job, f.issuer.Sign(t, claims))
					claims[field] = original
				}
				original := claims["event_name"]
				claims["event_name"] = "workflow_dispatch"
				allowed, err := workload.New(f.server.URL, f.server.Client())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := allowed.Prepare(ctx, f.environment.Ref, f.permission, f.issuer.Sign(t, claims), f.services); err != nil {
					t.Fatal("HTTP rejected second approved GitHub event", err)
				}
				if err := allowed.Revoke(ctx); err != nil {
					t.Fatal(err)
				}
				claims["event_name"] = original
			}
			// removing a service narrows availability. rolling the definition back
			// allocates a new ID and cannot give that replacement to the old session.
			narrow, err := f.owner.CreateServiceDefinition(ctx, "example", controlv1.CreateServiceDefinitionRequest{TeamId: f.team, SourceFingerprint: strings.Repeat("a", 64), Definition: controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{"inventory": {Protocol: "http"}}}})
			if err != nil {
				t.Fatal(err)
			}
			removed, err := f.owner.ApplyEnvironment(ctx, "example", f.environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: narrow.Revision})
			if err != nil {
				t.Fatal(err)
			}
			inventory, err := job.ListServices(ctx)
			if err != nil || len(inventory.Services) != 1 || inventory.Services[0].Service != "inventory" || inventory.Services[0].Id != prepared.Services["inventory"].ServiceId {
				t.Fatal("issued service availability did not narrow", err)
			}
			rolled, err := f.owner.ApplyEnvironment(ctx, "example", f.environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: removed.MutationRevision, DefinitionRevision: f.environment.AppliedDefinitionRevision, Targets: &f.environment.Targets})
			if err != nil {
				t.Fatal(err)
			}
			inventory, err = job.ListServices(ctx)
			if err != nil || len(inventory.Services) != 1 {
				t.Fatal("rollback expanded issued snapshot", err)
			}
			for _, s := range rolled.Services {
				if s.Service == "models" {
					if s.ServiceId == prepared.Services["models"].ServiceId {
						t.Fatal("rollback reused retired ID")
					}
					if _, err := job.CheckService(ctx, s.ServiceId); err == nil {
						t.Fatal("old session reached replacement service")
					}
				}
			}
			if renewed, err := job.Renew(ctx); err != nil || !renewed.ExpiresAt.Equal(*session.ExpiresAt) {
				t.Fatal("renew extended fixed window", err)
			}
			revoked, err := f.authority.RevokeEnvironmentVisitorPermissionWithResponse(ctx, f.team, f.permission, retainedVisitorBearer(f.human.AccessToken.String()))
			if err != nil || revoked.StatusCode() != 204 {
				t.Fatal("revoke exact permission", err)
			}
			if _, err := job.ListServices(ctx); err == nil {
				t.Fatal("revoked permission retained session")
			}
			if _, err := other.Renew(ctx); err == nil {
				t.Fatal("revoked permission renewed another session")
			}
			if _, err := f.owner.ApplyEnvironment(ctx, "example", f.environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: rolled.MutationRevision, DefinitionRevision: f.environment.AppliedDefinitionRevision}); err != nil {
				t.Fatal(err)
			}
			if _, err := job.ListServices(ctx); err == nil {
				t.Fatal("definition apply restored revoked permission")
			}
		})
	}
}

func (f *workloadExchangeRetryFixture) providerAuthority(t *testing.T) []byte {
	t.Helper()
	var snapshot []byte
	if err := f.inspect.QueryRow(t.Context(), `SELECT jsonb_build_object(
		'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM control.workload_sessions s WHERE s.team_id=$1),
		'machines',(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.session_id) FROM control.workload_session_machines m JOIN control.workload_sessions s ON s.id=m.session_id WHERE s.team_id=$1),
		'services',(SELECT jsonb_agg(to_jsonb(v) ORDER BY v.workload_session_id,v.service_id) FROM control.workload_session_services v JOIN control.workload_sessions s ON s.id=v.workload_session_id WHERE s.team_id=$1),
		'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.workload_session_id,a.occurred_at,a.event,a.service_id) FROM control.workload_audit a JOIN control.workload_sessions s ON s.id=a.workload_session_id WHERE s.team_id=$1),
		'assertions',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.jti_digest) FROM control.workload_assertions a JOIN control.workload_sessions s ON s.id=a.workload_session_id WHERE s.team_id=$1),
		'proof_uses',(SELECT jsonb_agg(to_jsonb(u) ORDER BY u.proof_digest) FROM control.machine_proof_uses u WHERE u.machine_id=$2)
	)::text`, f.team, f.machine).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func (f *workloadExchangeRetryFixture) rejectInvalidProviderTrust(t *testing.T) {
	t.Helper()
	saved := func() []byte {
		t.Helper()
		var snapshot []byte
		if err := f.inspect.QueryRow(t.Context(), `SELECT jsonb_agg(to_jsonb(m) ORDER BY m.id)::text FROM control.machine_identities m WHERE team_id=$1`, f.team).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	before := saved()
	for _, test := range []struct {
		name string
		edit func(*oidc.WorkloadTrust)
	}{
		{"invalid issuer", func(p *oidc.WorkloadTrust) { p.Issuer = "http://issuer.example" }},
		{"wildcard audience", func(p *oidc.WorkloadTrust) { p.Audience = "*" }},
		{"missing stable identity", func(p *oidc.WorkloadTrust) {
			delete(p.Claims, map[string]string{"github": "repository_id", "vercel": "project_id", "fly": "app_id", "google": "sub", "kubernetes": "service_account_uid", "gitlab": "job_project_id", "oidc": "sub"}[p.Provider])
		}},
		{"unsupported events", func(p *oidc.WorkloadTrust) { p.Events = []string{} }},
		{"reserved claim", func(p *oidc.WorkloadTrust) { p.Claims["exp"] = "123" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(f.trust)
			if err != nil {
				t.Fatal(err)
			}
			var invalid oidc.WorkloadTrust
			if err := json.Unmarshal(encoded, &invalid); err != nil {
				t.Fatal(err)
			}
			test.edit(&invalid)
			wire := &authorityv1.MachineTrust{Provider: authorityv1.MachineTrustProvider(invalid.Provider), Issuer: invalid.Issuer, JwksUrl: invalid.JWKSURL, Audience: invalid.Audience, Claims: invalid.Claims}
			if invalid.Events != nil {
				wire.Events = &invalid.Events
			}
			r, err := f.authority.RegisterMachineIdentityWithResponse(t.Context(), f.team, authorityv1.RegisterMachineRequest{Name: "invalid-provider-policy", ProofKind: "oidc", Trust: wire}, retainedVisitorBearer(f.human.AccessToken.String()))
			if err != nil || r.StatusCode() != 400 {
				t.Fatal("HTTP accepted invalid manager-saved provider trust", r, err)
			}
			if !reflect.DeepEqual(before, saved()) {
				t.Fatal("rejected provider registration wrote a machine identity")
			}
		})
	}
}

func (f *workloadExchangeRetryFixture) rejectProviderProof(t *testing.T, job *workload.Client, assertion string) {
	t.Helper()
	before := f.providerAuthority(t)
	current, err := job.Session()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := job.Attach(t.Context(), assertion); err == nil {
		t.Fatal("HTTP attachment accepted invalid provider proof")
	}
	if _, err := job.Prepare(t.Context(), f.environment.Ref, f.permission, assertion, f.services); err == nil {
		t.Fatal("HTTP nonce retry accepted invalid provider proof")
	}
	fresh, err := workload.New(f.server.URL, f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Prepare(t.Context(), f.environment.Ref, f.permission, assertion, f.services); err == nil {
		t.Fatal("HTTP fresh admission accepted invalid provider proof")
	}
	after, err := job.Session()
	if err != nil || !reflect.DeepEqual(current, after) || !reflect.DeepEqual(before, f.providerAuthority(t)) {
		t.Fatal("rejected provider proof changed accepted authority", err)
	}
}
