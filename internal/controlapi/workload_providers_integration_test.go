package controlapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	"github.com/tnldotdev/tnl/internal/workloadclient"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationWorkloadProviderSessions(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, provider := range []string{"vercel", "fly", "oidc"} {
		t.Run(provider, func(t *testing.T) {
			ctx := t.Context()
			dbURL := testutil.NewDisposablePostgresDatabaseURL(t, "workload_"+provider)
			if err := controlstate.Migrate(ctx, dbURL); err != nil {
				t.Fatal(err)
			}
			d, err := controlstate.Open(ctx, dbURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(d.Close)
			now := time.Now().UTC()
			human, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
			if err != nil {
				t.Fatal(err)
			}
			team := human.Identity.Memberships[0].TeamID
			trust := oidcauth.WorkloadTrust{Provider: provider, Issuer: "https://oidc.vercel.com/acme", Audience: "https://vercel.com/acme", Claims: map[string]string{"owner": "acme", "owner_id": "team_one", "project_id": "prj_store", "environment": "production"}}
			claims := map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": "owner:acme:project:storefront:environment:production", "owner": "acme", "owner_id": "team_one", "project": "storefront", "project_id": "prj_store", "environment": "production"}
			if provider == "fly" {
				trust.Issuer = "https://oidc.fly.io/acme"
				trust.Audience = "https://fly.io/acme"
				trust.Claims = map[string]string{"org_name": "acme", "org_id": "123", "app_name": "store", "app_id": "456", "machine_id": "148e21ea7e46e8"}
				claims = map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": "acme:store:store-one", "org_name": "acme", "org_id": "123", "app_name": "store", "app_id": "456", "machine_name": "store-one", "machine_id": "148e21ea7e46e8"}
			}
			if provider == "oidc" {
				trust.Issuer = "https://issuer.example/workloads"
				trust.Audience = "tnl-store"
				trust.Claims = map[string]string{"sub": "service:store", "tenant": "acme"}
				claims = map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": "service:store", "tenant": "acme"}
			}
			trust.JWKSURL = trust.Issuer + "/.well-known/jwks"
			claims["iat"], claims["nbf"], claims["exp"] = now.Unix(), now.Unix(), now.Add(10*time.Minute).Unix()
			issuer := githubtest.NewProvider(t, trust.Issuer)
			mux := http.NewServeMux()
			server := httptest.NewTLSServer(mux)
			t.Cleanup(server.Close)
			if _, err = authorityapi.Register(mux, authorityapi.Config{ControlURL: server.URL, HTTPClient: issuer.Client}, d); err != nil {
				t.Fatal(err)
			}
			h, err := NewHandler(Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, d, d, nil)
			if err != nil {
				t.Fatal(err)
			}
			mux.Handle("/", h)
			owner, err := controlclient.New(server.URL, server.Client(), human.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			configuration := controlstate.ProjectConfiguration{Publishers: map[string]controlstate.ProjectPublisherGroup{"production": {}}, Services: map[string]controlstate.ProjectServiceConfiguration{"inventory": {Publisher: "production", Target: "inventory.internal:3000"}, "models": {Publisher: "production", Protocol: "postgres", Target: "models.internal:5432"}}, Workloads: map[string]controlstate.ProjectWorkload{"storefront": {Provider: provider, Trust: trust, Services: []string{"inventory", "models"}, MaxDurationSeconds: 3600}}}
			data, _ := json.Marshal(configuration)
			var wire controlv1.ProjectConfiguration
			if err = json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			body := controlv1.ApplyProjectConfigurationRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Configuration: wire}
			applied, err := owner.ApplyProjectConfiguration(ctx, "store", body)
			if err != nil {
				t.Fatal(err)
			}
			job, err := workloadclient.New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			token := issuer.Sign(t, claims)
			identity, err := job.IdentifyPolicy(ctx, team, "store", body.SourceFingerprint, "storefront", token)
			if err != nil {
				t.Fatal("verify owner identity", err)
			}
			binding := identity.Binding
			if identity.AssertionExpiresAt.Unix() != now.Add(10*time.Minute).Unix() {
				t.Fatal("identity cache expiry did not come from the verified assertion")
			}
			session, err := job.Exchange(ctx, team, "store", body.SourceFingerprint, "storefront", token, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(session.ServiceIds) != 2 || !session.ExpiresAt.After(now.Add(59*time.Minute)) || session.LeaseExpiresAt.After(time.Now().Add(91*time.Second)) {
				t.Fatal("incorrect session bounds")
			}
			if session.Github != nil {
				t.Fatal("non-GitHub provider returned GitHub execution")
			}
			if session.Binding != binding {
				t.Fatal("exchange did not bind the verified identity")
			}
			if session.AssertionExpiresAt == nil || !session.AssertionExpiresAt.Equal(identity.AssertionExpiresAt) {
				t.Fatal("exchange omitted or changed verified assertion expiry")
			}
			claims["exp"] = now.Add(11 * time.Minute).Unix()
			rotated := issuer.Sign(t, claims)
			if current, err := job.Identify(ctx, team, "store", body.SourceFingerprint, "storefront", rotated); err != nil || current != binding {
				t.Fatal("rotating assertion changed owner identity", err)
			}
			if attached, err := job.Attach(ctx, rotated); err != nil || attached.Id != session.Id || attached.Binding != binding || !attached.ExpiresAt.Equal(session.ExpiresAt) || attached.AssertionExpiresAt == nil || attached.AssertionExpiresAt.Unix() != now.Add(11*time.Minute).Unix() {
				t.Fatal("authenticated assertion attachment changed session", err)
			}
			encoded, err := json.Marshal(session)
			if err != nil {
				t.Fatal(err)
			}
			var returned map[string]json.RawMessage
			if err = json.Unmarshal(encoded, &returned); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"github", "run_id", "run_attempt", "check_run_id"} {
				if _, found := returned[field]; found {
					t.Fatalf("%s session emitted GitHub field %s", provider, field)
				}
			}
			retry, err := job.Exchange(ctx, team, "store", body.SourceFingerprint, "storefront", token, nil)
			if err != nil || retry.Id != session.Id || retry.Credential != session.Credential || !retry.ExpiresAt.Equal(session.ExpiresAt) {
				t.Fatal("nonce retry changed fixed session", err)
			}
			other, err := workloadclient.New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			second, err := other.Exchange(ctx, team, "store", body.SourceFingerprint, "storefront", token, nil)
			if err != nil || second.Id == session.Id {
				t.Fatal("reusable provider token did not create a separately key-bound session", err)
			}
			for _, bad := range []struct{ source, name string }{{strings.Repeat("b", 64), "storefront"}, {body.SourceFingerprint, "another"}} {
				if _, err = job.Exchange(ctx, team, "store", bad.source, bad.name, token, nil); err == nil {
					t.Fatal("assertion crossed source or policy boundary")
				}
			}
			for field := range trust.Claims {
				original := claims[field]
				claims[field] = "another"
				if _, err := job.Attach(ctx, issuer.Sign(t, claims)); err == nil {
					t.Fatalf("attachment accepted wrong %s", field)
				}
				if _, err = job.Exchange(ctx, team, "store", body.SourceFingerprint, "storefront", issuer.Sign(t, claims), nil); err == nil {
					t.Fatalf("wrong %s accepted", field)
				}
				claims[field] = original
			}
			// narrowing deletes issued rights; additions cannot expand the old snapshot.
			p := (*body.Configuration.Workloads)["storefront"]
			p.Services = []string{"inventory"}
			(*body.Configuration.Workloads)["storefront"] = p
			body.ExpectedRevision = applied.Revision
			applied, err = owner.ApplyProjectConfiguration(ctx, "store", body)
			if err != nil {
				t.Fatal(err)
			}
			inventory, err := job.ListServices(ctx)
			if err != nil || len(inventory.Services) != 1 || inventory.Services[0].Service != "inventory" {
				t.Fatal("issued service snapshot did not narrow", err)
			}
			p.Services = []string{"inventory", "models"}
			(*body.Configuration.Workloads)["storefront"] = p
			body.ExpectedRevision = applied.Revision
			applied, err = owner.ApplyProjectConfiguration(ctx, "store", body)
			if err != nil {
				t.Fatal(err)
			}
			inventory, err = job.ListServices(ctx)
			if err != nil || len(inventory.Services) != 1 {
				t.Fatal("issued snapshot expanded", err)
			}
			if renewed, err := job.Renew(ctx); err != nil || !renewed.ExpiresAt.Equal(session.ExpiresAt) {
				t.Fatal("renew extended fixed window", err)
			}
			body.ExpectedRevision = applied.Revision
			body.Configuration.Workloads = nil
			if _, err = owner.ApplyProjectConfiguration(ctx, "store", body); err != nil {
				t.Fatal(err)
			}
			if _, err = job.ListServices(ctx); err == nil {
				t.Fatal("removed provider policy retained session")
			}
			if _, err = other.Renew(ctx); err == nil {
				t.Fatal("removed provider policy renewed another session")
			}
		})
	}
}
