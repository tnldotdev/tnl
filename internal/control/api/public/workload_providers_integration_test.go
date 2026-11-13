package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationWorkloadProviderSessions(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, provider := range []string{"vercel", "fly", "oidc", "google", "kubernetes", "gitlab"} {
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
			trust := oidc.WorkloadTrust{Provider: provider, Issuer: "https://oidc.vercel.com/acme", Audience: "https://vercel.com/acme", Claims: map[string]string{"owner": "acme", "owner_id": "team_one", "project": "storefront", "project_id": "prj_store", "environment": "production"}}
			claims := map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": "owner:acme:project:storefront:environment:production", "owner": "acme", "owner_id": "team_one", "project": "storefront", "project_id": "prj_store", "environment": "production"}
			if provider == "fly" {
				trust.Issuer = "https://oidc.fly.io/acme"
				trust.Audience = "https://control.example"
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
			claims["iat"], claims["nbf"], claims["exp"] = now.Unix(), now.Unix(), now.Add(10*time.Minute).Unix()
			issuer := githubtest.NewKeySet(t, trust.JWKSURL)
			mux := http.NewServeMux()
			server := httptest.NewTLSServer(mux)
			t.Cleanup(server.Close)
			if _, err = controlauthority.Register(mux, controlauthority.Config{ControlURL: server.URL, HTTPClient: issuer.Client}, d); err != nil {
				t.Fatal(err)
			}
			h, err := NewHandler(Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, DatabaseStores(d), d, nil)
			if err != nil {
				t.Fatal(err)
			}
			mux.Handle("/", h)
			owner, err := clientcontrol.New(server.URL, server.Client(), human.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			configuration := controlstate.ProjectConfiguration{PublisherGroups: map[string]controlstate.ProjectPublisherGroup{"production": {}}, Services: map[string]controlstate.ProjectServiceConfiguration{"inventory": {PublisherGroup: "production", Target: "inventory.internal:3000"}, "models": {PublisherGroup: "production", Protocol: "postgres", Target: "models.internal:5432"}}, Workloads: map[string]controlstate.ProjectWorkload{"storefront": {Provider: provider, Trust: trust, Services: []string{"inventory", "models"}, MaxDurationSeconds: 3600}}}
			if provider == "google" {
				p := configuration.Workloads["storefront"]
				p.Google = &controlstate.ProjectWorkloadGoogle{ServiceAccount: "orders@project.iam.gserviceaccount.com"}
				configuration.Workloads["storefront"] = p
			}
			if provider == "kubernetes" {
				p := configuration.Workloads["storefront"]
				p.Kubernetes = &controlstate.ProjectWorkloadKubernetes{Context: "eks-development", ClusterServer: "https://cluster.example.test", Namespace: "production", ServiceAccount: "orders"}
				configuration.Workloads["storefront"] = p
			}
			if provider == "gitlab" {
				p := configuration.Workloads["storefront"]
				p.GitLab = &controlstate.ProjectWorkloadGitLab{Server: "https://gitlab.example", Project: "shop/storefront", ProjectId: "123", NamespaceId: "456", DefaultBranch: new("trunk")}
				configuration.Workloads["storefront"] = p
			}
			data, _ := json.Marshal(configuration)
			var wire controlv1.ProjectConfiguration
			if err = json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			body := controlv1.ApplyProjectConfigurationRequest{TeamId: team, Source: &testProjectSource, Configuration: wire}
			applied, err := owner.ApplyProjectConfiguration(ctx, "store", body)
			if err != nil {
				t.Fatal(err)
			}
			job, err := workload.New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			token := issuer.Sign(t, claims)
			identity, err := job.IdentifyPolicy(ctx, team, "store", applied.SourceFingerprint, "storefront", token)
			if err != nil {
				t.Fatal("verify owner identity", err)
			}
			binding := identity.Binding
			if identity.AssertionExpiresAt.Unix() != now.Add(10*time.Minute).Unix() {
				t.Fatal("identity cache expiry did not come from the verified assertion")
			}
			session, err := job.Exchange(ctx, team, "store", applied.SourceFingerprint, "storefront", token, nil)
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
			if current, err := job.Identify(ctx, team, "store", applied.SourceFingerprint, "storefront", rotated); err != nil || current != binding {
				t.Fatal("rotating assertion changed owner identity", err)
			}
			if attached, err := job.Attach(ctx, rotated); err != nil || attached.Id != session.Id || attached.Binding != binding || !attached.ExpiresAt.Equal(*session.ExpiresAt) || attached.AssertionExpiresAt == nil || attached.AssertionExpiresAt.Unix() != now.Add(11*time.Minute).Unix() {
				t.Fatal("authenticated assertion attachment changed session", err)
			}
			if provider == "kubernetes" || provider == "gitlab" {
				execution, key, next := claims, "job_id", "2002"
				if provider == "kubernetes" {
					execution, key, next = claims["kubernetes.io"].(map[string]any)["pod"].(map[string]any), "uid", "33333333-3333-4333-8333-333333333333"
				}
				original := execution[key]
				execution[key] = next
				replacementToken := issuer.Sign(t, claims)
				replacementBinding, err := job.Identify(ctx, team, "store", applied.SourceFingerprint, "storefront", replacementToken)
				if err != nil || replacementBinding == binding {
					t.Fatal("replacement execution reused the old binding", err)
				}
				before, err := job.Session()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := job.Attach(ctx, replacementToken); err == nil {
					t.Fatal("replacement execution attached proof to the old session")
				}
				after, err := job.Session()
				if err != nil || after.Id != before.Id || after.Binding != before.Binding || !after.IdentityExpiresAt.Equal(before.IdentityExpiresAt) || !after.LeaseExpiresAt.Equal(before.LeaseExpiresAt) {
					t.Fatal("rejected attachment changed current authority", err)
				}
				replacement, err := workload.New(server.URL, server.Client())
				if err != nil {
					t.Fatal(err)
				}
				replaced, err := replacement.Exchange(ctx, team, "store", applied.SourceFingerprint, "storefront", replacementToken, nil)
				if err != nil || replaced.Id == session.Id || replaced.Binding != replacementBinding {
					t.Fatal("replacement execution did not receive separate authority", err)
				}
				if err := replacement.Revoke(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := job.ListServices(ctx); err != nil {
					t.Fatal("replacement cleanup revoked the original execution", err)
				}
				execution[key] = original
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
			retry, err := job.Exchange(ctx, team, "store", applied.SourceFingerprint, "storefront", token, nil)
			if err != nil || retry.Id != session.Id || retry.Credential != session.Credential || !retry.ExpiresAt.Equal(*session.ExpiresAt) {
				t.Fatal("nonce retry changed fixed session", err)
			}
			other, err := workload.New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			second, err := other.Exchange(ctx, team, "store", applied.SourceFingerprint, "storefront", token, nil)
			if err != nil || second.Id == session.Id {
				t.Fatal("reusable provider token did not create a separately key-bound session", err)
			}
			for _, bad := range []struct{ source, name string }{{strings.Repeat("b", 64), "storefront"}, {applied.SourceFingerprint, "another"}} {
				if _, err = job.Exchange(ctx, team, "store", bad.source, bad.name, token, nil); err == nil {
					t.Fatal("assertion crossed source or policy boundary")
				}
			}
			for field := range trust.Claims {
				selected, key := claims, field
				if provider == "kubernetes" && field == "service_account_uid" {
					selected = claims["kubernetes.io"].(map[string]any)["serviceaccount"].(map[string]any)
					key = "uid"
				}
				original := selected[key]
				selected[key] = "another"
				if provider == "kubernetes" && field == "service_account_uid" {
					selected[key] = "44444444-4444-4444-8444-444444444444"
				}
				if _, err := job.Attach(ctx, issuer.Sign(t, claims)); err == nil {
					t.Fatalf("attachment accepted wrong %s", field)
				}
				if _, err = job.Exchange(ctx, team, "store", applied.SourceFingerprint, "storefront", issuer.Sign(t, claims), nil); err == nil {
					t.Fatalf("wrong %s accepted", field)
				}
				selected[key] = original
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
			if renewed, err := job.Renew(ctx); err != nil || !renewed.ExpiresAt.Equal(*session.ExpiresAt) {
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
