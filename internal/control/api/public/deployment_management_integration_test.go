package public

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationDeploymentManagementHTTPContracts(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "deployment_management_http")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC()
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity.Memberships[0].TeamID
	_, err = d.ApplyProjectConfiguration(ctx, controlstate.ApplyProjectConfigurationRequest{TeamID: team, ActorID: session.Identity.Identity.ID, ProjectKey: "example", SourceFingerprint: strings.Repeat("a", 64), Now: now,
		Configuration: controlstate.ProjectConfiguration{PublisherGroups: map[string]controlstate.ProjectPublisherGroup{"production": {}}, Services: map[string]controlstate.ProjectServiceConfiguration{
			"db": {PublisherGroup: "production", Protocol: "postgres", Target: "db.internal:5432"}, "web": {PublisherGroup: "production", Target: "web.internal:3000"},
		}}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Config{ManagedURLMode: naming.ManagedURLModeSimple}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	if _, err = controlauthority.Register(h, controlauthority.Config{ControlURL: server.URL}, d); err != nil {
		t.Fatal(err)
	}
	api, err := controlv1.NewClientWithResponses(server.URL, controlv1.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	auth := func(token string) controlv1.RequestEditorFn {
		return func(_ context.Context, r *http.Request) error {
			r.Header.Set("Authorization", "Bearer "+token)
			return nil
		}
	}
	manager := auth(session.AccessToken.String())
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	all := controlv1.RegisterDeploymentManagementRequestAllDeployments(true)
	body := controlv1.RegisterDeploymentManagementRequest{Name: "customer-api", PublicKey: base64.RawURLEncoding.EncodeToString(public), Services: []string{"db"}, AllDeployments: &all, ExpiresIn: 600}
	params := &controlv1.RegisterDeploymentManagementParams{TeamId: team, IdempotencyKey: "register"}
	created, err := api.RegisterDeploymentManagementWithResponse(ctx, "example", params, body, manager)
	if err != nil || created.JSON201 == nil || created.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("register: %+v %v", created, err)
	}
	credential := created.JSON201
	recovered, err := api.RegisterDeploymentManagementWithResponse(ctx, "example", params, body, manager)
	if err != nil || !bytes.Equal(created.Body, recovered.Body) {
		t.Fatal("registration retry changed public facts or deadline", err)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var valid map[string]any
	if err = json.Unmarshal(encoded, &valid); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		field string
		value any
	}{
		{"capabilities", []string{"manage", "connect", "publish"}}, {"private_key", base64.RawURLEncoding.EncodeToString(private)},
		{"all_deployments", false}, {"deployment_ids", []string{}}, {"expires_in", 9223372036854775807},
		{"services", []string{"db", "db"}}, {"services", []string{"undeclared"}}, {"public_key", "invalid"},
	} {
		invalid := maps.Clone(valid)
		invalid[test.field] = test.value
		data, err := json.Marshal(invalid)
		if err != nil {
			t.Fatal(err)
		}
		response, err := api.RegisterDeploymentManagementWithBodyWithResponse(ctx, "example", &controlv1.RegisterDeploymentManagementParams{TeamId: team, IdempotencyKey: "invalid"}, "application/json", bytes.NewReader(data), manager)
		if err != nil || response.StatusCode() != 400 || response.ApplicationproblemJSONDefault == nil || response.ApplicationproblemJSONDefault.Code != controlv1.InvalidRequest || bytes.Contains(response.Body, []byte(base64.RawURLEncoding.EncodeToString(private))) {
			t.Fatal("invalid registration escaped strict boundary or leaked key", test.field, response, err)
		}
	}
	authority, err := clientauthority.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	token, err := authority.ExchangePublisherAssertion(ctx, credential.ClientId, credential.GrantId, credential.KeyId, private)
	if err != nil {
		t.Fatal(err)
	}
	runtime := auth(token)
	read, err := api.GetDeploymentWithResponse(ctx, "example", "production", &controlv1.GetDeploymentParams{TeamId: team}, runtime)
	if err != nil || read.JSON200 == nil || len(read.JSON200.Services) != 1 || len(read.JSON200.Targets) != 1 || bytes.Contains(read.Body, []byte("web.internal")) {
		t.Fatal("runtime read exposed unrelated target", read, err)
	}
	production := read.JSON200
	for _, call := range []func() (int, error){
		func() (int, error) {
			r, e := api.RegisterDeploymentManagementWithResponse(ctx, "example", params, body, runtime)
			if e != nil {
				return 0, e
			}
			return r.StatusCode(), nil
		},
		func() (int, error) {
			r, e := api.GetProjectConfigurationWithResponse(ctx, "example", &controlv1.GetProjectConfigurationParams{TeamId: team}, runtime)
			if e != nil {
				return 0, e
			}
			return r.StatusCode(), nil
		},
		func() (int, error) {
			r, e := api.ListPublisherIdentitiesWithResponse(ctx, &controlv1.ListPublisherIdentitiesParams{TeamId: team}, runtime)
			if e != nil {
				return 0, e
			}
			return r.StatusCode(), nil
		},
		func() (int, error) {
			r, e := api.GetServiceWithResponse(ctx, production.Services["db"].Id, runtime)
			if e != nil {
				return 0, e
			}
			return r.StatusCode(), nil
		},
	} {
		if code, err := call(); err != nil || code != 401 {
			t.Fatal("management implied administration or visitor access", code, err)
		}
	}
	publication, err := api.GetPublisherServiceWithResponse(ctx, runtime)
	if err != nil || publication.StatusCode() != 404 {
		t.Fatal("management implied service publication", err)
	}
	createdDeployment, err := api.CreateDeploymentWithResponse(ctx, "example", &controlv1.CreateDeploymentParams{TeamId: team, IdempotencyKey: "customer"}, controlv1.CreateDeploymentRequest{Name: "customer", Targets: map[string]controlv1.DeploymentTarget{"db": {Address: "customer.internal:5432"}}}, runtime)
	if err != nil || createdDeployment.JSON201 == nil {
		t.Fatalf("runtime create: %+v %v", createdDeployment, err)
	}
	setup, err := api.CreateDeploymentPublisherEnrollmentWithResponse(ctx, "example", createdDeployment.JSON201.Id, &controlv1.CreateDeploymentPublisherEnrollmentParams{TeamId: team, IdempotencyKey: "setup"}, controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: []string{"db"}}, runtime)
	if err != nil || setup.JSON201 == nil || setup.JSON201.ExpiresAt.After(credential.ExpiresAt) {
		t.Fatalf("runtime setup: %+v %v", setup, err)
	}
	revoked, err := api.RevokePublisherGrantWithResponse(ctx, credential.ClientId, credential.GrantId, &controlv1.RevokePublisherGrantParams{TeamId: team}, manager)
	if err != nil || revoked.StatusCode() != 204 {
		t.Fatal("existing grant revocation failed", revoked, err)
	}
	read, err = api.GetDeploymentWithResponse(ctx, "example", "production", &controlv1.GetDeploymentParams{TeamId: team}, runtime)
	if err != nil || read.StatusCode() != 401 {
		t.Fatal("runtime use ignored current grant revocation", err)
	}
	recovered, err = api.RegisterDeploymentManagementWithResponse(ctx, "example", params, body, manager)
	if err != nil || recovered.StatusCode() != 409 {
		t.Fatal("registration replay revived revoked grant", err)
	}
}
