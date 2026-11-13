package public

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationDeploymentHTTPContracts(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "deployment_http")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
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
	_, err = d.ApplyProjectConfiguration(ctx, controlstate.ApplyProjectConfigurationRequest{
		TeamID: team, ActorID: session.Identity.Identity.ID, ProjectKey: "example", SourceFingerprint: strings.Repeat("a", 64), Now: now,
		Configuration: controlstate.ProjectConfiguration{Services: map[string]controlstate.ProjectServiceConfiguration{"db": {Protocol: "postgres", Target: "localhost:5432"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	h, err := NewHandler(Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", h)
	api, err := controlv1.NewClientWithResponses(server.URL, controlv1.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	auth := func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+session.AccessToken.String())
		return nil
	}
	ca := "aws-rds"
	body := controlv1.CreateDeploymentRequest{Name: "customer", Targets: controlv1.DeploymentTargets{
		"db": {Address: "orders.abc.us-east-1.rds.amazonaws.com:5432", Tls: &controlv1.DeploymentTargetTLS{Ca: &ca}},
	}}
	params := &controlv1.CreateDeploymentParams{TeamId: team, IdempotencyKey: "setup-customer"}
	unauthenticated, err := api.CreateDeploymentWithResponse(ctx, "example", params, body)
	if err != nil || unauthenticated.StatusCode() != 401 {
		t.Fatal("anonymous deployment mutation accepted", err)
	}
	created, err := api.CreateDeploymentWithResponse(ctx, "example", params, body, auth)
	if err != nil || created.StatusCode() != 201 || created.JSON201 == nil || created.HTTPResponse.Header.Get("ETag") != `"1"` || created.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("deployment create contract: %+v %v", created, err)
	}
	id := created.JSON201.Id
	if created.JSON201.Services["db"].Protocol != controlv1.Postgres || created.JSON201.Targets["db"].Tls == nil {
		t.Fatal("generated contract lost protocol or captured TLS")
	}
	recovered, err := api.CreateDeploymentWithResponse(ctx, "example", params, body, auth)
	if err != nil || recovered.JSON201 == nil || recovered.JSON201.Id != id || !bytes.Equal(created.Body, recovered.Body) {
		t.Fatal("original creation key did not recover its reply", err)
	}
	for _, invalid := range []string{
		`{"name":"bad","targets":{"unknown":{"address":"localhost:5432"}}}`,
		`{"name":"bad","targets":{"db":{"address":"localhost:5432","tls":{"ca":"https://private.invalid/ca"}}}}`,
	} {
		response, err := api.CreateDeploymentWithBodyWithResponse(ctx, "example", &controlv1.CreateDeploymentParams{TeamId: team, IdempotencyKey: "invalid"}, "application/json", strings.NewReader(invalid), auth)
		if err != nil || response.StatusCode() != 400 || bytes.Contains(response.Body, []byte("private.invalid")) {
			t.Fatal("invalid declaration/trust was accepted or leaked", err)
		}
	}
	for _, forbidden := range []string{
		`{"targets":{"db":{"address":"localhost:5432","protocol":"mysql"}}}`,
		`{"targets":{"db":{"address":"localhost:5432","access":{"team":true}}}}`,
		`{"targets":{"db":{"address":"localhost:5432","tls":{"insecure":true}}}}`,
		`{"configuration":{"services":{}},"targets":{"db":{"address":"localhost:5432"}}}`,
		`{"targets":{"db":{"address":"localhost:5432","hostname":"owned.example.test"}}}`,
	} {
		etag := `"1"`
		response, err := api.UpdateDeploymentWithBodyWithResponse(ctx, "example", id, &controlv1.UpdateDeploymentParams{TeamId: team, IfMatch: &etag}, "application/json", strings.NewReader(forbidden), auth)
		if err != nil || response.StatusCode() != 400 {
			t.Fatal("narrow target update accepted unrelated authority", forbidden, err)
		}
	}
	update := controlv1.UpdateDeploymentRequest{Targets: controlv1.DeploymentTargets{"db": {Address: "replacement.internal:5432"}}}
	for _, value := range []struct {
		condition string
		want      int
	}{
		{"", 428}, {`W/"1"`, 400}, {"*", 400}, {`"01"`, 400}, {`"1", "2"`, 400}, {`"9"`, 412},
	} {
		condition := value.condition
		response, err := api.UpdateDeploymentWithResponse(ctx, "example", id, &controlv1.UpdateDeploymentParams{TeamId: team, IfMatch: &condition}, update, auth)
		if err != nil || response.StatusCode() != value.want {
			t.Fatal("conditional request contract", condition, response.StatusCode(), err)
		}
	}
	etag := `"1"`
	updated, err := api.UpdateDeploymentWithResponse(ctx, "example", id, &controlv1.UpdateDeploymentParams{TeamId: team, IfMatch: &etag}, update, auth)
	if err != nil || updated.JSON200 == nil || updated.HTTPResponse.Header.Get("ETag") != `"2"` || updated.JSON200.Services["db"].Id != created.JSON201.Services["db"].Id {
		t.Fatal("wire update changed the saved service identity", err)
	}
	current, err := api.GetDeploymentWithResponse(ctx, "example", "customer", &controlv1.GetDeploymentParams{TeamId: team}, auth)
	if err != nil || current.JSON200 == nil || current.JSON200.Targets["db"].Address == nil || *current.JSON200.Targets["db"].Address != update.Targets["db"].Address {
		t.Fatal("name and ID did not read the same updated deployment", err)
	}
	listing, err := api.ListDeploymentsWithResponse(ctx, "example", &controlv1.ListDeploymentsParams{TeamId: team}, auth)
	if err != nil || listing.JSON200 == nil || len(listing.JSON200.Deployments) != 1 || listing.JSON200.Deployments[0].Id != id {
		t.Fatal("generated deployment list contract", err)
	}
	missing, err := api.GetDeploymentWithResponse(ctx, "another", id, &controlv1.GetDeploymentParams{TeamId: team}, auth)
	if err != nil || missing.StatusCode() != 404 {
		t.Fatal("project selector crossed deployment ownership", err)
	}
	etag = `"2"`
	deleted, err := api.DeleteDeploymentWithResponse(ctx, "example", id, &controlv1.DeleteDeploymentParams{TeamId: team, IfMatch: &etag}, auth)
	if err != nil || deleted.StatusCode() != 204 || len(deleted.Body) != 0 {
		t.Fatal("deployment deletion contract", err)
	}
	replay, err := api.CreateDeploymentWithResponse(ctx, "example", params, body, auth)
	if err != nil || replay.StatusCode() != 409 {
		t.Fatal("wire retry recreated a deleted deployment", err)
	}
}
