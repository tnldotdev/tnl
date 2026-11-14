package public

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

func TestIntegrationDeploymentPublisherHTTPContracts(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "deployment_publishers_http")
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
	project, err := d.ApplyProjectConfiguration(ctx, controlstate.ApplyProjectConfigurationRequest{
		Deployment: "production", ServiceDeclarations: map[string]string{"db": "postgres", "web": "http", "stage": "postgres"},
		TeamID: team, ActorID: session.Identity.Identity.ID, ProjectKey: "example", SourceFingerprint: strings.Repeat("a", 64), Now: now,
		Configuration: controlstate.ProjectConfiguration{Settings: &controlstate.DeploymentSettings{}, Services: map[string]controlstate.ProjectServiceConfiguration{
			"db":  {Protocol: "postgres", Target: "db.internal:5432"},
			"web": {Target: "web.internal:3000"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.ApplyProjectConfiguration(ctx, controlstate.ApplyProjectConfigurationRequest{
		Deployment: "staging", ServiceDeclarations: project.ServiceDeclarations, ExpectedRevision: project.Revision,
		TeamID: team, ActorID: session.Identity.Identity.ID, ProjectKey: "example", SourceFingerprint: strings.Repeat("a", 64), Now: now,
		Configuration: controlstate.ProjectConfiguration{Settings: &controlstate.DeploymentSettings{}, Services: map[string]controlstate.ProjectServiceConfiguration{"stage": {Protocol: "postgres", Target: "stage.internal:5432"}}},
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
	params := &controlv1.CreateDeploymentPublisherEnrollmentParams{TeamId: team, IdempotencyKey: "setup-db"}
	body := controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: []string{"db"}}
	anonymous, err := api.CreateDeploymentPublisherEnrollmentWithResponse(ctx, "example", "production", params, body)
	if err != nil || anonymous.StatusCode() != 401 {
		t.Fatal("anonymous publisher setup admitted", err)
	}
	created, err := api.CreateDeploymentPublisherEnrollmentWithResponse(ctx, "example", "production", params, body, auth)
	if err != nil || created.JSON201 == nil || created.StatusCode() != 201 || created.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("publisher enrollment response: %+v %v", created, err)
	}
	enrollment := created.JSON201
	if enrollment.MaxMembers != 1 || len(enrollment.Services) != 1 || enrollment.Services["db"] != controlv1.Postgres || enrollment.ExpiresAt.Before(now.Add(9*time.Minute)) || enrollment.ExpiresAt.After(time.Now().Add(10*time.Minute)) {
		t.Fatal("publisher setup lost defaults, captured scope, or bounded deadline")
	}
	recovered, err := api.CreateDeploymentPublisherEnrollmentWithResponse(ctx, "example", enrollment.GroupId, params, body, auth)
	if err != nil || recovered.JSON201 == nil || !bytes.Equal(created.Body, recovered.Body) {
		t.Fatal("setup lost-response retry changed its secret or expiration", err)
	}
	changed, err := api.CreateDeploymentPublisherEnrollmentWithResponse(ctx, "example", "production", params, controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: []string{"web"}}, auth)
	if err != nil || changed.StatusCode() != 409 {
		t.Fatal("request key accepted a different service approval", err)
	}
	for _, invalid := range []string{
		`{}`, `{"services":[]}`, `{"services":["db","db"]}`, `{"services":["stage"]}`,
		`{"services":["db"],"max_members":0}`, `{"services":["db"],"max_members":257}`,
		`{"services":["db"],"expires_in":59}`, `{"services":["db"],"expires_in":9223372036854775807}`,
		`{"services":["db"],"targets":{"db":"private.invalid:5432"}}`,
		`{"services":["db"],"capabilities":["manage","connect"]}`,
		`{"services":["db"],"namespace":"owned.example.test"}`,
	} {
		response, err := api.CreateDeploymentPublisherEnrollmentWithBodyWithResponse(ctx, "example", "production", &controlv1.CreateDeploymentPublisherEnrollmentParams{TeamId: team, IdempotencyKey: "invalid"}, "application/json", strings.NewReader(invalid), auth)
		if err != nil || response.StatusCode() != 400 || bytes.Contains(response.Body, []byte("private.invalid")) {
			t.Fatal("invalid setup expanded authority or leaked input", invalid, err)
		}
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	redeemed, err := api.RedeemPublisherGroupEnrollmentWithResponse(ctx, controlv1.RedeemPublisherGroupEnrollmentRequest{EnrollmentKey: enrollment.EnrollmentKey, PublicKey: base64.RawURLEncoding.EncodeToString(public)})
	if err != nil || redeemed.JSON200 == nil {
		t.Fatal("scoped setup did not use the existing redemption exchange", err)
	}
	publisher := redeemed.JSON200.PublisherIdentityId
	read, err := api.GetDeploymentPublisherWithResponse(ctx, "example", "production", publisher, &controlv1.GetDeploymentPublisherParams{TeamId: team}, auth)
	if err != nil || read.JSON200 == nil || read.JSON200.PublisherIdentityId != publisher || read.JSON200.Services["db"] != controlv1.Postgres || read.JSON200.Runtime != nil || read.JSON200.Healthy || read.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("publisher observation confused enrollment with serving readiness", err)
	}
	for _, forbidden := range []string{enrollment.EnrollmentKey, "enrollment_key", "public_key", "access_token", "db.internal", "web.internal", "configuration"} {
		if bytes.Contains(read.Body, []byte(forbidden)) {
			t.Fatal("publisher read exposed credentials or private targets")
		}
	}
	listed, err := api.ListDeploymentPublishersWithResponse(ctx, "example", enrollment.GroupId, &controlv1.ListDeploymentPublishersParams{TeamId: team}, auth)
	if err != nil || listed.JSON200 == nil || len(listed.JSON200.Publishers) != 1 || listed.JSON200.Publishers[0].PublisherIdentityId != publisher {
		t.Fatal("generated publisher list contract lost the selected identity", err)
	}
	foreign, err := api.GetDeploymentPublisherWithResponse(ctx, "example", "staging", publisher, &controlv1.GetDeploymentPublisherParams{TeamId: team}, auth)
	if err != nil || foreign.StatusCode() != 404 {
		t.Fatal("publisher read crossed deployments", err)
	}
	wrongProject, err := api.GetDeploymentPublisherWithResponse(ctx, "another", "production", publisher, &controlv1.GetDeploymentPublisherParams{TeamId: team}, auth)
	if err != nil || wrongProject.StatusCode() != 404 {
		t.Fatal("publisher read crossed projects", err)
	}
	wrongRevoke, err := api.RevokeDeploymentPublisherWithResponse(ctx, "example", "staging", publisher, &controlv1.RevokeDeploymentPublisherParams{TeamId: team}, auth)
	if err != nil || wrongRevoke.StatusCode() != 404 {
		t.Fatal("publisher revocation crossed deployments", err)
	}
	for range 2 {
		revoked, err := api.RevokeDeploymentPublisherWithResponse(ctx, "example", "production", publisher, &controlv1.RevokeDeploymentPublisherParams{TeamId: team}, auth)
		if err != nil || revoked.StatusCode() != 204 || len(revoked.Body) != 0 {
			t.Fatal("publisher revocation is not repeatable", err)
		}
	}
	read, err = api.GetDeploymentPublisherWithResponse(ctx, "example", "production", publisher, &controlv1.GetDeploymentPublisherParams{TeamId: team}, auth)
	if err != nil || read.JSON200 == nil || read.JSON200.RevokedAt == nil || read.JSON200.Healthy {
		t.Fatal("revoked publisher observation was lost or reported healthy", err)
	}
	replay, err := api.CreateDeploymentPublisherEnrollmentWithResponse(ctx, "example", "production", params, body, auth)
	if err != nil || replay.StatusCode() != 409 || bytes.Contains(replay.Body, []byte(enrollment.EnrollmentKey)) {
		t.Fatal("replay restored consumed setup authority or returned its secret", err)
	}
}
