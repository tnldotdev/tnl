package public

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationDeploymentPublicationHTTPAndNativePreparation(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "deployment_publication_http")
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
	team, actor := session.Identity.Memberships[0].TeamID, session.Identity.Identity.ID
	applied, err := d.ApplyProjectConfiguration(ctx, controlstate.ApplyProjectConfigurationRequest{TeamID: team, ActorID: actor, ProjectKey: "shop", SourceFingerprint: strings.Repeat("a", 64), Deployment: "production", ServiceDeclarations: map[string]string{"web": "http", "other": "http"}, Configuration: controlstate.ProjectConfiguration{Settings: &controlstate.DeploymentSettings{}, Services: map[string]controlstate.ProjectServiceConfiguration{
		"web":   {Target: "app", PublicURL: &controlstate.ProjectServicePublicURL{Access: &controlstate.ProjectPublicAccess{Mode: "anonymous"}, Limits: &controlstate.ProjectPublicLimits{HTTP: &controlstate.ProjectHTTPApplicationLimits{Total: new(10)}}}},
		"other": {Target: "app", PublicURL: &controlstate.ProjectServicePublicURL{}},
	}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Config{ManagedURLMode: naming.ManagedURLModeSimple, DNSAutomation: true}, DatabaseStores(d), d, nil)
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
	manager := func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+session.AccessToken.String())
		return nil
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registration := controlv1.RegisterDeploymentCredentialRequest{Name: "app", PublicKey: base64.RawURLEncoding.EncodeToString(public), ExpiresIn: 600, DeploymentIds: new([]string{applied.Deployments[0].ID})}
	registration.Permissions.Publish = &controlv1.DeploymentPublishSelection{Services: new(controlv1.DeploymentCredentialServiceSelection{"web"}), Temporary: new(controlv1.TemporaryPublicationRestricted)}
	response, err := api.RegisterDeploymentCredentialWithResponse(ctx, "shop", &controlv1.RegisterDeploymentCredentialParams{TeamId: team, IdempotencyKey: "original"}, registration, manager)
	if err != nil || response.JSON201 == nil {
		t.Fatal("publish registration failed", response, err)
	}
	encoded, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	for _, permissions := range []string{
		`{"publish":{}}`, `{"publish":{"services":[]}}`, `{"publish":{"services":["web","web"]}}`,
		`{"publish":{"services":["unapproved"]}}`, `{"publish":{"temporary":"public"}}`,
		`{"publish":{"temporary":"restricted","anonymous":true}}`, `{"publish":["web"]}`,
	} {
		raw["permissions"] = json.RawMessage(permissions)
		body, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		denied, err := api.RegisterDeploymentCredentialWithBodyWithResponse(ctx, "shop", &controlv1.RegisterDeploymentCredentialParams{TeamId: team, IdempotencyKey: "invalid"}, "application/json", bytes.NewReader(body), manager)
		if err != nil || denied.StatusCode() != 400 || denied.ApplicationproblemJSONDefault == nil || denied.ApplicationproblemJSONDefault.Code != controlv1.InvalidRequest {
			t.Fatal("invalid publication approval escaped strict registration", denied, err)
		}
	}
	control, err := clientcontrol.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	native, saved, err := publisheridentity.PrepareDeployment(ctx, control, authority, *response.JSON201, private, "production", "web", nil)
	if err != nil || saved == nil || saved.PublicUrl.Ephemeral || saved.PublicUrl.AccessMode != controlv1.Anonymous || saved.Limits == nil || saved.Limits.Http == nil || saved.Limits.Http.Total == nil || *saved.Limits.Http.Total != 10 {
		t.Fatal("named preparation lost saved policy/limits", err)
	}
	if _, err = native.GetPublicURLByHostname(ctx, team, "other.invalid"); err == nil {
		t.Fatal("native escaped its one selected publication")
	}
	if _, _, err = publisheridentity.PrepareDeployment(ctx, control, authority, *response.JSON201, private, "production", "other", nil); err == nil {
		t.Fatal("HTTP preparation exposed unapproved service")
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	allocation := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: invocation, Target: "http://127.0.0.1:3000"}
	access, err := native.Access(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auth := func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+access)
		return nil
	}
	read, err := api.GetDeploymentPublicationWithResponse(ctx, "shop", "production", "web", &controlv1.GetDeploymentPublicationParams{TeamId: team}, auth)
	if err != nil || read.JSON200 == nil || read.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("publication response was missing or cacheable", err)
	}
	invalidAllocation, err := json.Marshal(map[string]any{"invocation_id": invocation, "target": allocation.Target, "hostname": "claimed.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	denied, err := api.AllocateDeploymentPublicationWithBodyWithResponse(ctx, "shop", "production", &controlv1.AllocateDeploymentPublicationParams{TeamId: team}, "application/json", bytes.NewReader(invalidAllocation), auth)
	if err != nil || denied.StatusCode() != 400 || denied.ApplicationproblemJSONDefault == nil || denied.ApplicationproblemJSONDefault.Code != controlv1.InvalidRequest {
		t.Fatal("allocation accepted a custom hostname claim", denied, err)
	}
	temporary, first, err := publisheridentity.PrepareDeployment(ctx, control, authority, *response.JSON201, private, "production", "", &allocation)
	if err != nil || first == nil || !first.PublicUrl.Ephemeral || first.PublicUrl.AccessMode != controlv1.Restricted {
		t.Fatal("temporary preparation borrowed anonymous saved policy", err)
	}
	_, retry, err := publisheridentity.PrepareDeployment(ctx, control, authority, *response.JSON201, private, "production", "", &allocation)
	if err != nil || retry.PublicUrl.Id != first.PublicUrl.Id || !retry.PublicUrl.ExpiresAt.Equal(*first.PublicUrl.ExpiresAt) {
		t.Fatal("native retry lost original allocation", err)
	}
	anonymous := allocation
	anonymous.AccessMode = new(controlv1.Anonymous)
	if _, _, err := publisheridentity.PrepareDeployment(ctx, control, authority, *response.JSON201, private, "production", "", &anonymous); err == nil {
		t.Fatal("HTTP allocation exceeded visitor approval")
	}
	if err := temporary.DeletePublicURL(ctx, first.PublicUrl.Id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := publisheridentity.PrepareDeployment(ctx, control, authority, *response.JSON201, private, "production", "", &allocation); err == nil {
		t.Fatal("deleted allocation resurrected through native retry")
	}
	if err := native.DeletePublicURL(ctx, saved.PublicUrl.Id); err == nil {
		t.Fatal("native named publication deleted saved URL")
	}
}
