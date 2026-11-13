package http_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationGeneratedManagementHTTP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "management_sdk")
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
		Deployment: "production", ServiceDeclarations: map[string]string{"db": "postgres", "web": "http"},
		TeamID: team, ActorID: session.Identity.Identity.ID, ProjectKey: "example", SourceFingerprint: strings.Repeat("a", 64), Now: now,
		Configuration: controlstate.ProjectConfiguration{PublisherGroups: map[string]controlstate.ProjectPublisherGroup{"production": {}}, Services: map[string]controlstate.ProjectServiceConfiguration{
			"db":  {PublisherGroup: "production", Protocol: "postgres", Target: "db.internal:5432"},
			"web": {PublisherGroup: "production", Target: "web.internal:3000"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	authorityHandler, err := controlauthority.NewHandler(controlauthority.Config{ControlURL: server.URL}, d)
	if err != nil {
		t.Fatal(err)
	}
	h, err := controlpublic.NewHandler(controlpublic.Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, controlpublic.DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/v1/publisher-token", authorityHandler)
	mux.Handle("/", h)
	api, err := controlv1.NewClientWithResponses(server.URL, controlv1.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	manager := func(_ context.Context, request *http.Request) error {
		request.Header.Set("Authorization", "Bearer "+session.AccessToken.String())
		return nil
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registration := controlv1.RegisterDeploymentCredentialRequest{PublicKey: base64.RawURLEncoding.EncodeToString(public), Name: "sdk-backend", ExpiresIn: 1800}
	registration.AllDeployments = new(controlv1.RegisterDeploymentCredentialRequestAllDeployments(true))
	registration.Permissions.Manage = new(controlv1.DeploymentCredentialServiceSelection{"db"})
	registered, err := api.RegisterDeploymentCredentialWithResponse(ctx, "example", &controlv1.RegisterDeploymentCredentialParams{TeamId: team, IdempotencyKey: "sdk-registration"}, registration, manager)
	if err != nil {
		t.Fatal("register SDK fixture credential", err)
	}
	if registered.JSON201 == nil {
		t.Fatalf("register SDK fixture credential: HTTP %d, %v", registered.StatusCode(), err)
	}
	credential := registered.JSON201
	authority, err := clientauthority.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	access, err := authority.ExchangePublisherAssertion(ctx, credential.ClientId, credential.GrantId, credential.KeyId, private)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "control.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	input := map[string]string{"server": server.URL, "team_id": team, "project_key": "example", "token": access}
	run := func(phase string) map[string]string {
		t.Helper()
		input["phase"] = phase
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, "node", "../fixtures/management-http.ts")
		command.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+ca)
		command.Stdin = bytes.NewReader(encoded)
		var diagnostics bytes.Buffer
		command.Stderr = &diagnostics
		output, err := command.Output()
		if err != nil {
			t.Fatalf("generated SDK %s phase failed: %v\n%s", phase, err, &diagnostics)
		}
		var result map[string]string
		if err := json.Unmarshal(output, &result); err != nil {
			t.Fatal("invalid SDK fixture result")
		}
		return result
	}
	created := run("create")
	publisherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := api.RedeemPublisherGroupEnrollmentWithResponse(ctx, controlv1.RedeemPublisherGroupEnrollmentRequest{EnrollmentKey: created["enrollment_key"], PublicKey: base64.RawURLEncoding.EncodeToString(publisherKey)})
	if err != nil || enrolled.JSON200 == nil {
		t.Fatal("redeem scoped SDK setup", err)
	}
	input["deployment_id"], input["publisher_id"] = created["deployment_id"], enrolled.JSON200.PublisherIdentityId
	run("publishers")
	if err := d.RevokePublisherGrant(ctx, team, credential.ClientId, credential.GrantId, session.Identity.Identity.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	run("revoked")
}
