package local

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationDeploymentApplicationUsesSharedRegistrationAndCleanup(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "deployment_app")
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
	team, actor := session.Identity.Memberships[0].TeamID, session.Identity.Identity.ID
	applied, err := d.ApplyProjectConfiguration(ctx, controlstate.ApplyProjectConfigurationRequest{
		TeamID: team, ActorID: actor, ProjectKey: "shop", SourceFingerprint: strings.Repeat("a", 64),
		Deployment: "production", ServiceDeclarations: map[string]string{"web": "http"},
		Configuration: controlstate.ProjectConfiguration{Settings: &controlstate.DeploymentSettings{}, Services: map[string]controlstate.ProjectServiceConfiguration{
			"web": {Target: "app", PublicURL: &controlstate.ProjectServicePublicURL{
				Access: &controlstate.ProjectPublicAccess{Mode: "anonymous"},
				Limits: &controlstate.ProjectPublicLimits{HTTP: &controlstate.ProjectHTTPApplicationLimits{Total: new(10)}},
			}},
		}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := controlpublic.NewHandler(controlpublic.Config{ManagedURLMode: naming.ManagedURLModeSimple, DNSAutomation: true}, controlpublic.DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewTLSServer(h)
	t.Cleanup(remote.Close)
	if _, err = controlauthority.Register(h, controlauthority.Config{ControlURL: remote.URL}, d); err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	http.DefaultTransport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host == remote.URL {
			return remote.Client().Transport.RoundTrip(r)
		}
		return original.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	api, err := controlv1.NewClientWithResponses(remote.URL, controlv1.WithHTTPClient(remote.Client()))
	if err != nil {
		t.Fatal(err)
	}
	registration := controlv1.RegisterDeploymentCredentialRequest{
		Name: "application", PublicKey: base64.RawURLEncoding.EncodeToString(public),
		DeploymentIds: new([]string{applied.Deployments[0].ID}), ExpiresIn: 600,
	}
	registration.Permissions.Publish = &controlv1.DeploymentPublishSelection{
		Services: new(controlv1.DeploymentCredentialServiceSelection{"web"}), Temporary: new(controlv1.TemporaryPublicationRestricted),
	}
	response, err := api.RegisterDeploymentCredentialWithResponse(ctx, "shop", &controlv1.RegisterDeploymentCredentialParams{TeamId: team, IdempotencyKey: "registration"}, registration, func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+session.AccessToken.String())
		return nil
	})
	if err != nil || response.JSON201 == nil {
		t.Fatal("register app publication", response, err)
	}
	credential := auth.DeploymentCredential{Version: 1, ControlURL: remote.URL, Team: "acme", Approval: *response.JSON201, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}
	token, err := credential.Encode()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := testAppRuntimeWorkers(t, true)
	ready := make(chan publisher.Config, 2)
	a.workers.RunPublisher = func(ctx context.Context, cfg publisher.Config) error {
		observe := cfg.Observe
		cfg.Observe = func(event publisher.Event) error {
			if err := observe(event); err != nil {
				return err
			}
			if event.Type == publisher.EventReady {
				ready <- cfg
			}
			return nil
		}
		return readyInvocation(ctx, cfg)
	}
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "app still running") }))
	t.Cleanup(listener.Close)
	for _, named := range []bool{true, false} {
		invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			t.Fatal(err)
		}
		endpoint, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
		if err != nil {
			t.Fatal(err)
		}
		selection := map[string]any{"project": "acme/shop", "name": "production", "credential": token}
		if named {
			selection["service"] = "web"
		}
		body := map[string]any{"version": 1, "invocation_id": invocation, "owner": "0123456789abcdef0123456789abcdef", "pid": os.Getpid(), "target": listener.URL, "deployment": selection}
		var registered publisherprotocol.Registration
		if err = publisherprotocol.Call(ctx, endpoint, "POST", "/v1/publications/register", body, &registered); err != nil {
			t.Fatal(err)
		}
		var cfg publisher.Config
		select {
		case cfg = <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("worker did not become routable")
		}
		if cfg.Ephemeral == named || cfg.Target != listener.URL || cfg.AssignedPublicURL == nil ||
			named && (cfg.AccessMode != controlv1.Anonymous || cfg.Limits.Requests != 10) || !named && cfg.AccessMode != controlv1.Restricted {
			t.Fatal("publication changed saved policy or invented a target")
		}
		encoded, err := json.Marshal(a.manager.Snapshot())
		if err != nil || strings.Contains(string(encoded), token) || strings.Contains(string(encoded), credential.PrivateKey) {
			t.Fatal("credential entered snapshot", err)
		}
		if err = publisherprotocol.Call(ctx, endpoint, "POST", "/v1/unregister", registered, nil); err != nil {
			t.Fatal(err)
		}
		u, err := d.GetPublicURLForAuthorization(ctx, cfg.AssignedPublicURL.Id)
		if named && (err != nil || u.LifecycleState != controlstate.PublicURLLifecycleEnabled) ||
			!named && !errors.Is(err, controlstate.ErrPublicURLNotFound) {
			t.Fatal("cleanup changed wrong URL lifetime", err)
		}
		stillRunning, err := http.Get(listener.URL)
		if err != nil {
			t.Fatal("cleanup stopped app listener", err)
		}
		_ = stillRunning.Body.Close()
		if stillRunning.StatusCode != 200 {
			t.Fatal("app stopped serving")
		}
	}
}
