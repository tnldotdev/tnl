package deployment_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublicURLAssignmentUsesExistingSignedRunAndRetainsSavedURL(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	f := publishingtest.New(t, testutil.PublishingHooks{})
	control, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("deployment application")) }))
	defer local.Close()
	u, err := f.SavedPublicURL(t.Context(), controlv1.App, local.URL)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := control.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: u.TeamId, PublicUrlId: &u.Id, Name: "deployment", Kind: "installed"})
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authority.RedeemPublisherEnrollment(t.Context(), enrollment.EnrollmentKey, public)
	if err != nil {
		t.Fatal(err)
	}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profile, err := database.Server(t.Context(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	publication := publisherdeployment.AssignmentPublisher{Member: controlv1.DeploymentPublisherIdentity{TeamId: u.TeamId, DeploymentId: "dpl_test", DeploymentName: "production", PublisherIdentityId: identity.ClientId, KeyId: identity.KeyId}, Private: key, State: profile, Control: publisheridentity.NativeControl{PublicURLControl: control}, Authority: authority}
	assignment := controlv1.DeploymentPublisherServiceAssignment{Service: "web", ServiceId: u.Id, ServiceKind: "public_url", GrantId: identity.GrantId, Hostname: &u.CanonicalHostname, Configuration: controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.ServiceProtocol("http")), Target: local.URL, PublicUrl: &controlv1.ProjectServicePublicURL{}}}
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}, 1), make(chan error, 1)
	go func() {
		done <- publication.Publish(ctx, assignment, func(healthy bool) {
			if healthy {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		})
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("public assignment did not join cleanup")
		}
	}()
	select {
	case <-ready:
		status, body, err := f.Visit(t.Context(), "https://"+u.CanonicalHostname)
		if err != nil || status != 200 || string(body) != "deployment application" {
			t.Fatal("signed public assignment did not carry visitor traffic", status, err)
		}
	case err := <-done:
		done <- err
		t.Fatal("public assignment stopped before readiness", err)
	case <-time.After(10 * time.Second):
		t.Fatal("public assignment did not become traffic-ready")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
		done <- nil
	case <-time.After(10 * time.Second):
		t.Fatal("public assignment did not stop")
	}
	if f.Runs.Load() != 1 || f.Allocations.Load() != 0 || f.Deletions.Load() != 0 {
		t.Fatal("saved deployment assignment allocated or deleted a URL")
	}
}
