package deployment_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
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
	f := startPublicURLAssignment(t, controlv1.Anonymous, nil)
	defer f.stop()
	status, body, err := f.Visit(t.Context(), "https://"+f.publicURL.CanonicalHostname)
	if err != nil || status != http.StatusOK || string(body) != "deployment application" {
		t.Fatal("signed public assignment did not carry visitor traffic", status, err)
	}
	f.stop()
	if f.Runs.Load() != 1 || f.Allocations.Load() != 0 || f.Deletions.Load() != 0 {
		t.Fatal("saved deployment assignment allocated or deleted a URL")
	}
}

func TestPublicURLAssignmentBrowserSignInFollowsDiscovery(t *testing.T) {
	for _, test := range []struct {
		name      string
		available *bool
		status    int
	}{
		{"available", new(true), http.StatusSeeOther},
		{"disabled", new(false), http.StatusForbidden},
		{"omitted", nil, http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !testutil.IsolatedPublishingTest(t) {
				return
			}
			f := startPublicURLAssignment(t, controlv1.Restricted, test.available)
			defer f.stop()
			address := "https://" + f.publicURL.CanonicalHostname + "/settings?tab=profile"
			response, _, err := f.VisitHTTP(t.Context(), address, nil)
			if err != nil || response.StatusCode != http.StatusForbidden || response.Header.Get("Location") != "" {
				t.Fatal("restricted API request started browser sign-in", response, err)
			}
			response, _, err = f.VisitHTTP(t.Context(), address, http.Header{
				"Sec-Fetch-Mode": {"navigate"},
				"Sec-Fetch-Dest": {"document"},
				"Accept":         {"text/html"},
			})
			if err != nil || response.StatusCode != test.status {
				t.Fatal("browser navigation ignored the advertised sign-in capability", response, err)
			}
			if test.status == http.StatusSeeOther {
				if response.Header.Get("Location") != "/__tnl/team/login?return=%2Fsettings%3Ftab%3Dprofile" {
					t.Fatal("browser sign-in lost the return path", response.Header)
				}
				cookies := response.Cookies()
				if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
					t.Fatal("browser sign-in did not set its secure attempt cookie", cookies)
				}
			} else if response.Header.Get("Location") != "" {
				t.Fatal("unavailable browser sign-in sent a redirect", response.Header)
			}
			if f.targetRequests.Load() != 0 {
				t.Fatal("restricted visitor reached the application")
			}
		})
	}
}

type publicURLAssignmentFixture struct {
	*publishingtest.Fixture
	publicURL      controlv1.PublicURL
	targetRequests *atomic.Int32
	stop           func()
}

func startPublicURLAssignment(t *testing.T, access controlv1.VisitorAccessMode, browserLogin *bool) publicURLAssignmentFixture {
	t.Helper()
	f := publishingtest.New(t, testutil.PublishingHooks{})
	f.SetBrowserLoginAvailable(browserLogin)
	control, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	targetRequests := new(atomic.Int32)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		_, _ = w.Write([]byte("deployment application"))
	}))
	t.Cleanup(local.Close)
	u, err := f.SavedPublicURL(t.Context(), controlv1.App, local.URL, access)
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
	t.Cleanup(func() { _ = database.Close() })
	profile, err := database.Server(t.Context(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	publication := publisherdeployment.AssignmentPublisher{Member: controlv1.DeploymentPublisherIdentity{TeamId: u.TeamId, DeploymentId: "dpl_test", DeploymentName: "production", PublisherIdentityId: identity.ClientId, KeyId: identity.KeyId}, Private: key, State: profile, Control: publisheridentity.NativeControl{PublicURLControl: control}, Authority: authority, ServerDiscovery: control}
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
	var stopped sync.Once
	stop := func() {
		stopped.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(10 * time.Second):
				t.Error("public assignment did not join cleanup")
			}
		})
	}
	t.Cleanup(stop)
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal("public assignment stopped before readiness", err)
	case <-time.After(10 * time.Second):
		t.Fatal("public assignment did not become traffic-ready")
	}
	return publicURLAssignmentFixture{Fixture: f, publicURL: u, targetRequests: targetRequests, stop: stop}
}
