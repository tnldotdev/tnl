package tnl

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestOpenRealPublicationReusesIdentityAndCleansCanceledContext(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	atReady := make(chan testutil.PublishingRun, 2)
	f := publishingtest.New(t, testutil.PublishingHooks{Ready: func(_ context.Context, setup testutil.PublishingRun) error {
		atReady <- setup
		return nil
	}})
	secret, err := f.NamespaceEnrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "state")
	prepared, err := PreparePublisherIdentity(t.Context(), Options{EnrollmentKey: secret, ServerURL: f.URL, StateDir: root, StateProtection: ProtectionFile, HTTPClient: f.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		options := Options{RequirePostQuantum: attempt == 1, PublisherIdentity: prepared, StateDir: root, StateProtection: ProtectionFile, HTTPClient: f.HTTP}
		if attempt == 1 {
			options.PublisherIdentity, options.PublisherIdentityID, options.ServerURL = nil, prepared.value.PublisherIdentityID(), f.URL
			options.AccessMode = controlv1.Anonymous
		}
		var requests atomic.Int32
		tunnel, err := Open(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(http.StatusNoContent) }), options)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if tunnel.URL() == "" {
			cancel()
			t.Fatal("Open returned before its exact run was ready")
		}
		service := tunnel.Service()
		if service.Protocol != controlv1.ServiceProtocolHTTP || !service.Ephemeral || service.Endpoint == nil ||
			service.Endpoint.Port != 443 || !service.Endpoint.Public || tunnel.Endpoint() != *service.Endpoint {
			cancel()
			t.Fatal("SDK did not return an ordinary public HTTP service snapshot")
		}
		if setup := <-atReady; setup.Service.RequirePostQuantum != options.RequirePostQuantum || setup.Service.Id != service.Id ||
			setup.Setup.ServiceRunId != setup.Preparation.ServiceRunId || setup.Setup.RunNumber < 1 {
			cancel()
			t.Fatal("Go SDK lost the exact service run or public HTTPS requirement")
		}
		status, _, err := f.Visit(t.Context(), tunnel.URL())
		if attempt == 0 {
			if err != nil || status >= 200 && status < 300 || requests.Load() != 0 {
				cancel()
				t.Fatal("default restricted policy admitted an anonymous handler request", status, err)
			}
			permission, tokenErr := f.OwnerVisitorToken(t.Context(), service.Id)
			if tokenErr != nil {
				cancel()
				t.Fatal(tokenErr)
			}
			status, _, _, err = f.VisitWithHeaders(t.Context(), tunnel.URL(), http.Header{httpaccess.VisitorTokenHeader: {permission.VisitorToken}})
		}
		if err != nil || status != 204 || requests.Load() != 1 {
			cancel()
			t.Fatalf("Go handler was not reachable through its allocated publisher: status=%d err=%v", status, err)
		}
		cancel()
		done := make(chan error, 1)
		go func() { done <- tunnel.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("context cancellation did not join publication cleanup")
		}
		if err := tunnel.Close(); err != nil {
			t.Fatal(err)
		}
	}
	deleted := f.DeletedIDs()
	if f.Enrollments.Load() != 1 || f.Allocations.Load() != 2 || f.Runs.Load() != 2 || len(deleted) != 2 || deleted[0] == deleted[1] {
		t.Fatalf("publisher reuse or invocation cleanup changed: enrollments=%d allocations=%d runs=%d visitor decisions=%d deleted=%v", f.Enrollments.Load(), f.Allocations.Load(), f.Runs.Load(), f.VisitorDecisions.Load(), deleted)
	}
}

func TestOpenCancellationBeforeReadyStillCleansExactAllocation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	atReady := make(chan testutil.PublishingRun, 1)
	f := publishingtest.New(t, testutil.PublishingHooks{Ready: func(ctx context.Context, setup testutil.PublishingRun) error {
		atReady <- setup
		<-ctx.Done()
		return ctx.Err()
	}})
	secret, err := f.NamespaceEnrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		tunnel, err := Open(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), Options{EnrollmentKey: secret, ServerURL: f.URL, StateDir: filepath.Join(t.TempDir(), "state"), StateProtection: ProtectionFile, HTTPClient: f.HTTP})
		if tunnel != nil {
			_ = tunnel.Close()
			result <- errors.New("Open returned an unready run")
			return
		}
		result <- err
	}()
	var setup testutil.PublishingRun
	select {
	case setup = <-atReady:
	case err := <-result:
		t.Fatalf("publication stopped before readiness: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("real publisher did not reach readiness")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("canceled Open returned before cleanup completed")
	}
	deleted := f.DeletedIDs()
	if f.Allocations.Load() != 1 || f.Runs.Load() != 1 || len(deleted) != 1 || deleted[0] != setup.Service.Id {
		t.Fatalf("canceled invocation cleaned a different service: deleted=%v run service=%s", deleted, setup.Service.Id)
	}
}

func TestOpenRequiresExplicitPublisherSetup(t *testing.T) {
	t.Setenv("TNL_PUBLISHER_CREDENTIAL_FILE", "")
	if err := os.Unsetenv("TNL_PUBLISHER_CREDENTIAL_FILE"); err != nil {
		t.Fatal(err)
	}
	_, err := Open(t.Context(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Options{ServerURL: "https://control.example", StateDir: filepath.Join(t.TempDir(), "state"), StateProtection: ProtectionFile})
	if !errors.Is(err, publisheridentity.ErrSetupRequired) {
		t.Fatalf("missing setup did not identify the explicit setup step: %v", err)
	}
}
