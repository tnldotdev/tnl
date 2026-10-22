package tnl

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestOpenRealPublicationReusesIdentityAndCleansCanceledContext(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	f := publishingtest.New(t, testutil.PublishingHooks{})
	secret, err := f.NamespaceEnrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "state")
	prepared, err := PreparePublisher(t.Context(), Options{EnrollmentKey: secret, ServerURL: f.URL, StateDir: root, StateProtection: ProtectionFile, HTTPClient: f.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		options := Options{Publisher: prepared, StateDir: root, StateProtection: ProtectionFile, HTTPClient: f.HTTP}
		if attempt == 1 {
			options.Publisher, options.PublisherID, options.ServerURL = nil, prepared.PublisherID(), f.URL
		}
		tunnel, err := Open(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), options)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if tunnel.URL() == "" {
			cancel()
			t.Fatal("Open returned before its exact run was ready")
		}
		if status, _, err := f.Visit(t.Context(), tunnel.URL()); err != nil || status != 204 {
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
	atReady := make(chan controlv1.PublishRunSetup, 1)
	f := publishingtest.New(t, testutil.PublishingHooks{Ready: func(ctx context.Context, setup controlv1.PublishRunSetup) error {
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
	var setup controlv1.PublishRunSetup
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
	if f.Allocations.Load() != 1 || f.Runs.Load() != 1 || len(deleted) != 1 || deleted[0] != setup.PublicUrl.Id {
		t.Fatalf("canceled invocation cleaned a different URL: deleted=%v run URL=%s", deleted, setup.PublicUrl.Id)
	}
}

func TestOpenRequiresExplicitPublisherSetup(t *testing.T) {
	t.Setenv("TNL_PUBLISHER_FILE", "")
	if err := os.Unsetenv("TNL_PUBLISHER_FILE"); err != nil {
		t.Fatal(err)
	}
	_, err := Open(t.Context(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), Options{ServerURL: "https://control.example", StateDir: filepath.Join(t.TempDir(), "state"), StateProtection: ProtectionFile})
	if !errors.Is(err, nativeauth.ErrSetupRequired) {
		t.Fatalf("missing setup did not identify the explicit setup step: %v", err)
	}
}
