package local

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/tnl"
)

var goSDKOwnerDescriptor = flag.String("tnl-sdk-owner-descriptor", "", "private native owner descriptor for the Go SDK launcher fixture")

// the helper replaces only endpoint process discovery, not publication. the SDK
// sends the canonical private requests to the real native owner in this test.
func TestGoSDKEndpointProcess(t *testing.T) {
	if *goSDKOwnerDescriptor == "" {
		t.Skip("endpoint helper requires an explicit private descriptor")
	}
	owner, err := publisherprotocol.ReadEndpoint(*goSDKOwnerDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	var invocationID string
	for index, argument := range os.Args {
		if argument == "--invocation-id" && index+1 < len(os.Args) {
			invocationID = os.Args[index+1]
		}
	}
	var endpoint publisherprotocol.Endpoint
	if err := publisherprotocol.Call(t.Context(), owner, "POST", "/v1/capabilities", publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocationID}, &endpoint); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(endpoint); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func goSDKPublicationFixture(t *testing.T, hooks testutil.PublishingHooks) (*publishingtest.Fixture, tnl.Options, <-chan bool) {
	t.Helper()
	a, _, body, fixture := invocationRuntime(t, hooks)
	identityID := body["publisher_identity_id"].(string)
	// this real transport fixture uses its pre-enrolled identity. production
	// source exchange, key persistence and original-key cleanup have separate
	// canonical-client proofs in application_authority and application_session.
	a.ApplicationAuthority = applicationAuthority(func(ctx context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		profile, err := a.state.Server(ctx, fixture.URL)
		if err != nil {
			return invocation.ApplicationGrant{}, err
		}
		control, err := clientcontrol.New(fixture.URL, fixture.HTTP, "")
		if err != nil {
			return invocation.ApplicationGrant{}, err
		}
		authority, err := clientauthority.New(fixture.URL, fixture.HTTP, "")
		if err != nil {
			return invocation.ApplicationGrant{}, err
		}
		native, err := publisheridentity.ResolveAdHoc(ctx, profile, publisheridentity.NativeControl{PublicURLControl: control}, authority, fixture.URL, "", "", "", "", "", identityID, nil)
		if err != nil {
			return invocation.ApplicationGrant{}, err
		}
		publicURL, err := native.Allocate(ctx, controlv1.AllocateEphemeralPublicURLRequest{InvocationId: selection.InvocationID, Target: selection.Target, RequirePostQuantum: selection.RequirePostQuantum})
		return invocation.ApplicationGrant{Control: native, PublisherIdentityID: native.PublisherIdentityID(), PublicURL: publicURL, RefreshAuth: func(context.Context, json.RawMessage) error { return nil }, Cleanup: func(ctx context.Context) error { return native.DeletePublicURL(ctx, publicURL.Id) }}, err
	})
	attached := make(chan bool, 2)
	a.AttachPublication = func(_ context.Context, _ publisherapp.Service, config *publisher.Config) error {
		attached <- config.RequirePostQuantum != nil && *config.RequirePostQuantum
		return nil
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	descriptor := filepath.Join(directory, "owner.json")
	if err := publisherprotocol.WriteEndpoint(descriptor, a.capabilities.Owner()); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	binary := filepath.Join(directory, "tnl")
	script := fmt.Sprintf("#!/bin/sh\nexec %s -test.run='^TestGoSDKEndpointProcess$' -tnl-sdk-owner-descriptor=%s -- \"$@\"\n", quote(executable), quote(descriptor))
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	options := tnl.Options{ServerURL: fixture.URL, Namespace: fixture.Namespace, Directory: a.project.Root, Binary: binary, OIDCSource: &tnl.OIDCSource{MachineID: "mci_0123456789ABCDEFGHIJKL", Assertion: func(context.Context) (tnl.OIDCAssertion, error) {
		return tnl.OIDCAssertion{Token: "fixture-proof", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}}}
	prepared, err := tnl.PreparePublisherIdentity(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	options.PublisherIdentity, options.OIDCSource = prepared, nil
	return fixture, options, attached
}

func TestGoSDKNativePublicationTrafficAndCleanup(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	fixture, options, attached := goSDKPublicationFixture(t, testutil.PublishingHooks{})
	for attempt := range 2 {
		options.RequirePostQuantum = attempt == 1
		ctx, cancel := context.WithCancel(t.Context())
		tunnel, err := tnl.Open(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), options)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if requirement := <-attached; requirement != options.RequirePostQuantum {
			cancel()
			t.Fatal("Go SDK lost the public HTTPS requirement")
		}
		if status, _, err := fixture.Visit(t.Context(), tunnel.URL()); err != nil || status != 204 {
			cancel()
			t.Fatalf("Go SDK handler was not reachable through native publication: status=%d err=%v", status, err)
		}
		cancel()
		if err := tunnel.Wait(); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.Close(); err != nil {
			t.Fatal(err)
		}
	}
	deleted := fixture.DeletedIDs()
	if fixture.Allocations.Load() != 2 || fixture.Runs.Load() != 2 || len(deleted) != 2 || deleted[0] == deleted[1] {
		t.Fatalf("SDK invocations lost independent allocation or cleanup: allocations=%d runs=%d deleted=%v", fixture.Allocations.Load(), fixture.Runs.Load(), deleted)
	}
}

func TestGoSDKNativeCancellationBeforeReadyCleansExactAllocation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	atReady := make(chan controlv1.PublishRunSetup, 1)
	fixture, options, _ := goSDKPublicationFixture(t, testutil.PublishingHooks{Ready: func(ctx context.Context, setup controlv1.PublishRunSetup) error {
		atReady <- setup
		<-ctx.Done()
		return context.Cause(ctx)
	}})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		tunnel, err := tnl.Open(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), options)
		if tunnel != nil {
			err = errors.Join(err, tunnel.Close(), errors.New("Open returned an unready native run"))
		}
		done <- err
	}()
	var setup controlv1.PublishRunSetup
	select {
	case setup = <-atReady:
	case err := <-done:
		t.Fatal("native publication stopped before reaching readiness", err)
	case <-time.After(10 * time.Second):
		t.Fatal("native publication did not reach readiness")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("canceled Open lost its original cause", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("canceled Open did not join exact native cleanup")
	}
	deleted := fixture.DeletedIDs()
	if fixture.Allocations.Load() != 1 || fixture.Runs.Load() != 1 || len(deleted) != 1 || deleted[0] != setup.PublicUrl.Id {
		t.Fatalf("canceled Go SDK cleaned a different allocation: allocations=%d runs=%d deleted=%v expected=%s", fixture.Allocations.Load(), fixture.Runs.Load(), deleted, setup.PublicUrl.Id)
	}
}
