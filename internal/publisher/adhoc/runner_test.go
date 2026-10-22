package adhoc

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestRunCleansExactAllocationAfterCanceledCallback(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	f := publishingtest.New(t, testutil.PublishingHooks{})
	secret, err := f.NamespaceEnrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	d, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	state, err := d.Server(t.Context(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	invocation, _ := opaqueid.New(opaqueid.InvocationPrefix)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	registrationErr := errors.New("registration is no longer current")
	allocated := ""
	err = Run(ctx, Options{ControlURL: f.URL, HTTPClient: f.HTTP, State: state, EnrollmentKey: secret, InvocationID: invocation, Target: "http://app.internal:3000", Limits: publisher.ApplicationLimits{Requests: 1}, OnAllocated: func(route controlv1.PublicURL) error { allocated = route.Id; cancel(); return registrationErr }})
	deleted := f.DeletedIDs()
	if !errors.Is(err, registrationErr) || f.Allocations.Load() != 1 || f.Deletions.Load() != 1 || len(deleted) != 1 || deleted[0] != allocated || f.Runs.Load() != 0 {
		t.Fatalf("allocation cleanup lost exact ownership: err=%v allocations=%d deleted=%v allocated=%s", err, f.Allocations.Load(), deleted, allocated)
	}
}

func TestRunRejectsLimitsAndMissingScopeBeforeAllocation(t *testing.T) {
	invocation, _ := opaqueid.New(opaqueid.InvocationPrefix)
	options := Options{ControlURL: "https://control.example", State: &clientstate.Store{}, InvocationID: invocation, Target: "http://127.0.0.1:3000", Limits: publisher.ApplicationLimits{RateRequests: 1, RatePer: -time.Second}}
	if err := Run(t.Context(), options); err == nil {
		t.Fatal("invalid rate reached allocation")
	}
	options.Limits = publisher.ApplicationLimits{}
	if err := Run(t.Context(), options); !errors.Is(err, nativeauth.ErrSelection) {
		t.Fatalf("missing scope accepted: %v", err)
	}
}
