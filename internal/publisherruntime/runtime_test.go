package publisherruntime

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/internal/publisherprovenance"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type lostStartControl struct {
	public              ed25519.PublicKey
	requests            []controlv1.PublisherRuntimeRequest
	startLost, replaced bool
}

type runtimeControlFunc func(context.Context, controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error)

func (f runtimeControlFunc) PublisherRuntime(ctx context.Context, r controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	return f(ctx, r)
}

func TestInvalidRuntimeReplyCannotStartOrRenew(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, epoch := range []int64{-1, math.MaxInt64, 0} {
		calls := 0
		c := runtimeControlFunc(func(_ context.Context, r controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
			calls++
			return controlv1.PublisherRuntimeResponse{Epoch: epoch}, nil
		})
		o, err := New(c, "https://control.example", "publisher", "key", "scope", private)
		if err != nil {
			t.Fatal(err)
		}
		_, err = o.Renew(t.Context())
		reason, _ := failure.ReasonOf(err)
		if reason != failure.ServerResponseInvalid || o.started || epoch != 0 && calls != 1 {
			t.Fatal("invalid runtime reply advanced startup", epoch, err)
		}
	}
}

func (c *lostStartControl) PublisherRuntime(_ context.Context, r controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	c.requests = append(c.requests, r)
	if _, err := publisheridentity.Verify(r.Assertion, "publisher", "key", publisheridentity.RuntimeScope("scope", string(r.Action), r.ProcessRunId, r.ExpectedEpoch, publisherprovenance.Digest(r.Deployment)), "https://control.example/v1/publisher-runtime", c.public, time.Now()); err != nil {
		return controlv1.PublisherRuntimeResponse{}, err
	}
	if c.replaced {
		return controlv1.PublisherRuntimeResponse{}, controlclient.ErrStatusConflict
	}
	epoch := int64(7)
	if r.Action != controlv1.RuntimeInspect {
		epoch++
	}
	if r.Action == controlv1.RuntimeStart && !c.startLost {
		c.startLost = true
		return controlv1.PublisherRuntimeResponse{}, controlclient.ErrUnavailable
	}
	return controlv1.PublisherRuntimeResponse{Epoch: epoch, LeaseExpiresAt: new(time.Now().Add(time.Minute))}, nil
}

func TestRuntimeDeploymentRetainedAcrossLostReply(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	control := &lostStartControl{public: public}
	report := controlv1.PublisherDeploymentReport{DeploymentId: "aws-example", Provider: "aws", ReplicaKey: "replica-1", Instance: "instance", Image: "ghcr.io/tnldotdev/tnl@sha256:" + strings.Repeat("a", 64), SoftwareVersion: "devel", TemplateVersion: "2", TemplateSha256: strings.Repeat("b", 64)}
	expected := report
	owner, err := New(control, "https://control.example", "publisher", "key", "scope", private, &report)
	if err != nil {
		t.Fatal(err)
	}
	report.Image = "changed after construction"
	if _, err := owner.Renew(t.Context()); !errors.Is(err, controlclient.ErrUnavailable) {
		t.Fatal(err)
	}
	if id := observability.IdentityFromContext(owner.ObservabilityContext(t.Context(), "team", "scope")); id != (observability.Identity{}) {
		t.Fatal("unconfirmed runtime acquired deployment metric scope", id)
	}
	if _, err := owner.Renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	parent := observability.ReplaceIdentity(t.Context(), observability.Identity{TeamID: "old-team", DeploymentID: "old-deployment", PublicURLID: "old-url"})
	scoped := owner.ObservabilityContext(parent, "team", "scope")
	if id := observability.IdentityFromContext(scoped); id != (observability.Identity{TeamID: "team", PublisherGroupID: "scope", PublisherIdentityID: "publisher", DeploymentID: expected.DeploymentId, ReplicaKey: expected.ReplicaKey}) {
		t.Fatal("accepted immutable runtime deployment was not bound to a fresh identity", id)
	}
	service := observability.NarrowIdentity(scoped, observability.Identity{ServiceID: "service"})
	if id := observability.IdentityFromContext(service); id.DeploymentID != expected.DeploymentId || id.ReplicaKey != expected.ReplicaKey || id.ServiceID != "service" || id.PublicURLID != "" {
		t.Fatal("service scope lost deployment provenance or leaked prior public URL", id)
	}
	if id := observability.IdentityFromContext(owner.ObservabilityContext(parent, "team", "different-group")); id != (observability.Identity{}) {
		t.Fatal("runtime attributed a foreign group", id)
	}
	if _, err := owner.Renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := owner.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if id := observability.IdentityFromContext(owner.ObservabilityContext(scoped, "team", "scope")); id != (observability.Identity{}) {
		t.Fatal("stopped runtime retained deployment scope", id)
	}
	for _, request := range control.requests {
		if request.Deployment == nil || *request.Deployment != expected {
			t.Fatal("runtime metadata changed during lifecycle")
		}
	}
}

func TestLostStartRetainsProcessAndExpectedEpoch(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &lostStartControl{public: public}
	o, err := New(c, "https://control.example", "publisher", "key", "scope", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.Renew(t.Context()); !errors.Is(err, controlclient.ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err = o.Renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(c.requests) != 3 || c.requests[0].Action != controlv1.RuntimeInspect || c.requests[1].Action != controlv1.RuntimeStart || c.requests[2].Action != controlv1.RuntimeStart || c.requests[1].ExpectedEpoch != 7 || c.requests[2].ExpectedEpoch != 7 || c.requests[1].ProcessRunId != c.requests[2].ProcessRunId || c.requests[1].Assertion == c.requests[2].Assertion {
		t.Fatal("lost start changed binding or reused assertion")
	}
	if _, err = o.Renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	if c.requests[3].Action != controlv1.RuntimeRenew || c.requests[3].ExpectedEpoch != 8 || c.requests[3].ProcessRunId != c.requests[1].ProcessRunId {
		t.Fatal("renew changed process epoch")
	}
	c.replaced = true
	for range 2 {
		_, err = o.Renew(t.Context())
		if !errors.Is(err, controlclient.ErrStatusConflict) {
			t.Fatal(err)
		}
		reason, _ := failure.ReasonOf(err)
		definition, _ := failure.DefinitionFor(reason)
		if definition.Retry != failure.RetryAfterChange {
			t.Fatal("replaced runtime would restart automatically")
		}
	}
	for _, r := range c.requests[4:] {
		if r.Action != controlv1.RuntimeRenew || r.ExpectedEpoch != 8 {
			t.Fatal("stale runtime re-inspected or started")
		}
	}
	next, err := New(c, "https://control.example", "publisher", "key", "scope", private)
	if err != nil {
		t.Fatal(err)
	}
	if next.run == o.run {
		t.Fatal("new process reused run ID")
	}
}

func TestRuntimeOwnsSigningKeySnapshot(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &lostStartControl{public: public, startLost: true}
	owner, err := New(c, "https://control.example", "publisher", "key", "scope", private)
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	if _, err := owner.Renew(t.Context()); err != nil {
		t.Fatal("caller mutation changed the runtime signing identity", err)
	}
}
