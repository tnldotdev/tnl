package httpaccess

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherVisitorPolicyRejectsMissingOrChangedSourceMasterWithoutExtendingPolicy(t *testing.T) {
	for _, mutate := range []func(*controlv1.VisitorPolicyUpdate){
		func(update *controlv1.VisitorPolicyUpdate) { update.VisitorSourceKey = nil },
		func(update *controlv1.VisitorPolicyUpdate) { update.VisitorSourceKey = new([]byte{1}) },
		func(update *controlv1.VisitorPolicyUpdate) { update.VisitorSourceKey = new(make([]byte, 32)) },
		func(update *controlv1.VisitorPolicyUpdate) {
			update.VisitorSourceKey = new(bytes.Repeat([]byte{2}, 32))
		},
		func(update *controlv1.VisitorPolicyUpdate) { update.VisitorSourceAuthority = new([]byte{1}) },
	} {
		synctest.Test(t, func(t *testing.T) {
			base := &visitorfixture.PolicyClient{Key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
			base.Revision.Store(1)
			var changed bool
			client := policyClientFunc(func(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
				update, err := base.ReadPublisherVisitorPolicy(ctx, request, token)
				if changed {
					mutate(&update)
				}
				return update, err
			})
			policy, err := PreparePolicy(t.Context(), client, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: visitorfixture.PublicURLID}, "run", 1, "run-secret", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer policy.Close()
			before, _, _ := policy.Lease().Current()
			changed = true
			if err := policy.Refresh(t.Context()); !errors.Is(err, visitorlease.ErrUpdate) {
				t.Fatal("invalid run master lost its policy classification", err)
			}
			after, enabled, _ := policy.Lease().Current()
			if !enabled || !after.ValidUntil.Equal(before.ValidUntil) || policy.SourceKey() != ([32]byte{1}) {
				t.Fatal("invalid source-key renewal changed serving authority")
			}
		})
	}
}

func TestPublisherVisitorPolicySourceKeyIsImmutableDuringRefresh(t *testing.T) {
	for _, kind := range []visitorscope.Kind{visitorscope.PublicURL, visitorscope.Service} {
		t.Run(string(kind), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				prefix, want := "url_", [32]byte{1}
				if kind == visitorscope.Service {
					prefix, want = "svc_", [32]byte{}
				}
				client := &visitorfixture.PolicyClient{Key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
				policy, err := PreparePolicy(t.Context(), client, visitorscope.Scope{Kind: kind, ID: prefix + strings.Repeat("A", 22)}, "run", 1, "run-secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer policy.Close()
				if got := policy.SourceKey(); got != want {
					t.Fatal("initial source facts did not match the resource kind")
				}
				// no ordering between this read and refresh: callers may read the
				// initial source facts without joining the policy refresh owner.
				read := make(chan [32]byte, 1)
				go func() { read <- policy.SourceKey() }()
				if err := policy.Refresh(t.Context()); err != nil {
					t.Fatal(err)
				}
				if got := <-read; got != want || policy.SourceKey() != want {
					t.Fatal("refresh changed immutable source facts")
				}
				if _, enabled, _ := policy.Lease().Current(); !enabled {
					t.Fatal("refresh lost serving authority")
				}
			})
		})
	}
}
