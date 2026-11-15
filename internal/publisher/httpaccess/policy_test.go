package httpaccess

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherVisitorPolicyRejectsRetiredScopeBeforeFetching(t *testing.T) {
	client := &visitorfixture.PolicyClient{Key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
	for _, scope := range []visitorscope.Scope{
		{Kind: "public_url", ID: "url_" + strings.Repeat("A", 22)},
		{Kind: "public_url", ID: "svc_" + strings.Repeat("A", 22)},
		{Kind: visitorscope.Service, ID: "url_" + strings.Repeat("A", 22)},
	} {
		policy, err := PreparePolicy(t.Context(), client, scope, "srun_"+strings.Repeat("B", 22), 1, "run-secret", nil)
		if policy != nil {
			policy.Close()
			t.Fatal("retired scope acquired a policy owner")
		}
		if !errors.Is(err, visitorlease.ErrUpdate) || client.Calls.Load() != 0 {
			t.Fatal("retired scope fetched visitor authority", err)
		}
	}
}

func TestPublisherVisitorPolicyRetiredResponseCannotExtendServiceAuthority(t *testing.T) {
	for _, kind := range []string{"retired kind", "retired ID"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				base := &visitorfixture.PolicyClient{Key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
				var changed bool
				client := policyClientFunc(func(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
					update, err := base.ReadPublisherVisitorPolicy(ctx, request, token)
					if changed {
						if kind == "retired kind" {
							update.Policy.Resource.Kind = "public_url"
						} else {
							update.Policy.Resource.Id = "url_" + strings.Repeat("A", 22)
						}
					}
					return update, err
				})
				scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
				policy, err := PreparePolicy(t.Context(), client, scope, "srun_"+strings.Repeat("B", 22), 1, "run-secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer policy.Close()
				before, _, _ := policy.Lease().Current()
				changed = true
				time.Sleep(time.Second)
				if err := policy.Refresh(t.Context()); !errors.Is(err, visitorlease.ErrUpdate) {
					t.Fatal("retired response did not fail closed", err)
				}
				after, enabled, _ := policy.Lease().Current()
				if !enabled || after.Scope != scope || after.VisitorPolicyRevision != before.VisitorPolicyRevision || !after.ValidUntil.Equal(before.ValidUntil) {
					t.Fatal("retired response changed service authority or extended its deadline")
				}
			})
		})
	}
}

func TestPublisherVisitorPolicyOutageEndsTrafficWithoutVisitorRPCs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &visitorfixture.PolicyClient{Key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
		scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
		policy, err := PreparePolicy(t.Context(), client, scope, "srun_"+strings.Repeat("B", 22), 1, "run-secret", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		view, enabled, _ := policy.lease.Current()
		if !enabled {
			t.Fatal("publisher became ready without policy")
		}
		permission := visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: 1, Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("C", 22), SessionID: "cs_" + strings.Repeat("D", 22)}, ExpiresAt: time.Now().Add(time.Minute)}
		token, err := visitortoken.Sign(view.Issuer, "test-key", client.Key, permission, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		before := client.Calls.Load()
		for range 10 {
			if _, err := visitortoken.VerifyBearer(token, view, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		if client.Calls.Load() != before {
			t.Fatal("prepared verification made a control call")
		}
		verified, err := visitortoken.VerifyBearer(token, view, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Bool
		guard, err := policy.lease.Bind(verified, netip.MustParseAddr("192.0.2.1"), func() { stopped.Store(true) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		client.Fail.Store(true)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if !stopped.Load() {
			t.Fatal("background failures extended publisher authority")
		}
		if _, enabled, _ := policy.lease.Current(); enabled {
			t.Fatal("publisher retained expired visitor policy")
		}
		client.Fail.Store(false)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if _, enabled, _ := policy.lease.Current(); !enabled {
			t.Fatal("publisher did not recover through a fresh snapshot")
		}
	})
}
