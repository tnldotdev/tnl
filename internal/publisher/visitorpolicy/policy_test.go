package visitorpolicy

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

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type policyClientFixture struct {
	key      ed25519.PrivateKey
	fail     atomic.Bool
	calls    atomic.Int64
	revision atomic.Int64
}

type startupPolicyClient func(context.Context, controlv1.PublisherVisitorPolicyRequest, string) (controlv1.VisitorPolicyUpdate, error)

func (f startupPolicyClient) ReadPublisherVisitorPolicy(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	return f(ctx, body, token)
}

func TestPublisherVisitorPolicyStartupRetriesOnlyTemporaryFailures(t *testing.T) {
	for _, kind := range []visitorscope.Kind{visitorscope.PublicURL, visitorscope.Service} {
		t.Run(string(kind), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				prefix := "url_"
				if kind == visitorscope.Service {
					prefix = "svc_"
				}
				scope := visitorscope.Scope{Kind: kind, ID: prefix + strings.Repeat("A", 22)}
				base := &policyClientFixture{key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
				calls := 0
				client := startupPolicyClient(func(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
					calls++
					if body.RunId != "run" || body.RunNumber != 1 || body.Resource.Id != scope.ID || token != "run-secret" || body.AfterRevision != 0 {
						t.Error("startup retry changed the authority or reused a failed snapshot")
					}
					if calls == 1 {
						return controlv1.VisitorPolicyUpdate{}, failure.Wrap("read policy", failure.ServerUnavailable, errors.New("serialization conflict"))
					}
					if calls == 2 {
						return controlv1.VisitorPolicyUpdate{}, failure.Wrap("read policy", failure.ServerRateLimited, errors.New("retry later"))
					}
					return base.ReadPublisherVisitorPolicy(ctx, body, token)
				})
				started := time.Now()
				policy, err := Prepare(t.Context(), client, scope, "run", 1, "run-secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer policy.Close()
				if calls != 3 || time.Since(started) != 300*time.Millisecond {
					t.Fatal("temporary startup failures were not backed off", calls, time.Since(started))
				}
				if _, enabled, _ := policy.Lease.Current(); !enabled {
					t.Fatal("startup returned before installing the successful snapshot")
				}
			})
		})
	}
}

func TestPublisherVisitorPolicyStartupDenialAndInvalidResponseDoNotRetry(t *testing.T) {
	for _, reason := range []failure.Reason{failure.Authentication, failure.ServerResponseInvalid, failure.ServerResourceNotFound} {
		t.Run(string(reason), func(t *testing.T) {
			cause := errors.New("private failure context")
			denied := failure.Wrap("read policy", reason, cause)
			calls := 0
			client := startupPolicyClient(func(context.Context, controlv1.PublisherVisitorPolicyRequest, string) (controlv1.VisitorPolicyUpdate, error) {
				calls++
				return controlv1.VisitorPolicyUpdate{}, denied
			})
			scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
			policy, err := Prepare(t.Context(), client, scope, "run", 1, "run-secret", nil)
			if policy != nil || !errors.Is(err, cause) || calls != 1 {
				t.Fatal("terminal startup failure retried or lost its cause", err, calls)
			}
		})
	}
}

func TestPublisherVisitorPolicyStartupOutageHasFixedBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cause := errors.New("serialization conflict")
		calls := 0
		client := startupPolicyClient(func(context.Context, controlv1.PublisherVisitorPolicyRequest, string) (controlv1.VisitorPolicyUpdate, error) {
			calls++
			return controlv1.VisitorPolicyUpdate{}, failure.Wrap("read policy", failure.ServerUnavailable, cause)
		})
		scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
		started := time.Now()
		policy, err := Prepare(t.Context(), client, scope, "run", 1, "run-secret", nil)
		if policy != nil || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cause) || time.Since(started) != 10*time.Second || calls > 20 {
			t.Fatal("startup retry escaped its budget or lost its cause", err, calls, time.Since(started))
		}
	})
}

func TestPublisherVisitorPolicyStartupCancellationInterruptsRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		calls := 0
		client := startupPolicyClient(func(context.Context, controlv1.PublisherVisitorPolicyRequest, string) (controlv1.VisitorPolicyUpdate, error) {
			calls++
			cancel()
			return controlv1.VisitorPolicyUpdate{}, failure.Wrap("read policy", failure.ServerUnavailable, errors.New("temporary"))
		})
		scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
		policy, err := Prepare(ctx, client, scope, "run", 1, "run-secret", nil)
		if policy != nil || !errors.Is(err, context.Canceled) || calls != 1 {
			t.Fatal("canceled startup retried", err, calls)
		}
	})
}

func TestPublisherVisitorPolicyConcurrentRefreshUsesCurrentRevision(t *testing.T) {
	for _, kind := range []visitorscope.Kind{visitorscope.PublicURL, visitorscope.Service} {
		t.Run(string(kind), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				prefix := "url_"
				if kind == visitorscope.Service {
					prefix = "svc_"
				}
				scope := visitorscope.Scope{Kind: kind, ID: prefix + strings.Repeat("A", 22)}
				base := &policyClientFixture{key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
				blocked, release := context.WithCancel(t.Context())
				defer release()
				started := make(chan struct{})
				var calls atomic.Int64
				client := startupPolicyClient(func(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
					n := calls.Add(1)
					if body.AfterRevision != n-1 {
						t.Errorf("refresh %d used revision %d, want %d", n, body.AfterRevision, n-1)
					}
					if n == 2 {
						close(started)
						select {
						case <-blocked.Done():
						case <-ctx.Done():
							return controlv1.VisitorPolicyUpdate{}, context.Cause(ctx)
						}
					}
					base.revision.Store(n)
					return base.ReadPublisherVisitorPolicy(ctx, body, token)
				})
				policy, err := Prepare(t.Context(), client, scope, "run", 1, "run-secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer policy.Close()
				first, second := make(chan error, 1), make(chan error, 1)
				go func() { first <- policy.Refresh(t.Context()) }()
				<-started
				go func() { second <- policy.Refresh(t.Context()) }()
				synctest.Wait()
				if got := calls.Load(); got != 2 {
					t.Error("overlapping refresh issued a stale-revision request", got)
				}
				release()
				if err := <-first; err != nil {
					t.Error("first policy refresh failed", err)
				}
				if err := <-second; err != nil {
					t.Error("next policy refresh failed", err)
				}
				view, enabled, _ := policy.Lease.Current()
				if !enabled || view.VisitorPolicyRevision != 3 || calls.Load() != 3 {
					t.Fatal("refresh did not install the current policy", view.VisitorPolicyRevision, calls.Load())
				}
			})
		})
	}
}

func TestPublisherVisitorPolicyWaitingRefreshIsCancelableAndBounded(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "request budget"}[timeout], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
				base := &policyClientFixture{key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
				blocked, release := context.WithCancel(t.Context())
				defer release()
				started := make(chan struct{})
				var calls, waitingCalls atomic.Int64
				type waitingKey struct{}
				client := startupPolicyClient(func(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
					if ctx.Value(waitingKey{}) != nil {
						waitingCalls.Add(1)
					}
					if calls.Add(1) == 2 {
						close(started)
						// model a response that arrives after cancellation. it must
						// neither strand a waiting caller nor extend its authority.
						<-blocked.Done()
					}
					return base.ReadPublisherVisitorPolicy(ctx, body, token)
				})
				policy, err := Prepare(t.Context(), client, scope, "run", 1, "run-secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer policy.Close()
				before, _, _ := policy.Lease.Current()
				first, waiting := make(chan error, 1), make(chan error, 1)
				go func() { first <- policy.Refresh(t.Context()) }()
				<-started
				ctx, cancel := context.WithCancelCause(context.WithValue(t.Context(), waitingKey{}, true))
				defer cancel(context.Canceled)
				begin := time.Now()
				go func() { waiting <- policy.Refresh(ctx) }()
				synctest.Wait()
				want := error(context.DeadlineExceeded)
				if !timeout {
					want = errors.New("credential preparation stopped")
					cancel(want)
				}
				if err := <-waiting; !errors.Is(err, want) {
					t.Error("waiting refresh lost its cancellation or deadline", err)
				}
				if waitingCalls.Load() != 0 || timeout && time.Since(begin) != 2*time.Second {
					t.Error("waiting refresh escaped its request budget or issued a control call", waitingCalls.Load(), time.Since(begin))
				}
				current, enabled, _ := policy.Lease.Current()
				if !enabled || !current.ValidUntil.Equal(before.ValidUntil) {
					t.Error("waiting preparation changed the last confirmed policy deadline")
				}
				release()
				err = <-first
				if timeout && !errors.Is(err, context.DeadlineExceeded) || !timeout && err != nil {
					t.Error("blocked response ignored its original request deadline", err)
				}
			})
		})
	}
}

func (f *policyClientFixture) ReadPublisherVisitorPolicy(_ context.Context, body controlv1.PublisherVisitorPolicyRequest, credential string) (controlv1.VisitorPolicyUpdate, error) {
	f.calls.Add(1)
	if credential != "run-secret" {
		return controlv1.VisitorPolicyUpdate{}, errors.New("wrong run credential")
	}
	if f.fail.Load() {
		return controlv1.VisitorPolicyUpdate{}, errors.New("control unavailable")
	}
	now := time.Now()
	revision := max(int64(1), f.revision.Load())
	metadataRevision := int64(0)
	if body.Resource.Kind == "service" {
		metadataRevision = 1
	}
	events := []int64{}
	if body.AfterRevision != 0 {
		for next := body.AfterRevision + 1; next <= revision; next++ {
			events = append(events, next)
		}
	}
	return controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, Revisions: events, SnapshotRequired: body.AfterRevision == 0,
		Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: "preview.example.test", Port: 443, Issuer: "https://control.example.test", VisitorPolicyRevision: revision, KeyRevision: 1, MetadataRevision: metadataRevision,
			ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Enabled: true, Anonymous: false, VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "test-key", PublicKey: f.key.Public().(ed25519.PublicKey)}}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}}}, nil
}

func TestPublisherVisitorPolicyOutageEndsTrafficWithoutVisitorRPCs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &policyClientFixture{key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
		scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
		policy, err := Prepare(t.Context(), client, scope, "pr_"+strings.Repeat("B", 22), 1, "run-secret", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		view, enabled, _ := policy.Lease.Current()
		if !enabled {
			t.Fatal("publisher became ready without policy")
		}
		permission := visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: 1, Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("C", 22), SessionID: "cs_" + strings.Repeat("D", 22)}, ExpiresAt: time.Now().Add(time.Minute)}
		token, err := visitortoken.Sign(view.Issuer, "test-key", client.key, permission, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		before := client.calls.Load()
		for range 10 {
			if _, err := visitortoken.VerifyBearer(token, view, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		if client.calls.Load() != before {
			t.Fatal("prepared verification made a control call")
		}
		verified, err := visitortoken.VerifyBearer(token, view, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Bool
		guard, err := policy.Lease.Bind(verified, netip.MustParseAddr("192.0.2.1"), func() { stopped.Store(true) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		client.fail.Store(true)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if !stopped.Load() {
			t.Fatal("background failures extended publisher authority")
		}
		if _, enabled, _ := policy.Lease.Current(); enabled {
			t.Fatal("publisher retained expired visitor policy")
		}
		client.fail.Store(false)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if _, enabled, _ := policy.Lease.Current(); !enabled {
			t.Fatal("publisher did not recover through a fresh snapshot")
		}
	})
}
