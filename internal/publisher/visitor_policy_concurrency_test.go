package publisher

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type policyClientFunc func(context.Context, controlv1.PublisherVisitorPolicyRequest, string) (controlv1.VisitorPolicyUpdate, error)

func (f policyClientFunc) ReadPublisherVisitorPolicy(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	return f(ctx, body, token)
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
				client := policyClientFunc(func(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
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
				policy, err := prepareVisitorPolicy(t.Context(), client, scope, "run", 1, "run-secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer policy.Close()
				first, second := make(chan error, 1), make(chan error, 1)
				go func() { first <- policy.refresh(t.Context()) }()
				<-started
				go func() { second <- policy.refresh(t.Context()) }()
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
				view, enabled, _ := policy.lease.Current()
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
				client := policyClientFunc(func(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
					if ctx.Value(waitingKey{}) != nil {
						waitingCalls.Add(1)
					}
					if calls.Add(1) == 2 {
						close(started)
						<-blocked.Done()
					}
					return base.ReadPublisherVisitorPolicy(ctx, body, token)
				})
				policy, err := prepareVisitorPolicy(t.Context(), client, scope, "run", 1, "run-secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer policy.Close()
				before, _, _ := policy.lease.Current()
				first, waiting := make(chan error, 1), make(chan error, 1)
				go func() { first <- policy.refresh(t.Context()) }()
				<-started
				ctx, cancel := context.WithCancelCause(context.WithValue(t.Context(), waitingKey{}, true))
				defer cancel(context.Canceled)
				begin := time.Now()
				go func() { waiting <- policy.refresh(ctx) }()
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
				current, enabled, _ := policy.lease.Current()
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

// retain a future deadline without delivering its timer callback.
type timerLagContext struct {
	context.Context
	deadline time.Time
}

func (c timerLagContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestPublisherVisitorPolicyAbsoluteDeadlineFencesTimerLag(t *testing.T) {
	for _, lateResponse := range []bool{false, true} {
		t.Run(map[bool]string{false: "before fetch", true: "control response"}[lateResponse], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				base := &policyClientFixture{key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
				client := policyClientFunc(func(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
					if base.calls.Load() > 0 && lateResponse {
						time.Sleep(time.Second)
						if ctx.Err() != nil {
							t.Error("fixture did not retain the delayed timer callback")
						}
					}
					return base.ReadPublisherVisitorPolicy(ctx, body, token)
				})
				scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
				policy, err := prepareVisitorPolicy(t.Context(), client, scope, "run", 1, "run-secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer policy.Close()
				before, _, _ := policy.lease.Current()
				call := timerLagContext{Context: t.Context(), deadline: time.Now().Add(time.Second)}
				wantCalls := int64(2)
				if !lateResponse {
					time.Sleep(time.Second)
					wantCalls = 1
				}
				if err := policy.refresh(call); !errors.Is(err, context.DeadlineExceeded) {
					t.Error("refresh accepted an expired absolute deadline", err)
				}
				if base.calls.Load() != wantCalls {
					t.Error("expired preparation issued another control call", base.calls.Load())
				}
				current, enabled, _ := policy.lease.Current()
				if !enabled || !current.ControlTime.Equal(before.ControlTime) || !current.ValidUntil.Equal(before.ValidUntil) {
					t.Error("expired preparation installed a late observation")
				}
			})
		})
	}
}
