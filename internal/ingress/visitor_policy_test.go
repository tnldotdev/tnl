package ingress

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	failureproblem "github.com/tnldotdev/tnl/internal/failure/problem"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publicPolicyTestClient struct {
	ControlClient
	read func(context.Context, string, ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error)
}

func (c publicPolicyTestClient) ReadIngressVisitorPolicy(ctx context.Context, id string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	return c.read(ctx, id, body)
}

func publicPolicyWire(body ingressv1.IngressVisitorPolicyRequest, hostname string, now time.Time) controlv1.VisitorPolicyUpdate {
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("i", 32)))
	return controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, SnapshotRequired: body.AfterRevision == 0, Revisions: []int64{},
		Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: hostname, Port: 443, Issuer: "https://control.example.test",
			VisitorPolicyRevision: 1, KeyRevision: 1, Enabled: true, ObservedAt: now, ValidUntil: now.Add(10 * time.Second),
			VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "ingress-test", PublicKey: key.Public().(ed25519.PublicKey)}}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}}}
}

func publicPolicyEvent(now time.Time, revision, number int64, hostname string, ready bool) ingressv1.IngressRoutingTableEvent {
	event := readinessEvent(now, revision, number, hostname, ready)
	event.PublicUrlId = "url_" + strings.Repeat("A", 22)
	event.Entry.PublicUrlId = event.PublicUrlId
	return event
}

func TestPublicPolicyInstallationDoesNotWaitForStartingSiblingsOrVisitorRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		first := publicPolicyEvent(now, 1, 1, "pool.example", true)
		sibling := publicPolicyEvent(now, 2, 2, "pool.example", false)
		other := publicPolicyEvent(now, 3, 3, "other.example", false)
		other.PublicUrlId, other.Entry.PublicUrlId = "url_"+strings.Repeat("B", 22), "url_"+strings.Repeat("B", 22)
		blocked, release := make(chan struct{}), make(chan struct{})
		var calls atomic.Int64
		client := publicPolicyTestClient{read: func(ctx context.Context, id string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
			calls.Add(1)
			if id != "ingress" || body.IngressRunId != "run" || body.IngressLeaseRevision != 1 || body.PolicyRevision != 1 {
				t.Error("preparation lost its process or projection binding")
			}
			if body.PublishRunId == sibling.Entry.PublishRunId {
				close(blocked)
				select {
				case <-release:
				case <-ctx.Done():
					return controlv1.VisitorPolicyUpdate{}, ctx.Err()
				}
			}
			hostname := "pool.example"
			if body.Resource.Id == other.PublicUrlId {
				hostname = "other.example"
			}
			return publicPolicyWire(body, hostname, time.Now()), nil
		}}
		c := testLeaseController(t, client)
		c.publicRunPrepared = c.installedPublicPolicy
		owner := testIngressLease(now)
		if err := c.setLease(owner); err != nil {
			t.Fatal(err)
		}
		if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 3, Entries: []ingressv1.IngressRoutingTableEvent{first, sibling, other}}); err != nil {
			t.Fatal(err)
		}
		c.markRoutingTableCurrent(true)
		if c.Ready(now) || len(c.publicRunObservations(owner, now)) != 0 {
			t.Fatal("routing installation claimed future permission installation")
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- c.publicPolicyLoop(ctx) }()
		stop := sync.OnceFunc(func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
		defer stop()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		<-blocked
		if !c.Ready(time.Now()) {
			t.Fatal("starting sibling blocked initial installation of the ready run")
		}
		before := calls.Load()
		for range 10 {
			entries, reason := c.LookupAllWithReason("pool.example", time.Now())
			if reason != LookupCurrent || len(entries) != 1 || entries[0].PublishRunId != first.Entry.PublishRunId {
				t.Fatal("pending policy hid or joined its ready sibling", entries, reason)
			}
			if entries, reason := c.LookupAllWithReason("other.example", time.Now()); reason != LookupCurrent || len(entries) != 1 {
				t.Fatal("pending policy hid an unrelated URL", entries, reason)
			}
		}
		if calls.Load() != before || len(c.publicRunObservations(owner, time.Now())) != 2 {
			t.Fatal("lookup issued preparation I/O or observed a pending policy")
		}
		close(release)
		synctest.Wait()
		if entries, reason := c.LookupAllWithReason("pool.example", time.Now()); reason != LookupCurrent || len(entries) != 2 {
			t.Fatal("completed installation was not visible before observation", entries, reason)
		}
		for _, mutate := range []func(*ingressv1.IngressRoutingTableEntry, *ingressv1.IngressLease){
			func(entry *ingressv1.IngressRoutingTableEntry, _ *ingressv1.IngressLease) {
				entry.PublishRunId = "different"
			},
			func(entry *ingressv1.IngressRoutingTableEntry, _ *ingressv1.IngressLease) { entry.PublishRunNumber++ },
			func(entry *ingressv1.IngressRoutingTableEntry, _ *ingressv1.IngressLease) {
				entry.PublicUrlId = other.PublicUrlId
			},
			func(entry *ingressv1.IngressRoutingTableEntry, _ *ingressv1.IngressLease) { entry.PolicyRevision++ },
			func(entry *ingressv1.IngressRoutingTableEntry, _ *ingressv1.IngressLease) {
				entry.CanonicalHostname = "other.example"
			},
			func(_ *ingressv1.IngressRoutingTableEntry, owner *ingressv1.IngressLease) {
				owner.IngressId = "different"
			},
			func(_ *ingressv1.IngressRoutingTableEntry, owner *ingressv1.IngressLease) {
				owner.IngressRunId = "restarted"
			},
			func(_ *ingressv1.IngressRoutingTableEntry, owner *ingressv1.IngressLease) {
				owner.IngressLeaseRevision++
			},
		} {
			entry, changed := first.Entry, owner
			mutate(&entry, &changed)
			if _, ok := c.installedPublicPolicy(entry, changed, time.Now()); ok {
				t.Fatal("prepared permission crossed a resource/run/process/projection boundary")
			}
		}
		stop()
		if len(c.publicRunObservations(owner, time.Now())) != 0 {
			t.Fatal("shutdown retained installed authority")
		}
	})
}

func TestPublicPolicyPreparationIsNotCappedByInstalledRunCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		client := publicPolicyTestClient{read: func(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
			return publicPolicyWire(body, "pool.example", time.Now()), nil
		}}
		c := testLeaseController(t, client)
		owner := testIngressLease(now)
		if err := c.setLease(owner); err != nil {
			t.Fatal(err)
		}
		const installed = 4096
		events := make([]ingressv1.IngressRoutingTableEvent, installed+1)
		for index := range events {
			events[index] = publicPolicyEvent(now, int64(index+1), int64(index+1), "pool.example", false)
			if index < installed {
				run, err := c.preparePublicPolicy(t.Context(), events[index].Entry, owner)
				if err != nil {
					t.Fatal(err)
				}
				c.publicPolicies[run.request.PublishRunId] = run
			}
		}
		if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: int64(len(events)), Entries: events}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- c.publicPolicyLoop(ctx) }()
		defer func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if _, ok := c.installedPublicPolicy(events[installed].Entry, owner, time.Now()); !ok {
			t.Fatal("existing installations prevented another run from preparing policy")
		}
	})
}

func TestPublicPolicyClockTranslationAndOutageCannotExtendObservation(t *testing.T) {
	for _, offset := range []time.Duration{0, -3 * time.Hour, 3 * time.Hour} {
		t.Run(offset.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local := time.Now().Add(offset)
				control := local.Add(time.Hour)
				var unavailable atomic.Bool
				client := publicPolicyTestClient{read: func(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
					if unavailable.Load() {
						return controlv1.VisitorPolicyUpdate{}, errors.New("control unavailable")
					}
					return publicPolicyWire(body, "pool.example", control), nil
				}}
				c := testLeaseController(t, client)
				c.now = func() time.Time { return time.Now().Add(offset) }
				entry, owner := publicPolicyEvent(local, 1, 1, "pool.example", true).Entry, testIngressLease(local)
				entry.PublicUrlExpiresAt, owner.LeaseExpiresAt = control.Add(time.Hour), control.Add(time.Hour)
				run, err := c.preparePublicPolicy(t.Context(), entry, owner)
				if err != nil {
					t.Fatal(err)
				}
				defer run.close()
				c.publicPolicies[entry.PublishRunId] = run
				until, ok := c.installedPublicPolicy(entry, owner, local)
				if !ok || !until.Equal(control.Add(10*time.Second)) {
					t.Fatal("observation used local clock or receipt time as new authority", until, ok)
				}
				unavailable.Store(true)
				time.Sleep(10 * time.Second)
				synctest.Wait()
				owner.LeaseExpiresAt = owner.LeaseExpiresAt.Add(time.Hour)
				if _, ok := c.installedPublicPolicy(entry, owner, c.now()); ok {
					t.Fatal("process renewal or outage extended installed policy")
				}
			})
		})
	}
}

func TestPublicPolicyCancellationJoinsPendingInstallation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		client := publicPolicyTestClient{read: func(ctx context.Context, _ string, _ ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
			deadline, ok := ctx.Deadline()
			if !ok || !deadline.After(time.Now()) || deadline.After(time.Now().Add(2*time.Second)) {
				t.Error("preparation request did not receive its fixed budget")
			}
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			return controlv1.VisitorPolicyUpdate{}, ctx.Err()
		}}
		c := testLeaseController(t, client)
		c.publicRunPrepared = c.installedPublicPolicy
		now := time.Now()
		if err := c.setLease(testIngressLease(now)); err != nil {
			t.Fatal(err)
		}
		event := publicPolicyEvent(now, 1, 1, "pool.example", true)
		if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{event}}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- c.publicPolicyLoop(ctx) }()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		<-started
		cancel()
		<-canceled
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("preparation owner returned before request cleanup joined")
		default:
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if len(c.publicPolicies) != 0 {
			t.Fatal("canceled installation published prepared state")
		}
	})
}

func TestPublicPolicyLateResponseCannotInstall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := publicPolicyTestClient{read: func(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
			// a late backend response cannot restart preparation authority.
			time.Sleep(2 * time.Second)
			return publicPolicyWire(body, "pool.example", time.Now()), nil
		}}
		c := testLeaseController(t, client)
		now := time.Now()
		run, err := c.preparePublicPolicy(t.Context(), publicPolicyEvent(now, 1, 1, "pool.example", true).Entry, testIngressLease(now))
		if run != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("late response installed a policy", err)
		}
	})
}

func TestPublicPolicyStaleProcessImmediatelyFencesController(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"direct", serviceapi.NewProblemError(409, "ingress_lease_stale", "ingress lease is stale")},
		{"HTTP", ingressHTTPProblem(409, &ingressv1.Problem{Status: 409, Type: failureproblem.URL("ingress_lease_stale"), Code: ingressv1.IngressLeaseStale})},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := publicPolicyTestClient{read: func(context.Context, string, ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
				return controlv1.VisitorPolicyUpdate{}, test.err
			}}
			c := testLeaseController(t, client)
			now := time.Now()
			owner := testIngressLease(now)
			if err := c.setLease(owner); err != nil {
				t.Fatal(err)
			}
			run, err := c.preparePublicPolicy(t.Context(), publicPolicyEvent(now, 1, 1, "pool.example", true).Entry, owner)
			if run != nil || !errors.Is(err, ErrIngressLeaseLost) || c.Lease().IngressLeaseRevision != 0 || c.Ready(now) {
				t.Fatal("explicit stale-process result retained serving authority", err)
			}
		})
	}
}

func TestPublicPolicySurvivesControlRetryOnlyUntilInstalledDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		owner := testIngressLease(now)
		event := publicPolicyEvent(now, 1, 1, "pool.example", true)
		outage := make(chan struct{})
		var unavailable atomic.Bool
		client := publicPolicyTestClient{ControlClient: leaseTestClient{
			register: func(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
				if unavailable.Load() {
					return ingressv1.IngressLease{}, errors.New("control unavailable")
				}
				return owner, nil
			},
			renew: func(context.Context) (ingressv1.IngressLease, error) {
				if unavailable.Load() {
					return ingressv1.IngressLease{}, errors.New("control unavailable")
				}
				return owner, nil
			},
			snapshot: func(context.Context) (ingressv1.IngressRoutingTableSnapshot, error) {
				return ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{event}}, nil
			},
			events: func(ctx context.Context) (ingressv1.IngressRoutingTablePage, error) {
				select {
				case <-outage:
					return ingressv1.IngressRoutingTablePage{}, errors.New("control unavailable")
				case <-ctx.Done():
					return ingressv1.IngressRoutingTablePage{}, ctx.Err()
				}
			},
		}, read: func(context.Context, string, ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
			if unavailable.Load() {
				return controlv1.VisitorPolicyUpdate{}, errors.New("control unavailable")
			}
			return publicPolicyWire(ingressv1.IngressVisitorPolicyRequest{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: event.PublicUrlId}}, "pool.example", time.Now()), nil
		}}
		c, err := NewController(ControllerConfig{Client: client, RoutingTable: new(RoutingTable),
			Registration:    ingressv1.IngressRegistration{IngressId: owner.IngressId, IngressRunId: owner.IngressRunId, ProtocolVersion: 1, ConnectionCapacity: 10},
			RenewalInterval: time.Hour, RetryInterval: 100 * time.Millisecond, RoutingWait: time.Second, Report: func(error) {}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		stop := sync.OnceFunc(func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
		defer stop()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if _, ok := c.Lookup("pool.example", time.Now()); !ok {
			t.Fatal("initial run did not install policy")
		}
		unavailable.Store(true)
		close(outage)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		if _, ok := c.Lookup("pool.example", time.Now()); !ok {
			t.Fatal("control retry discarded still-current installed permission")
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if _, ok := c.Lookup("pool.example", time.Now()); ok {
			t.Fatal("control retry extended the installed policy deadline")
		}
	})
}
