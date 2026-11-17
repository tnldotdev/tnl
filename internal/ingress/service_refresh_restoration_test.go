package ingress

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type restorationRefreshCall struct {
	started, deadline time.Time
	id                string
	lease             ingressv1.IngressLeaseIdentity
	runs              int
}

type restorationRefreshControl struct {
	PublicServiceControl
	mu     sync.Mutex
	calls  []restorationRefreshCall
	active int
	read   func(context.Context, string, ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error)
}

func (c *restorationRefreshControl) ReadIngressServices(ctx context.Context, id string, lease ingressv1.IngressLeaseIdentity) (snapshot ingressv1.IngressServices, err error) {
	deadline, _ := ctx.Deadline()
	c.mu.Lock()
	index := len(c.calls)
	c.calls = append(c.calls, restorationRefreshCall{started: time.Now(), deadline: deadline, id: id, lease: lease})
	c.active++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.active--
		c.calls[index].runs = len(snapshot.Runs)
		c.mu.Unlock()
	}()
	return c.read(ctx, id, lease)
}

func (c *restorationRefreshControl) state() ([]restorationRefreshCall, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls), c.active
}

type restorationRefreshWorker struct {
	control *restorationRefreshControl
	cancel  context.CancelFunc
	joined  chan struct{}
	result  error
}

func restorationStartRefresh(t *testing.T, f *restorationServiceFixture, read func(context.Context, string, ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error)) *restorationRefreshWorker {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	worker := &restorationRefreshWorker{
		control: &restorationRefreshControl{PublicServiceControl: f.server.config.Control, read: read},
		cancel:  cancel, joined: make(chan struct{}),
	}
	f.server.config.Control = worker.control
	go func() {
		defer close(worker.joined)
		worker.result = f.server.RefreshServices(ctx)
	}()
	return worker
}

func (w *restorationRefreshWorker) stop(t *testing.T) {
	t.Helper()
	w.cancel()
	synctest.Wait()
	restorationRequireClosed(t, w.joined, "RefreshServices cleanup")
	_, active := w.control.state()
	if active != 0 || w.result != nil && !errors.Is(w.result, ErrIngressLeaseLost) {
		t.Error("refresh left an active read or lost shutdown classification", active, w.result)
	}
}

func restorationFreshSnapshot(t *testing.T, f *restorationServiceFixture) ingressv1.IngressServices {
	t.Helper()
	snapshot := restorationCloneSnapshot(t, f.snapshot)
	snapshot.ObservedAt, snapshot.ValidUntil = time.Now(), time.Now().Add(visitortoken.PolicyLifetime)
	lease := f.lease.current()
	for index := range snapshot.Runs {
		run := &snapshot.Runs[index]
		run.ValidUntil = snapshot.ValidUntil
		restorationDelegate(t, lease, run, snapshot.ObservedAt, privateMinTime(snapshot.ValidUntil, lease.ServingUntil))
	}
	return snapshot
}

func TestServiceRefreshRestorationShortLeasesKeepSigningThenFenceOutage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// preserve the old fractional-second boundary: a two-second process
		// lease initially leaves only 1.25 seconds of whole-second delegation.
		restorationAdvance(time.Until(time.Now().Truncate(time.Second).Add(750 * time.Millisecond)))
		f := restorationService(t)
		defer f.server.Close()
		lease := f.lease.current()
		lease.ServingUntil = time.Now().Add(2 * time.Second)
		f.lease.set(lease)
		var failed atomic.Bool
		worker := restorationStartRefresh(t, f, func(context.Context, string, ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
			if failed.Load() {
				return ingressv1.IngressServices{}, errors.New("control unavailable")
			}
			return restorationFreshSnapshot(t, f), nil
		})
		defer worker.stop(t)
		synctest.Wait()
		renewLease := func() {
			current := f.lease.current()
			current.ServingUntil = time.Now().Add(2 * time.Second)
			f.lease.set(current)
		}
		// process leases renew every 500 ms. RefreshServices retains its current
		// normal one-second cap; no faster production timer is introduced.
		for step := range 100 {
			if step%5 == 0 {
				renewLease()
			}
			restorationSignSource(t, f)
			restorationAdvance(100 * time.Millisecond)
		}
		calls, _ := worker.control.state()
		if len(calls) < 8 {
			t.Fatal("healthy short delegations did not refresh at least eight times", len(calls))
		}
		route := f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())[0]
		expires := route.until
		var stopped atomic.Int32
		release, err := f.server.services.bind(route, netip.MustParseAddr("192.0.2.4"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		failed.Store(true)
		before := len(calls)
		expiredSteps := 0
		for step := range 40 {
			if step%5 == 0 {
				renewLease()
			}
			restorationAdvance(100 * time.Millisecond)
			if !time.Now().Before(expires) {
				expiredSteps++
				if len(f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())) != 0 {
					t.Fatal("failed refresh retained expired installed signing authority")
				}
				restorationRejectSource(t, f)
			} else {
				restorationSignSource(t, f)
			}
		}
		calls, active := worker.control.state()
		if retries := len(calls) - before; retries < 1 || retries > 4 {
			t.Error("four-second outage escaped the original one-to-four retry bound", retries)
		}
		if expiredSteps == 0 || stopped.Load() != 1 || active != 0 {
			t.Error("outage did not fence and join the expired serving authority", expiredSteps, stopped.Load(), active)
		}
	})
}

func TestServiceRefreshRestorationCancellationJoinsBlockedRead(t *testing.T) {
	for _, phase := range []string{"initial", "refresh"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := restorationService(t)
				defer f.server.Close()
				entered, canceled, cleanup := make(chan struct{}), make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(cleanup) })
				reads := 0
				worker := restorationStartRefresh(t, f, func(ctx context.Context, id string, identity ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
					reads++
					current := f.lease.current()
					if id != current.IngressId || identity.IngressRunId != current.IngressRunId || identity.IngressLeaseRevision != current.IngressLeaseRevision {
						t.Error("refresh changed the current process identity")
					}
					if phase == "refresh" && reads == 1 {
						return restorationFreshSnapshot(t, f), nil
					}
					close(entered)
					<-ctx.Done()
					close(canceled)
					<-cleanup
					return restorationFreshSnapshot(t, f), nil
				})
				defer func() { unblock(); worker.stop(t) }()
				synctest.Wait()
				if phase == "refresh" {
					restorationSignSource(t, f)
					restorationAdvance(time.Second)
				}
				restorationRequireClosed(t, entered, "blocked snapshot read")
				calls, active := worker.control.state()
				last := calls[len(calls)-1]
				if active != 1 || !last.deadline.Equal(last.started.Add(2*time.Second)) {
					t.Fatal("refresh changed its fixed two-second request cap", active, last.deadline.Sub(last.started))
				}
				worker.cancel()
				synctest.Wait()
				restorationRequireClosed(t, canceled, "snapshot request cancellation")
				select {
				case <-worker.joined:
					t.Fatal("RefreshServices returned before canceled read cleanup joined")
				default:
				}
				unblock()
				synctest.Wait()
				restorationRequireClosed(t, worker.joined, "joined canceled snapshot read")
				if f.server.RoutingReady(time.Now()) ||
					len(f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())) != 0 {
					t.Fatal("late success during canceled cleanup installed routing authority")
				}
				restorationRejectSource(t, f)
			})
		})
	}
}

func TestServiceRefreshRestorationBlockedReadCannotHideProcessExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := restorationService(t)
		defer f.server.Close()
		lease := f.lease.current()
		lease.ServingUntil = time.Now().Add(50 * time.Millisecond)
		f.lease.set(lease)
		if err := f.server.services.apply(time.Now(), lease, f.snapshot); err != nil {
			t.Fatal(err)
		}
		route := f.server.services.lookup("route.example", 443, lease, time.Now())[0]
		stopped := make(chan struct{})
		release, err := f.server.services.bind(route, netip.MustParseAddr("192.0.2.4"), func() { close(stopped) })
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		entered, cleanup := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(cleanup) })
		worker := restorationStartRefresh(t, f, func(ctx context.Context, _ string, _ ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
			close(entered)
			<-ctx.Done()
			<-cleanup
			return f.snapshot, nil
		})
		defer func() { unblock(); worker.stop(t) }()
		synctest.Wait()
		restorationRequireClosed(t, entered, "blocked process snapshot")
		restorationAdvance(50 * time.Millisecond)
		restorationRequireClosed(t, stopped, "visitor expiry during blocked read")
		if f.server.RoutingReady(time.Now()) || len(f.server.services.lookup("route.example", 443, lease, time.Now())) != 0 {
			t.Fatal("blocked refresh hid the original process lease expiry")
		}
		calls, active := worker.control.state()
		if len(calls) != 1 || active != 1 {
			t.Fatal("fixture did not retain the one actual blocked read through expiry")
		}
	})
}

func TestServiceRefreshRestorationRejectsLateSuccessAndReplacedProcess(t *testing.T) {
	for _, mode := range []string{"timeout", "replaced_process"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := restorationService(t)
				defer f.server.Close()
				entered, finish := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(finish) })
				var reportMu sync.Mutex
				var reports []error
				f.server.config.OnError = func(err error) {
					reportMu.Lock()
					reports = append(reports, err)
					reportMu.Unlock()
				}
				worker := restorationStartRefresh(t, f, func(context.Context, string, ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
					close(entered)
					<-finish
					return f.snapshot, nil
				})
				defer func() { unblock(); worker.stop(t) }()
				synctest.Wait()
				restorationRequireClosed(t, entered, "snapshot response gate")
				if mode == "timeout" {
					restorationAdvance(2 * time.Second)
				} else {
					lease := f.lease.current()
					lease.IngressLeaseRevision++
					lease.IngressRunId = publicServiceTestID(t, "ir_")
					f.lease.set(lease)
				}
				unblock()
				synctest.Wait()
				if f.server.RoutingReady(time.Now()) {
					t.Fatal("late or replaced-process response installed serving state")
				}
				f.server.services.mu.Lock()
				installed := len(f.server.services.runs)
				f.server.services.mu.Unlock()
				if installed != 0 {
					t.Fatal("stale response retained a route owner")
				}
				reportMu.Lock()
				defer reportMu.Unlock()
				if mode == "timeout" && (len(reports) != 1 || !errors.Is(reports[0], context.DeadlineExceeded)) {
					t.Error("late successful refresh lost timeout classification", reports)
				}
			})
		})
	}
}

type restorationHTTPDoer func(*http.Request) (*http.Response, error)

func (f restorationHTTPDoer) Do(request *http.Request) (*http.Response, error) { return f(request) }

func TestServiceRefreshRestorationStaleProcessImmediatelyFencesServing(t *testing.T) {
	for _, transport := range []string{"direct", "http_409"} {
		t.Run(transport, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := restorationService(t)
				defer f.server.Close()
				generated, err := ingressv1.NewClientWithResponses("https://control.example", ingressv1.WithHTTPClient(restorationHTTPDoer(func(request *http.Request) (*http.Response, error) {
					if request.Method != http.MethodPost || request.URL.Path != "/internal/v1/ingresses/ingress-a/services" {
						t.Error("stale response did not use the current snapshot operation", request.Method, request.URL.Path)
					}
					return &http.Response{StatusCode: http.StatusConflict, Header: http.Header{"Content-Type": {"application/problem+json"}},
						Body: io.NopCloser(strings.NewReader(`{"type":"https://tnl.dev/problems/ingress_lease_stale","title":"ingress lease stale","code":"ingress_lease_stale","status":409,"detail":"process replaced","request_id":"source-restoration"}`))}, nil
				})))
				if err != nil {
					t.Fatal(err)
				}
				client, err := NewHTTPControlClient(generated)
				if err != nil {
					t.Fatal(err)
				}
				reads := 0
				worker := restorationStartRefresh(t, f, func(ctx context.Context, id string, lease ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
					reads++
					if reads == 1 {
						return restorationFreshSnapshot(t, f), nil
					}
					if transport == "http_409" {
						return client.ReadIngressServices(ctx, id, lease)
					}
					return ingressv1.IngressServices{}, ErrIngressLeaseLost
				})
				defer worker.stop(t)
				synctest.Wait()
				restorationSignSource(t, f)
				restorationAdvance(time.Second)
				if f.server.RoutingReady(time.Now()) ||
					len(f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())) != 0 {
					t.Error("explicit stale-process response retained installed serving authority")
				}
				restorationRejectSource(t, f)
			})
		})
	}
}

func TestServiceRefreshRestorationTransientErrorsCannotExtendInstalledDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := restorationService(t)
		defer f.server.Close()
		reads := 0
		worker := restorationStartRefresh(t, f, func(context.Context, string, ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
			reads++
			if reads == 1 {
				return restorationFreshSnapshot(t, f), nil
			}
			return ingressv1.IngressServices{}, errors.New("temporary snapshot outage")
		})
		defer worker.stop(t)
		synctest.Wait()
		route := f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())[0]
		original := route.until
		var stopped atomic.Int32
		release, err := f.server.services.bind(route, netip.MustParseAddr("192.0.2.4"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		restorationAdvance(200 * time.Millisecond)
		restorationSignSource(t, f)
		restorationAdvance(time.Second)
		restorationSignSource(t, f)
		current := f.lease.current()
		current.ServingUntil = time.Now().Add(time.Minute)
		f.lease.set(current)
		restorationAdvance(time.Until(original))
		if stopped.Load() != 1 || len(f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())) != 0 {
			t.Fatal("transient refresh or renewed process lease extended the original ten-second authority")
		}
		restorationRejectSource(t, f)
		calls, active := worker.control.state()
		if len(calls) < 2 || active != 0 {
			t.Fatal("actual refresh outage was not exercised")
		}
	})
}

func TestServiceRefreshRestorationClockTranslationSpendsRequestDelay(t *testing.T) {
	for _, offset := range []time.Duration{0, -3 * time.Hour, 3 * time.Hour} {
		t.Run(offset.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := restorationService(t)
				defer f.server.Close()
				started := time.Now()
				controlNow := started.Add(time.Hour - offset)
				snapshot := restorationCloneSnapshot(t, f.snapshot)
				snapshot.ObservedAt, snapshot.ValidUntil = controlNow, controlNow.Add(visitortoken.PolicyLifetime)
				run := &snapshot.Runs[0]
				run.ValidUntil = snapshot.ValidUntil
				for index := range run.ConnectedRelays {
					run.ConnectedRelays[index].ServingUntil = controlNow.Add(time.Minute)
				}
				restorationDelegate(t, f.lease.current(), run, controlNow, snapshot.ValidUntil)
				entered, finish := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(finish) })
				reads := 0
				worker := restorationStartRefresh(t, f, func(context.Context, string, ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
					reads++
					if reads != 1 {
						return ingressv1.IngressServices{}, errors.New("clock-skew snapshot outage")
					}
					close(entered)
					<-finish
					return snapshot, nil
				})
				defer func() { unblock(); worker.stop(t) }()
				synctest.Wait()
				restorationRequireClosed(t, entered, "clock-skew response gate")
				restorationAdvance(time.Second)
				unblock()
				synctest.Wait()
				routes := f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())
				if len(routes) != 1 || !routes[0].until.Equal(started.Add(visitortoken.PolicyLifetime)) ||
					!f.server.RoutingObservedAt().Equal(controlNow) || !routes[0].authorityTime(time.Now()).Equal(controlNow.Add(time.Second)) {
					t.Fatal("snapshot translation extended the request-start budget or lost control time")
				}
				restorationAdvance(visitortoken.PolicyLifetime - time.Second)
				if len(f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())) != 0 {
					t.Fatal("clock translation allowed serving beyond the original ten-second observation")
				}
			})
		})
	}
}

func restorationLargeSnapshot(t *testing.T, f *restorationServiceFixture, count int) ingressv1.IngressServices {
	t.Helper()
	snapshot := ingressv1.IngressServices{ObservedAt: time.Now(), ValidUntil: time.Now().Add(visitortoken.PolicyLifetime)}
	for index := range count {
		run := f.snapshot.Runs[0]
		run.ServiceRunId, run.RunNumber = publicServiceTestID(t, "srun_"), int64(index+1)
		run.ConnectedRelays = slices.Clone(run.ConnectedRelays)
		run.ValidUntil = snapshot.ValidUntil
		restorationDelegate(t, f.lease.current(), &run, snapshot.ObservedAt, snapshot.ValidUntil)
		snapshot.Runs = append(snapshot.Runs, run)
	}
	return snapshot
}

func TestServiceRefreshRestorationFullSnapshotsKeep2001RunTailCurrent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := restorationService(t)
		defer f.server.Close()
		initial := restorationLargeSnapshot(t, f, 2001)
		var changed ingressv1.IngressServices
		entered, finish := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(finish) })
		reads := 0
		worker := restorationStartRefresh(t, f, func(context.Context, string, ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
			reads++
			if reads == 1 {
				return initial, nil
			}
			if reads == 2 {
				close(entered)
				<-finish
			}
			snapshot := restorationCloneSnapshot(t, changed)
			snapshot.ObservedAt, snapshot.ValidUntil = time.Now(), time.Now().Add(visitortoken.PolicyLifetime)
			for index := range snapshot.Runs {
				snapshot.Runs[index].ValidUntil = snapshot.ValidUntil
			}
			return snapshot, nil
		})
		defer func() { unblock(); worker.stop(t) }()
		synctest.Wait()
		routes := f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())
		if len(routes) != 2001 {
			t.Fatal("initial full snapshot lost its tail", len(routes))
		}
		deadlines := make(map[string]time.Time, 2001)
		for _, route := range routes {
			deadlines[route.run.ServiceRunId] = route.until
		}
		restorationAdvance(2 * time.Second)
		restorationRequireClosed(t, entered, "large churn snapshot read")
		if len(f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())) != 2001 {
			t.Fatal("blocked full-snapshot read hid healthy installed siblings")
		}
		restorationSignSource(t, f)
		blockedCalls, blocked := worker.control.state()
		if len(blockedCalls) != 2 || blocked != 1 {
			t.Fatal("visitor work refreshed control or lost the blocked background read")
		}
		changed = restorationCloneSnapshot(t, initial)
		// removed, expired, and withdrawn rows are omissions in the current full
		// snapshot, not legacy page events. replace the next run and add a tail.
		changed.Runs = changed.Runs[3:]
		oldReplacement := changed.Runs[0].ServiceRunId
		changed.ObservedAt, changed.ValidUntil = time.Now(), time.Now().Add(visitortoken.PolicyLifetime)
		changed.Runs[0].ServiceRunId, changed.Runs[0].RunNumber = publicServiceTestID(t, "srun_"), 2002
		changed.Runs[0].ValidUntil = changed.ValidUntil
		restorationDelegate(t, f.lease.current(), &changed.Runs[0], changed.ObservedAt, changed.ValidUntil)
		tail := f.snapshot.Runs[0]
		tail.ServiceRunId, tail.RunNumber, tail.Hostname = publicServiceTestID(t, "srun_"), 2003, "tail.example"
		tail.ValidUntil = changed.ValidUntil
		restorationDelegate(t, f.lease.current(), &tail, changed.ObservedAt, changed.ValidUntil)
		changed.Runs = append(changed.Runs, tail)
		unblock()
		synctest.Wait()
		f.server.services.mu.Lock()
		for _, omitted := range append(initial.Runs[:3:3], initial.Runs[3]) {
			if f.server.services.runs[omitted.ServiceRunId] != nil {
				t.Error("large snapshot retained an omitted or replaced run")
			}
		}
		for id, route := range f.server.services.runs {
			if original, unchanged := deadlines[id]; unchanged && route.until.After(original) {
				t.Error("churn refreshed an unchanged delegation beyond its original deadline")
			}
		}
		lastPresent := f.server.services.runs[initial.Runs[2000].ServiceRunId] != nil
		replaced := f.server.services.runs[oldReplacement] == nil
		f.server.services.mu.Unlock()
		if !lastPresent || !replaced || len(f.server.services.lookup("tail.example", 443, f.lease.current(), time.Now())) != 1 {
			t.Fatal("large snapshot starved its old or newly added tail")
		}
		before, _ := worker.control.state()
		for range 10 {
			if len(f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())) != 1998 {
				t.Fatal("churn lost healthy sibling runs")
			}
		}
		after, _ := worker.control.state()
		if len(before) != 2 || len(after) != 2 {
			t.Error("lookups started control work instead of using the full snapshot")
		}
		if len(before) == 2 && (before[0].runs != 2001 || before[1].runs != 1999 ||
			before[0].runs+before[1].runs > 2*2001) {
			t.Error("churn lost the full-snapshot row workload or exceeded twice the initial row count")
		}
		restorationAdvance(time.Second)
		after, _ = worker.control.state()
		if len(after) != 3 || len(f.server.services.lookup("tail.example", 443, f.lease.current(), time.Now())) != 1 {
			t.Error("large churn snapshot prevented subsequent periodic refresh")
		}
	})
}

func TestServiceRefreshRestorationAddsRunBeyond4096InstalledRuns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := restorationService(t)
		defer f.server.Close()
		initial := restorationLargeSnapshot(t, f, 4096)
		var expanded ingressv1.IngressServices
		entered, finish := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(finish) })
		reads := 0
		worker := restorationStartRefresh(t, f, func(context.Context, string, ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
			reads++
			if reads == 1 {
				return initial, nil
			}
			close(entered)
			<-finish
			return expanded, nil
		})
		defer func() { unblock(); worker.stop(t) }()
		synctest.Wait()
		if len(f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())) != 4096 {
			t.Fatal("fixture did not install all 4096 original runs")
		}
		restorationAdvance(time.Second)
		restorationRequireClosed(t, entered, "full replacement read")
		expanded = restorationCloneSnapshot(t, initial)
		expanded.ObservedAt, expanded.ValidUntil = time.Now(), time.Now().Add(visitortoken.PolicyLifetime)
		added := f.snapshot.Runs[0]
		added.ServiceRunId, added.RunNumber, added.Hostname = publicServiceTestID(t, "srun_"), 4097, "added.example"
		added.ValidUntil = expanded.ValidUntil
		restorationDelegate(t, f.lease.current(), &added, expanded.ObservedAt, expanded.ValidUntil)
		expanded.Runs = append(expanded.Runs, added)
		observation, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		unblock()
		synctest.Wait()
		if observation.Err() != nil || len(f.server.services.lookup("added.example", 443, f.lease.current(), time.Now())) != 1 ||
			len(f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())) != 4096 {
			t.Fatal("installed-run count prevented a new run from joining the full snapshot within the original 100ms observation bound")
		}
		calls, active := worker.control.state()
		if len(calls) != 2 || active != 0 {
			t.Error("full-snapshot installation invented per-run preparation or extra reads", len(calls), active)
		} else if calls[0].runs != 4096 || calls[1].runs != 4097 {
			t.Error("large installed-run workload was reduced at the read boundary")
		}
	})
}
