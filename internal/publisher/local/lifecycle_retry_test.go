package local

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestInvocationExhaustedCleanupCanExplicitlyRetryExactAllocation(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, f := invocationRuntime(t)
	transport := f.HTTP.Transport
	var unavailable atomic.Bool
	var attempts atomic.Int32
	var deleted sync.Map
	unavailable.Store(true)
	deleting := make(chan time.Time, 8)
	f.HTTP.Transport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/publisher/services/") {
			attempts.Add(1)
			deleted.Store(r.URL.Path, true)
			until, ok := r.Context().Deadline()
			if !ok {
				return nil, errors.New("allocation deletion needs a bounded context")
			}
			deleting <- until
			if unavailable.Load() {
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
		}
		return transport.RoundTrip(r)
	})
	defer func() { f.HTTP.Transport = transport }()
	var registration publisherprotocol.Registration
	if err := publisherprotocol.Call(t.Context(), endpoint, http.MethodPost, "/v1/publications/register", body, &registration); err != nil {
		t.Fatal(err)
	}
	waitInvocation(t, a, func(s publisherapp.Snapshot) bool {
		for _, service := range s.Services {
			if service.RegistrationID == registration.RegistrationID {
				return service.Routable
			}
		}
		return false
	})
	until := time.Now().UTC().Add(300 * time.Millisecond)
	request := registration
	request.ShutdownDeadline = &until
	if err := publisherprotocol.Call(t.Context(), endpoint, http.MethodPost, "/v1/unregister", request, nil); err == nil {
		t.Fatal("exhausted cleanup was reported as success")
	}
	if observed := <-deleting; !observed.Equal(until) {
		t.Fatal("automatic shutdown did not retain the exact caller deadline", observed, until)
	}
	if _, retained := a.manager.ServiceForRegistration(registration.RegistrationID); !retained {
		t.Fatal("failed cleanup lost its retryable allocation")
	}
	unavailable.Store(false)
	before := attempts.Load()
	retryUntil := time.Now().UTC().Add(2 * time.Second)
	request.ShutdownDeadline = &retryUntil
	if err := publisherprotocol.Call(t.Context(), endpoint, http.MethodPost, "/v1/unregister", request, nil); err != nil {
		t.Fatal("explicit cleanup retry could not reach recovered control", err)
	}
	if attempts.Load() != before+1 || f.Deletions.Load() != 1 || f.Allocations.Load() != 1 {
		t.Fatal("explicit retry failed to clean only the retained allocation", attempts.Load(), f.Deletions.Load(), f.Allocations.Load())
	}
	if observed := <-deleting; !observed.Equal(retryUntil) {
		t.Fatal("explicit retry did not use its separate bounded operation", observed, retryUntil)
	}
	if _, retained := a.manager.ServiceForRegistration(registration.RegistrationID); retained {
		t.Fatal("confirmed deletion retained registration ownership")
	}
	if !errors.Is(a.manager.RetirementError(), context.DeadlineExceeded) {
		t.Fatal("successful retry erased the original cleanup timeout", a.manager.RetirementError())
	}
	count := 0
	deleted.Range(func(_, _ any) bool { count++; return true })
	if count != 1 {
		t.Fatal("cleanup retry changed allocation identity")
	}
}

type initialHeartbeatFailure struct {
	publisherservice.RunControl
	first atomic.Bool
}

func (c *initialHeartbeatFailure) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	if c.first.CompareAndSwap(false, true) {
		return controlv1.ServiceRunState{}, failure.Wrap("heartbeat service run", failure.ServerUnavailable, errors.New("transient initial heartbeat failure"))
	}
	return c.RunControl.HeartbeatServiceRun(ctx, service, run, token, health)
}

func TestConfiguredServiceRunRetryLeavesLiveRegistrationShutdownUnstarted(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, f, _ := restoredConfiguredWorkers(t, config.Services{"web": {Public: new(false)}}, nil, nil)
	a.manager.Alive = func(pid int) bool { return pid == os.Getpid() }
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(target.Close)
	heartbeat := &initialHeartbeatFailure{}
	type attempt struct {
		number   int32
		shutdown context.Context
	}
	entered := make(chan attempt, 2)
	ready := make(chan struct{}, 1)
	var attempts atomic.Int32
	var lastStatus atomic.Pointer[publisherservice.RunStatus]
	var lastConnect [2]atomic.Pointer[error]
	a.AttachPublication = func(_ context.Context, _ publisherapp.Service, cfg *publisherservice.RunConfig) error {
		entered <- attempt{number: attempts.Add(1), shutdown: cfg.ShutdownContext}
		heartbeat.RunControl = cfg.Control
		cfg.Control = heartbeat
		cfg.HeartbeatInterval = 100 * time.Millisecond
		onStatus := cfg.ObserveReadiness
		cfg.ObserveReadiness = func(status publisherservice.RunStatus) {
			lastStatus.Store(&status)
			onStatus(status)
		}
		cfg.Connect = func(ctx context.Context, bound *publisherservice.Bound, slot uint8, options publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
			session, err := bound.ConnectSlot(ctx, slot, options)
			lastConnect[slot].Store(&err)
			return session, err
		}
		onReady := cfg.Ready
		cfg.Ready = func() error {
			if err := onReady(); err != nil {
				return err
			}
			ready <- struct{}{}
			return nil
		}
		return nil
	}
	registration := restoredRegisterApp(t, a, "web", target.URL, false)
	first := restoredWorkerReceive(t, entered, 3*time.Second)
	second := restoredWorkerReceive(t, entered, 3*time.Second)
	// readiness joins real TLS and both relay slots, not just entry into
	// the worker. keep the wait below the registration's initial lease.
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Errorf("replacement publisher never became ready: last status=%+v runs=%d", lastStatus.Load(), f.Runs.Load())
		for slot := range lastConnect {
			if err := lastConnect[slot].Load(); err != nil {
				t.Errorf("slot %d last connect: %v", slot, *err)
			}
		}
		t.FailNow()
	}
	if first.number != 1 || second.number != 2 || first.shutdown != second.shutdown || f.Runs.Load() != 2 {
		t.Fatal("fixture did not retire one failed run and serve its replacement", first.number, second.number, f.Runs.Load())
	}
	// keep the SDK lease live beyond the first attempt's natural shutdown cap.
	renew := time.NewTicker(time.Second)
	defer renew.Stop()
	bound := time.NewTimer(11 * time.Second)
	defer bound.Stop()
wait:
	for {
		select {
		case <-second.shutdown.Done():
			t.Fatal("ordinary run retirement expired the live registration's terminal fence", context.Cause(second.shutdown))
		case <-renew.C:
			if err := a.manager.RenewTarget(registration.RegistrationID, registration.Owner, registration.Target); err != nil {
				t.Fatal(err)
			}
		case <-bound.C:
			break wait
		}
	}
	snapshot, err := a.workers.Check(t.Context(), []string{"web"})
	if err != nil || len(snapshot.Services) != 1 || !snapshot.Services[0].Registered || !snapshot.Services[0].Routable || !snapshot.Services[0].Ready {
		t.Fatal("healthy replacement lost its real readiness/journal observation", snapshot.Services, err)
	}
	if a.manager.Sweep(a.manager.Alive) {
		t.Fatal("a readiness write asked the live app owner to exit")
	}
	if err := a.manager.UnregisterTarget(registration.RegistrationID, registration.Owner, registration.Target); err != nil {
		t.Fatal("terminal shutdown failed after the healthy retry", err)
	}
}
