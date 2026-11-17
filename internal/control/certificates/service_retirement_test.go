package certificates

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/control/certificates/acme"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func TestServiceWorkerRetiredIssuanceNeverResumesCAWork(t *testing.T) {
	for _, status := range []string{"pending", "ready", "processing"} {
		t.Run(status, func(t *testing.T) {
			now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
			api, work := dnsSafetyOrder(t, "canceled", now)
			work.FinalizationPossible = true
			api.order.Status = status
			store := &certificateStoreStub{work: work}
			dns := &dnsChallengesStub{}
			worker := &ServiceWorker{
				store: store, config: ServiceConfig{DNSChallenges: dns, PollInterval: time.Second},
				now:    func() time.Time { return now },
				client: func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil },
			}
			for range 3 {
				if found, err := worker.processOne(t.Context()); err != nil || !found {
					t.Fatal("recover retired issuance", found, err)
				}
				if store.saved.State != controlstate.ACMEOrderCanceled || !store.saved.FinalizationPossible ||
					!store.saved.AvailableAt.After(now) || store.saved.NotAfter != nil ||
					len(api.finalizations) != 0 || api.newOrderCalls != 0 || api.acceptCalls != 0 ||
					len(dns.presentCalls) != 0 || len(dns.cleanupCalls) != 0 {
					t.Fatal("uncertain retirement resumed issuance or discarded quarantine", store.saved.State, store.saved.AvailableAt)
				}
				store.work = store.saved
				now = store.saved.AvailableAt
			}
		})
	}
}

func TestServiceWorkerRetiredCleanupJoinsProviderBeforeReturning(t *testing.T) {
	for _, stop := range []string{"cancel", "deadline"} {
		t.Run(stop, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now()
				api, work := dnsSafetyOrder(t, "canceled", now)
				store := &certificateStoreStub{work: work}
				entered, stopped, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan error, 1)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				dns := &dnsChallengesStub{cleanup: func(ctx context.Context) error {
					if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(now.Add(10*time.Second)) {
						t.Error("cleanup lost its original operation deadline", deadline)
					}
					close(entered)
					<-ctx.Done()
					close(stopped)
					<-release
					return ctx.Err()
				}}
				worker, err := NewServiceWorker(store, ServiceConfig{
					WorkerID: "retired-cleanup", Profile: "tlsserver", HTTPClient: &http.Client{},
					DNSChallenges: dns, OperationTimeout: 10 * time.Second, LeaseDuration: time.Minute,
				})
				if err != nil {
					t.Fatal(err)
				}
				worker.client = func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil }
				go func() { joined <- worker.Run(ctx) }()
				<-entered
				if stop == "cancel" {
					cancel()
				} else {
					time.Sleep(10 * time.Second)
				}
				<-stopped
				synctest.Wait()
				select {
				case err := <-joined:
					t.Fatal("worker returned before the provider operation joined", err)
				default:
				}
				cancel()
				unblock()
				if err := <-joined; err != nil {
					t.Fatal(err)
				}
				if store.saves != 0 || api.newOrderCalls != 0 || len(api.orderURLs) != 0 ||
					api.acceptCalls != 0 || len(api.finalizations) != 0 || len(dns.presentCalls) != 0 {
					t.Fatal("cancellation completed cleanup or resumed issuance before provider completion")
				}
				store.work = work
				dns.cleanup = nil
				if found, err := worker.processOne(t.Context()); !found || err != nil {
					t.Fatal("retry durable cleanup", found, err)
				}
				if store.saved.State != controlstate.ACMEOrderCanceled ||
					store.saved.Authorizations[0].State != controlstate.ACMEAuthorizationComplete ||
					store.saved.Authorizations[0].CleanupCompletedAt == nil || len(dns.cleanupCalls) != 2 {
					t.Fatal("joined cancellation lost the original durable cleanup")
				}
			})
		})
	}
}

func TestServiceWorkerInFlightFinalizationJoinsOriginalDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		api, work := dnsSafetyOrder(t, "presented", now)
		work.State, api.order.Status = controlstate.ACMEOrderReadyToFinalize, "ready"
		store := &certificateStoreStub{work: work}
		dns := &dnsChallengesStub{}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		entered, stopped, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan error, 1)
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		client := &heldFinalizationACME{acmeAPI: api, finalize: func(ctx context.Context) (acme.Order, error) {
			if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(now.Add(10*time.Second)) {
				t.Error("in-flight finalization lost its original deadline", deadline)
			}
			close(entered)
			<-ctx.Done()
			close(stopped)
			<-release
			return acme.Order{}, ctx.Err()
		}}
		worker, err := NewServiceWorker(store, ServiceConfig{
			WorkerID: "held-finalization", Profile: "tlsserver", HTTPClient: &http.Client{},
			DNSChallenges: dns, OperationTimeout: 10 * time.Second, LeaseDuration: time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		worker.client = func(controlstate.ACMEAccount) (acmeAPI, error) { return client, nil }
		go func() { joined <- worker.Run(ctx) }()
		<-entered
		time.Sleep(10 * time.Second)
		<-stopped
		synctest.Wait()
		select {
		case err := <-joined:
			t.Fatal("worker detached an unfinished finalization", err)
		default:
		}
		cancel()
		unblock()
		if err := <-joined; err != nil {
			t.Fatal(err)
		}
		if store.saves != 0 || len(dns.cleanupCalls) != 0 || len(dns.presentCalls) != 0 ||
			api.newOrderCalls != 0 || api.acceptCalls != 0 || len(api.orderURLs) != 1 {
			t.Fatal("worker started more work or saved finalization before joining the provider")
		}
	})
}

type heldFinalizationACME struct {
	acmeAPI
	finalize func(context.Context) (acme.Order, error)
}

func (a *heldFinalizationACME) FinalizeOrder(ctx context.Context, _, _ string, _ []byte) (acme.Order, error) {
	return a.finalize(ctx)
}
