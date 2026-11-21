package certificates

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/control/certificates/acme"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func TestServiceClaimQueueKeepsEightWorkersAvailable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const workers = 8
		queue := NewServiceClaimQueue()
		var claims, remaining, inFlight, canceled atomic.Int32
		store := &certificateStoreStub{claim: func(context.Context) (controlstate.ACMEOrderWork, bool, error) {
			claims.Add(1)
			if remaining.Load() == 0 {
				return controlstate.ACMEOrderWork{}, false, nil
			}
			remaining.Add(-1)
			return controlstate.ACMEOrderWork{
				State: "pending", ChallengeMethod: "dns-01",
				Account: controlstate.ACMEAccount{AccountURL: "https://acme.example/account"},
			}, true, nil
		}}
		ctx, stop := context.WithCancel(t.Context())
		var group sync.WaitGroup
		defer func() {
			stop()
			group.Wait()
		}()
		for i := range workers {
			worker, err := NewServiceWorker(store, ServiceConfig{
				WorkerID: "worker-" + strconv.Itoa(i), Profile: "tlsserver",
				HTTPClient: http.DefaultClient, DNSChallenges: &dnsChallengesStub{},
				OperationTimeout: 200 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			worker.client = func(controlstate.ACMEAccount) (acmeAPI, error) {
				return &blockedServiceOrder{inFlight: &inFlight, canceled: &canceled}, nil
			}
			group.Go(func() {
				if err := worker.Run(ctx, queue); err != nil {
					t.Error(err)
				}
			})
		}

		time.Sleep(4*defaultIdleInterval + time.Millisecond)
		synctest.Wait()
		if got := claims.Load(); got != 5 {
			t.Fatalf("empty claims = %d, want 5 across all workers", got)
		}
		remaining.Store(workers)
		time.Sleep(defaultIdleInterval)
		synctest.Wait()
		if got := inFlight.Load(); got != workers {
			t.Fatalf("order calls started before any completed = %d, want %d", got, workers)
		}
		if got := claims.Load(); got != 5+workers {
			t.Fatalf("claims with all workers busy = %d, want %d", got, 5+workers)
		}
		stop()
		group.Wait()
		if got := canceled.Load(); got != workers {
			t.Fatalf("joined order calls = %d, want %d", got, workers)
		}
	})
}

func TestServiceClaimQueueBacksOffAfterErrorAndReturnsCanceledTurn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := NewServiceClaimQueue()
		var claims int
		ctx, stop := context.WithCancel(t.Context())
		store := &certificateStoreStub{claim: func(context.Context) (controlstate.ACMEOrderWork, bool, error) {
			claims++
			return controlstate.ACMEOrderWork{}, false, errors.New("unavailable")
		}}
		worker, err := NewServiceWorker(store, ServiceConfig{WorkerID: "worker", Profile: "tlsserver", HTTPClient: http.DefaultClient})
		if err != nil {
			t.Fatal(err)
		}
		var group sync.WaitGroup
		defer func() {
			stop()
			group.Wait()
		}()
		group.Go(func() {
			if err := worker.Run(ctx, queue); err != nil {
				t.Error(err)
			}
		})
		synctest.Wait()
		if claims != 1 {
			t.Fatalf("claims before the retry delay = %d, want 1", claims)
		}
		stop()
		group.Wait()

		started := time.Now()
		// a canceled worker must not consume the shared turn or erase its delay.
		if !queue.take(t.Context()) || time.Since(started) != defaultIdleInterval {
			t.Fatal("another worker could not take the turn after the original retry delay")
		}
	})
}

type blockedServiceOrder struct {
	acmeStub
	inFlight, canceled *atomic.Int32
}

func (a *blockedServiceOrder) NewOrder(ctx context.Context, _ []string, _ string) (acme.Order, error) {
	a.inFlight.Add(1)
	<-ctx.Done()
	a.canceled.Add(1)
	return acme.Order{}, ctx.Err()
}
