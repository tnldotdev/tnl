package state

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func capacityFixture(t *testing.T, capacity int32) (publishRunFixture, ServiceRunState, []IngressLeaseIdentity) {
	t.Helper()
	f := newPublishRunFixture(t)
	run := privateClaimRun(t, f)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET stream_capacity=$2 WHERE id=$1`, run.RunID, capacity); err != nil {
		t.Fatal(err)
	}
	var owners []IngressLeaseIdentity
	for index := range 2 {
		lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{IngressID: fmt.Sprintf("capacity-%d", index), IngressRunID: fmt.Sprintf("process-%d", index), ProtocolVersion: 1, ConnectionCapacity: 10, IngressPoolID: PrimaryIngressPoolID}, f.now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		owners = append(owners, lease.IngressLeaseIdentity)
	}
	return f, run, owners
}

func capacityRequest(run ServiceRunState, owner IngressLeaseIdentity, key string, amount int32) StreamCapacityRequest {
	return StreamCapacityRequest{Owner: owner, Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}, RunID: run.RunID, RunNumber: run.RunNumber, RequestID: key, Capacity: amount}
}

func TestIntegrationStreamCapacityConcurrentOwnersCannotDoubleSpend(t *testing.T) {
	f, run, owners := capacityFixture(t, 4)
	var workers sync.WaitGroup
	var mu sync.Mutex
	var allocations []StreamCapacityAllocation
	for index := range 12 {
		workers.Go(func() {
			allocation, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[index%2], fmt.Sprintf("request-%d", index), 3), f.now)
			if err != nil && !errors.Is(err, ErrStreamCapacity) {
				t.Errorf("allocate: %v", err)
				return
			}
			if err == nil {
				mu.Lock()
				allocations = append(allocations, allocation)
				mu.Unlock()
			}
		})
	}
	workers.Wait()
	var granted int32
	for _, allocation := range allocations {
		granted += allocation.Capacity
	}
	if granted != 4 {
		t.Fatalf("delegated %d connections from a capacity-4 run", granted)
	}
}

func TestIntegrationStreamCapacityRetirementWaitsForGrantedDeadline(t *testing.T) {
	f, run, owners := capacityFixture(t, 2)
	request := capacityRequest(run, owners[0], "first", 2)
	first, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now.Add(time.Second))
	if err != nil || replayed.ID != first.ID || replayed.Capacity != 2 {
		t.Fatal("ambiguous allocation retry spent capacity twice", err)
	}
	if err := f.database.RetireStreamCapacity(t.Context(), owners[0], first.ID, f.now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[1], "replacement", 2), f.now.Add(3*time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("retired owner capacity was reissued while still usable", err)
	}
	if _, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now.Add(3*time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("retired allocation was renewed", err)
	}
	replacement, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[1], "replacement", 2), replayed.ValidUntil)
	if err != nil || replacement.ID == first.ID {
		t.Fatal("expired allocation identity was reused", err)
	}
	if err := f.database.RetireStreamCapacity(t.Context(), owners[0], replacement.ID, replayed.ValidUntil); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("stale owner released a replacement allocation", err)
	}
}

func TestIntegrationStreamCapacityReductionCannotRenewOversizedGrants(t *testing.T) {
	f, run, owners := capacityFixture(t, 2)
	request := capacityRequest(run, owners[0], "old", 2)
	first, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET stream_capacity=1 WHERE id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now.Add(time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("capacity reduction renewed an oversized allocation", err)
	}
	if _, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[1], "new", 1), f.now.Add(time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("capacity reduction double-spent a live allocation", err)
	}
	next, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[1], "new", 1), first.ValidUntil)
	if err != nil || next.Capacity != 1 {
		t.Fatal("reduced capacity did not become available after the old deadline", err)
	}
}

func TestIntegrationStreamCapacityRestartCannotReusePriorProcessGrant(t *testing.T) {
	f, run, owners := capacityFixture(t, 2)
	first, err := f.database.AllocateStreamCapacity(t.Context(), capacityRequest(run, owners[0], "old-process", 2), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.ingress_leases SET lease_expires_at=$2 WHERE ingress_id=$1`, owners[0].IngressID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	restarted, err := f.database.RegisterIngress(t.Context(), IngressRegistration{IngressID: owners[0].IngressID, IngressRunID: "replacement-process", ProtocolVersion: 1, ConnectionCapacity: 10, IngressPoolID: PrimaryIngressPoolID}, f.now.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.database.RetireStreamCapacity(t.Context(), owners[0], first.ID, f.now.Add(2*time.Second)); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("restarted ingress accepted the old process's release", err)
	}
	request := capacityRequest(run, restarted.IngressLeaseIdentity, "new-process", 2)
	if _, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now.Add(2*time.Second)); !errors.Is(err, ErrStreamCapacity) {
		t.Fatal("process replacement reissued capacity before its old deadline", err)
	}
	if _, err := f.database.AllocateStreamCapacity(t.Context(), request, first.ValidUntil); err != nil {
		t.Fatal("replacement process could not acquire expired capacity", err)
	}
}

func TestIntegrationStreamCapacityRejectsClosedRunAndDrainingIngress(t *testing.T) {
	for _, boundary := range []string{"run", "ingress"} {
		t.Run(boundary, func(t *testing.T) {
			f, run, owners := capacityFixture(t, 2)
			request := capacityRequest(run, owners[0], "first", 2)
			if _, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now); err != nil {
				t.Fatal(err)
			}
			if boundary == "run" {
				if err := f.database.CloseServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, f.now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.database.BeginIngressDrain(t.Context(), owners[0], f.now.Add(time.Second), f.now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.database.AllocateStreamCapacity(t.Context(), request, f.now.Add(2*time.Second)); !errors.Is(err, ErrStreamCapacity) {
				t.Fatal("closed run or draining ingress renewed capacity", err)
			}
		})
	}
}
