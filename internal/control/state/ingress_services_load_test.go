package state

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// qualify complete database snapshots through the same two control pools as
// lifecycle load tests. this does not qualify HTTP serialization, ingress
// installation, or visitor traffic; those remain runtime load boundaries.
func TestLoadIngressServiceSnapshots(t *testing.T) {
	f := newControlLoadFixture(t)
	sessions := readySteadyLoadSessions(t, f)
	expected := make(map[string]servicePublicationFixture, len(sessions))
	for _, session := range sessions {
		expected[session.run.RunID] = session
	}
	var ingresses [2]IngressLease
	for index := range ingresses {
		lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
			IngressID: fmt.Sprintf("snapshot-load-%d", index), IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
			ProtocolVersion: 1, HTTPS: true, IngressPoolID: PrimaryIngressPoolID,
			ConnectionCapacity: uint64(max(64, f.routes)),
		}, f.now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		ingresses[index] = lease
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	const rounds = 10
	durations := make([]time.Duration, rounds*len(ingresses))
	bytes := make([]int, len(durations))
	started := make(chan struct{})
	results := make(chan error, len(ingresses))
	var workers sync.WaitGroup
	f.startMetrics(t)
	defer f.logStats(t)
	for index, ingress := range ingresses {
		workers.Go(func() {
			<-started
			for round := range rounds {
				// the serving owner allows at most two seconds for a refresh.
				// never give a scale test a longer authority-installation budget.
				call, stop := context.WithTimeout(ctx, 2*time.Second)
				begin := time.Now()
				snapshot, err := f.controls[index].ReadIngressServices(call, ingress.IngressLeaseIdentity, f.now)
				elapsed := time.Since(begin)
				stop()
				if err != nil {
					results <- fmt.Errorf("ingress %d round %d snapshot: %w", index, round, err)
					return
				}
				if elapsed >= 2*time.Second || len(snapshot.Runs) != len(expected) {
					results <- fmt.Errorf("ingress %d round %d incomplete or late snapshot: runs=%d/%d elapsed=%s",
						index, round, len(snapshot.Runs), len(expected), elapsed)
					return
				}
				seen := make(map[string]bool, len(snapshot.Runs))
				for _, run := range snapshot.Runs {
					session, found := expected[run.RunID]
					if !found || seen[run.RunID] || run.ServiceID != session.service.ID || run.RunNumber != session.run.RunNumber ||
						run.Hostname != session.service.Endpoint.Hostname || run.Port != 443 || len(run.Relays) != 2 ||
						len(run.SourceKey) != 32 || len(run.SourceAuthority) == 0 {
						results <- fmt.Errorf("ingress %d round %d changed a service/run or delegated source scope", index, round)
						return
					}
					seen[run.RunID] = true
				}
				encoded, err := json.Marshal(snapshot)
				if err != nil {
					results <- err
					return
				}
				offset := index*rounds + round
				durations[offset], bytes[offset] = elapsed, len(encoded)
			}
			results <- nil
		})
	}
	close(started)
	defer workers.Wait()
	for range ingresses {
		if err := <-results; err != nil {
			cancel()
			t.Fatal(err)
		}
	}
	workers.Wait()
	slices.Sort(durations)
	var total time.Duration
	for _, elapsed := range durations {
		total += elapsed
	}
	t.Logf("complete_snapshots=%d services=%d controls=2 ingress_observers=2 mean=%s p95=%s max=%s max_json_bytes=%d",
		len(durations), len(expected), total/time.Duration(len(durations)),
		durations[(len(durations)*95-1)/100], durations[len(durations)-1], slices.Max(bytes))
	var visitors int
	if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.public_service_visitors`).Scan(&visitors); err != nil || visitors != 0 {
		t.Fatal("routing scale qualification wrote per-visitor coordination state", visitors, err)
	}
}
