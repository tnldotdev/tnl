package daemon

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

type separatedPublisherActivationPlan struct {
	RequestedParallel int                                 `json:"requested_parallel"`
	EffectiveParallel int                                 `json:"effective_parallel"`
	Waves             int                                 `json:"waves"`
	Shards            []separatedPublisherActivationShard `json:"shards"`
}

type separatedPublisherActivationShard struct {
	Indexes  []int `json:"indexes"`
	Parallel int   `json:"parallel"`
	Waves    int   `json:"waves"`
}

// keep paired transports and their first-64 distribution in one activation plan.
func planSeparatedPublisherActivation(count, shards, parallel int) separatedPublisherActivationPlan {
	plan := separatedPublisherActivationPlan{RequestedParallel: parallel, Shards: make([]separatedPublisherActivationShard, shards)}
	active := 0
	for shard := range plan.Shards {
		for index := 2 * shard; index < count; index += 2 * shards {
			plan.Shards[shard].Indexes = append(plan.Shards[shard].Indexes, index)
			if index+1 < count {
				plan.Shards[shard].Indexes = append(plan.Shards[shard].Indexes, index+1)
			}
		}
		if len(plan.Shards[shard].Indexes) != 0 {
			active++
		}
	}
	// preserve the existing minimum of one slot per nonempty shard, even when
	// the requested limit is smaller. report that effective allocation explicitly.
	slots := min(count, max(parallel, active))
	for allocated := 0; allocated < slots; {
		for shard := range plan.Shards {
			activation := &plan.Shards[shard]
			if allocated < slots && activation.Parallel < len(activation.Indexes) {
				activation.Parallel++
				allocated++
			}
		}
	}
	for shard := range plan.Shards {
		activation := &plan.Shards[shard]
		if activation.Parallel == 0 {
			continue
		}
		activation.Waves = (len(activation.Indexes) + activation.Parallel - 1) / activation.Parallel
		plan.EffectiveParallel += activation.Parallel
		plan.Waves = max(plan.Waves, activation.Waves)
	}
	return plan
}

func (plan separatedPublisherActivationPlan) readinessTimeout(publisherTimeout time.Duration) time.Duration {
	return time.Duration(plan.Waves)*publisherTimeout + 10*time.Second
}

func TestSeparatedPublisherActivationPlan(t *testing.T) {
	for _, test := range []struct {
		count, parallel int
		wantParallel    []int
		wantWaves       int
	}{
		{4, 1, []int{1, 1, 0, 0}, 2},
		{4, 2, []int{1, 1, 0, 0}, 2},
		{4, 3, []int{2, 1, 0, 0}, 2},
		{4, 4, []int{2, 2, 0, 0}, 1},
		{4, 1000, []int{2, 2, 0, 0}, 1},
		{8, 1, []int{1, 1, 1, 1}, 2},
		{8, 3, []int{1, 1, 1, 1}, 2},
		{8, 4, []int{1, 1, 1, 1}, 2},
		{8, 5, []int{2, 1, 1, 1}, 2},
		{8, 8, []int{2, 2, 2, 2}, 1},
		{17, 1, []int{1, 1, 1, 1}, 5},
		{17, 4, []int{1, 1, 1, 1}, 5},
		{17, 5, []int{2, 1, 1, 1}, 4},
		{17, 6, []int{2, 2, 1, 1}, 4},
		{17, 8, []int{2, 2, 2, 2}, 3},
		{17, 9, []int{3, 2, 2, 2}, 2},
		{17, 16, []int{4, 4, 4, 4}, 2},
		{17, 1000, []int{5, 4, 4, 4}, 1},
		{3000, 1, []int{1, 1, 1, 1}, 750},
		{3000, 4, []int{1, 1, 1, 1}, 750},
		{3000, 5, []int{2, 1, 1, 1}, 750},
		{3000, 17, []int{5, 4, 4, 4}, 188},
		{3000, 64, []int{16, 16, 16, 16}, 47},
		{3000, 1000, []int{250, 250, 250, 250}, 3},
	} {
		t.Run(fmt.Sprintf("count=%d/parallel=%d", test.count, test.parallel), func(t *testing.T) {
			plan := planSeparatedPublisherActivation(test.count, 4, test.parallel)
			var parallel []int
			for _, shard := range plan.Shards {
				parallel = append(parallel, shard.Parallel)
			}
			if !slices.Equal(parallel, test.wantParallel) || plan.Waves != test.wantWaves {
				t.Fatalf("parallel=%v waves=%d, want parallel=%v waves=%d", parallel, plan.Waves, test.wantParallel, test.wantWaves)
			}
		})
	}
}

func TestSeparatedPublisherActivationDefaultReadinessBudget(t *testing.T) {
	plan := planSeparatedPublisherActivation(4, 4, 4)
	if plan.EffectiveParallel != 4 {
		t.Errorf("default activation uses %d startup slots, want 4", plan.EffectiveParallel)
	}
	if got := plan.readinessTimeout(30 * time.Second); got != 40*time.Second {
		t.Errorf("default readiness deadline = %s, want unchanged 40s", got)
	}
}

func TestSeparatedPublisherActivationSingleShard(t *testing.T) {
	plan := planSeparatedPublisherActivation(1, 1, 4)
	if plan.RequestedParallel != 4 || plan.EffectiveParallel != 1 || plan.Waves != 1 || len(plan.Shards) != 1 {
		t.Fatalf("single publisher activation: %+v", plan)
	}
	shard := plan.Shards[0]
	if !slices.Equal(shard.Indexes, []int{0}) || shard.Parallel != 1 || shard.Waves != 1 {
		t.Fatalf("single publisher shard: %+v", shard)
	}
}

func TestSeparatedPublisherActivationPlanPartitions(t *testing.T) {
	for _, test := range []struct {
		count int
		want  [][]int
	}{
		{4, [][]int{{0, 1}, {2, 3}, nil, nil}},
		{8, [][]int{{0, 1}, {2, 3}, {4, 5}, {6, 7}}},
		{17, [][]int{{0, 1, 8, 9, 16}, {2, 3, 10, 11}, {4, 5, 12, 13}, {6, 7, 14, 15}}},
	} {
		for _, parallel := range []int{1, 3, 4, 5, 64, 1000} {
			plan := planSeparatedPublisherActivation(test.count, 4, parallel)
			for shard, want := range test.want {
				if !slices.Equal(plan.Shards[shard].Indexes, want) {
					t.Fatalf("count=%d parallel=%d shard=%d indexes=%v, want %v", test.count, parallel, shard, plan.Shards[shard].Indexes, want)
				}
			}
		}
	}
}

func TestSeparatedPublisherActivationPlanLimits(t *testing.T) {
	for _, count := range []int{4, 8, 17, 3000} {
		for parallel := 1; parallel <= 1000; parallel++ {
			plan := planSeparatedPublisherActivation(count, 4, parallel)
			active, effective, waves := 0, 0, 0
			for shard, activation := range plan.Shards {
				if len(activation.Indexes) == 0 {
					if activation.Parallel != 0 || activation.Waves != 0 {
						t.Fatalf("count=%d parallel=%d inactive shard=%d has startup work: %+v", count, parallel, shard, activation)
					}
					continue
				}
				active++
				if activation.Parallel < 1 || activation.Parallel > len(activation.Indexes) {
					t.Fatalf("count=%d parallel=%d shard=%d invalid allocation: %+v", count, parallel, shard, activation)
				}
				wantWaves := (len(activation.Indexes) + activation.Parallel - 1) / activation.Parallel
				if activation.Waves != wantWaves {
					t.Fatalf("count=%d parallel=%d shard=%d waves=%d want %d", count, parallel, shard, activation.Waves, wantWaves)
				}
				effective += activation.Parallel
				waves = max(waves, wantWaves)
			}
			// low requested limits retain the existing one-slot-per-active-shard behavior.
			wantEffective := min(count, max(parallel, active))
			if plan.RequestedParallel != parallel || plan.EffectiveParallel != effective || effective != wantEffective || plan.Waves != waves {
				t.Fatalf("count=%d requested=%d effective=%d reported=%d want=%d waves=%d want=%d", count, parallel, effective, plan.EffectiveParallel, wantEffective, plan.Waves, waves)
			}
		}
	}
}
