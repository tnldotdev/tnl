package state

import (
	"context"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// only positive permission and DNS observations survive a read. signing input,
// relay connections and decrypted service configurations stay in the transaction.
type ingressReadCache struct {
	sync.Mutex
	pools map[string]map[string]ingressReadObservation
	size  int
}

func (c *ingressReadCache) replace(pool string, runs map[string]ingressReadObservation) {
	const maxRuns = 16384
	c.Lock()
	defer c.Unlock()
	c.size -= len(c.pools[pool])
	delete(c.pools, pool)
	if len(runs) == 0 || len(runs) > maxRuns {
		return
	}
	if c.pools == nil || c.size+len(runs) > maxRuns {
		c.pools = make(map[string]map[string]ingressReadObservation)
		c.size = 0
	}
	c.pools[pool] = runs
	c.size += len(runs)
}

type ingressReadObservation struct {
	row       controlstatedb.ListIngressServiceRunsRow
	observed  time.Time
	global    int64
	revisions []int64
}

func (o ingressReadObservation) current(now time.Time, versions *[257]int64) bool {
	if o.row.RunID == "" || now.Before(o.observed) || o.global != versions[0] ||
		o.row.PermissionUntil.Valid && !now.Before(o.row.PermissionUntil.Time) ||
		o.row.RecheckAt.Valid && !now.Before(o.row.RecheckAt.Time) ||
		o.row.AliasDnsUntil.Valid && !now.Before(o.row.AliasDnsUntil.Time) {
		return false
	}
	for i, bucket := range o.row.Buckets {
		if o.revisions[i] != versions[1+bucket] {
			return false
		}
	}
	return true
}

func (d *Database) readIngressObservations(ctx context.Context, q *controlstatedb.Queries, pool string, live []controlstatedb.ListLiveIngressRunsRow, now time.Time) (map[string]ingressReadObservation, error) {
	rows, err := q.ListReadDependencyVersions(ctx, "ingress")
	if err != nil {
		return nil, err
	}
	var versions [257]int64
	for _, row := range rows {
		versions[1+row.Bucket] = row.Revision
	}
	d.ingressReads.Lock()
	previous := d.ingressReads.pools[pool]
	d.ingressReads.Unlock()
	current := make(map[string]ingressReadObservation, len(live))
	var dirty []string
	for _, run := range live {
		if old := previous[run.ID]; old.current(now, &versions) {
			current[run.ID] = old
		} else {
			dirty = append(dirty, run.ID)
		}
	}
	if len(dirty) > 0 {
		fresh, err := q.ListIngressServiceRuns(ctx, controlstatedb.ListIngressServiceRunsParams{RunIds: dirty, Now: timestamptz(now)})
		if err != nil {
			return nil, err
		}
		for _, row := range fresh {
			o := ingressReadObservation{row: row, observed: now, global: versions[0], revisions: make([]int64, len(row.Buckets))}
			for i, bucket := range row.Buckets {
				o.revisions[i] = versions[1+bucket]
			}
			current[row.RunID] = o
		}
	}
	return current, nil
}
