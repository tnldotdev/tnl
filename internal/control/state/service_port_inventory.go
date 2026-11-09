package state

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

var ErrServicePortsInUse = errors.New("service port inventory excludes a held or quarantined port")
var ErrServicePortsExhausted = errors.New("ingress pool has no available service port")

// ConfigureIngressServicePorts serializes with allocation. removing an active
// or quarantined port cannot silently strand a private or public client profile.
func (d *Database) ConfigureIngressServicePorts(ctx context.Context, pool string, ranges []tcpport.Range) (retErr error) {
	if pool == "" {
		return tcpport.ErrInventory
	}
	inventory, err := tcpport.NewInventory(ranges)
	if err != nil {
		return err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "configure service port inventory", &retErr)()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('managed-ports/'||$1,0))`, pool); err != nil {
		return err
	}
	if err := configureIngressServicePorts(ctx, tx, pool, inventory); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func configureIngressServicePorts(ctx context.Context, tx pgx.Tx, pool string, inventory tcpport.Inventory) error {
	ranges := inventory.Ranges()
	first, last := make([]int32, len(ranges)), make([]int32, len(ranges))
	for i, r := range ranges {
		first[i], last[i] = int32(r.First), int32(r.Last)
	}
	var excluded bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_port_claims claim WHERE claim.ingress_pool_id=$1 AND claim.state<>'released' AND NOT EXISTS(SELECT 1 FROM unnest($2::int[],$3::int[]) inventory(first_port,last_port) WHERE claim.port BETWEEN inventory.first_port AND inventory.last_port))`, pool, first, last).Scan(&excluded); err != nil {
		return err
	}
	if excluded {
		return ErrServicePortsInUse
	}
	if _, err := tx.Exec(ctx, `DELETE FROM control.ingress_service_port_ranges WHERE ingress_pool_id=$1`, pool); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO control.ingress_service_port_ranges(ingress_pool_id,first_port,last_port) SELECT $1,first_port,last_port FROM unnest($2::int[],$3::int[]) inventory(first_port,last_port)`, pool, first, last); err != nil {
		return err
	}
	return nil
}

// multi-pool mutations take the same inventory locks as single-service
// allocation, in one order. a newly configured pool is eligible on the next
// mutation if it was not present when this snapshot was locked.
func lockServicePortInventories(ctx context.Context, tx pgx.Tx, extra []string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM control.ingress_pools ORDER BY id`)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	ids = append(ids, extra...)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('managed-ports/'||$1,0))`, id); err != nil {
			return nil, err
		}
	}
	return ids, nil
}
