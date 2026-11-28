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
var ErrServicePortInventoryMismatch = errors.New("configured service ports differ from the saved ingress pool; apply the change explicitly with tnld ingress-pool apply")
var ErrIngressPoolUnavailable = errors.New("ingress pool port policy has not been initialized")

// ReadIngressServicePorts returns durable allocation policy, not live capacity.
func (d *Database) ReadIngressServicePorts(ctx context.Context, pool string) (result []tcpport.Range, retErr error) {
	if err := d.requireOpen(); err != nil {
		return nil, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "read ingress pool port inventory", &retErr)()
	var configured bool
	if err := tx.QueryRow(ctx, `SELECT ports_configured FROM control.ingress_pools WHERE id=$1`, pool).Scan(&configured); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrIngressPoolInvalid
		}
		return nil, err
	}
	if !configured {
		return nil, ErrIngressPoolUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT first_port,last_port FROM control.ingress_service_port_ranges WHERE ingress_pool_id=$1 ORDER BY first_port`, pool)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result = []tcpport.Range{}
	for rows.Next() {
		var r tcpport.Range
		if err := rows.Scan(&r.First, &r.Last); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, tx.Commit(ctx)
}

// EnsureIngressServicePorts initializes a pool once. another control process
// cannot silently replace shared policy with a different startup configuration.
func (d *Database) EnsureIngressServicePorts(ctx context.Context, pool string, ranges []tcpport.Range) error {
	return d.configureIngressServicePorts(ctx, pool, ranges, false)
}

// ConfigureIngressServicePorts serializes with allocation. removing an active
// or quarantined port cannot silently strand a private or public client profile.
func (d *Database) ConfigureIngressServicePorts(ctx context.Context, pool string, ranges []tcpport.Range) (retErr error) {
	return d.configureIngressServicePorts(ctx, pool, ranges, true)
}

func (d *Database) configureIngressServicePorts(ctx context.Context, pool string, ranges []tcpport.Range, replace bool) (retErr error) {
	if pool == "" {
		return tcpport.ErrInventory
	}
	inventory, err := tcpport.NewInventory(ranges)
	if err != nil {
		return err
	}
	ranges = inventory.Ranges()
	first, last := make([]int32, len(ranges)), make([]int32, len(ranges))
	for i, r := range ranges {
		first[i], last[i] = int32(r.First), int32(r.Last)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "configure service port inventory", &retErr)()
	// previous serving binaries allocate under this guard. keep configuration
	// compatible with them; current allocators share the pool row below.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('managed-ports/'||$1,0))`, pool); err != nil {
		return err
	}
	var configured bool
	if err = tx.QueryRow(ctx, `SELECT ports_configured FROM control.ingress_pools WHERE id=$1 FOR UPDATE`, pool).Scan(&configured); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return tcpport.ErrInventory
		}
		return err
	}
	if configured && !replace {
		rows, err := tx.Query(ctx, `SELECT first_port,last_port FROM control.ingress_service_port_ranges WHERE ingress_pool_id=$1 ORDER BY first_port`, pool)
		if err != nil {
			return err
		}
		var saved []tcpport.Range
		for rows.Next() {
			var r tcpport.Range
			if err := rows.Scan(&r.First, &r.Last); err != nil {
				rows.Close()
				return err
			}
			saved = append(saved, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if !slices.Equal(saved, ranges) {
			return ErrServicePortInventoryMismatch
		}
		return tx.Commit(ctx)
	}
	var excluded bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_port_claims claim WHERE claim.ingress_pool_id=$1 AND claim.state<>'released' AND NOT EXISTS(SELECT 1 FROM unnest($2::int[],$3::int[]) inventory(first_port,last_port) WHERE claim.port BETWEEN inventory.first_port AND inventory.last_port))`, pool, first, last).Scan(&excluded); err != nil {
		return err
	}
	if excluded {
		return ErrServicePortsInUse
	}
	if _, err = tx.Exec(ctx, `DELETE FROM control.ingress_service_port_ranges WHERE ingress_pool_id=$1`, pool); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO control.ingress_service_port_ranges(ingress_pool_id,first_port,last_port) SELECT $1,first_port,last_port FROM unnest($2::int[],$3::int[]) inventory(first_port,last_port)`, pool, first, last); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.ingress_pools SET ports_configured=true WHERE id=$1`, pool); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
