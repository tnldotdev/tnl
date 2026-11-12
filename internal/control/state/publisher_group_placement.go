package state

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// a group is placed once, with room for all its initial services. later apply
// operations must grow that pool rather than silently change saved endpoints.
func ensurePublisherGroupIngressPool(ctx context.Context, tx pgx.Tx, group string, services int, retained []string, pools []string) error {
	var assigned *string
	if err := tx.QueryRow(ctx, `SELECT ingress_pool_id FROM control.project_publisher_groups WHERE id=$1 FOR UPDATE`, group).Scan(&assigned); err != nil {
		return err
	}
	if assigned != nil {
		return nil
	}
	// a directly declared group can receive a retained service. inherit its
	// reservation's pool rather than making that service occupy an unclaimed port
	// in another pool; combining retained services from different pools is rejected.
	rows, err := tx.Query(ctx, `SELECT DISTINCT ingress_pool_id FROM control.service_port_claims WHERE service_id=ANY($1::text[]) AND state='held'`, retained)
	if err != nil {
		return err
	}
	held, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if len(held) > 1 {
		return ErrServicePoolPinned
	}
	requiredPool := ""
	if len(held) == 1 {
		requiredPool = held[0]
	}
	var pool string
	err = tx.QueryRow(ctx, `SELECT pool.id FROM control.ingress_pools pool
	    WHERE pool.id=ANY($1::text[]) AND (pool.state='enabled' OR (pool.id=$2 AND pool.state='disabled'))
	    AND ($4='' OR pool.id=$4)
	    AND (SELECT COALESCE(sum(last_port-first_port+1),0) FROM control.ingress_service_port_ranges WHERE ingress_pool_id=pool.id)
	      - (SELECT count(*) FROM control.service_port_claims WHERE ingress_pool_id=pool.id AND state<>'released') >= $3
	    ORDER BY (pool.id=$2) DESC,pool.id LIMIT 1`, pools, PrimaryIngressPoolID, services, requiredPool).Scan(&pool)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServicePortsExhausted
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.project_publisher_groups SET ingress_pool_id=$2 WHERE id=$1`, group, pool)
	return err
}
