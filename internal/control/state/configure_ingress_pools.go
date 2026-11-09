package state

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	ingresspool "github.com/tnldotdev/tnl/internal/ingress/pool"
)

var ErrIngressPoolPinned = errors.New("ingress pool address is pinned; add a new pool instead of changing its address")

// configure all pools atomically. omitted pools drain instead of losing the
// addresses, reservations and DNS authority still used by saved services.
func (d *Database) ConfigureIngressPools(ctx context.Context, pools []ingresspool.Configuration, now time.Time) (retErr error) {
	if err := ingresspool.ValidateConfigurations(pools); err != nil {
		return err
	}
	if now.IsZero() {
		return ingresspool.ErrConfiguration
	}
	pools = slices.Clone(pools)
	slices.SortFunc(pools, func(a, b ingresspool.Configuration) int { return strings.Compare(string(a.ID), string(b.ID)) })
	ids := make([]string, len(pools))
	for i, pool := range pools {
		ids[i] = string(pool.ID)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "configure ingress pools", &retErr)()
	if _, err := lockServicePortInventories(ctx, tx, ids); err != nil {
		return err
	}
	address := func(a netip.Addr) *netip.Addr {
		if !a.IsValid() {
			return nil
		}
		return &a
	}
	for _, pool := range pools {
		state := IngressPoolEnabled
		if pool.Draining {
			state = IngressPoolDraining
		}
		tag, err := tx.Exec(ctx, `INSERT INTO control.ingress_pools(id,ipv4_address,ipv6_address,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5)
		    ON CONFLICT(id) DO UPDATE SET ipv4_address=EXCLUDED.ipv4_address,ipv6_address=EXCLUDED.ipv6_address,state=EXCLUDED.state,updated_at=GREATEST(control.ingress_pools.updated_at,EXCLUDED.updated_at)
		    WHERE (control.ingress_pools.state='disabled' AND control.ingress_pools.ipv4_address IS NULL AND control.ingress_pools.ipv6_address IS NULL)
		       OR (control.ingress_pools.ipv4_address IS NOT DISTINCT FROM EXCLUDED.ipv4_address AND control.ingress_pools.ipv6_address IS NOT DISTINCT FROM EXCLUDED.ipv6_address)`, string(pool.ID), address(pool.IPv4Address), address(pool.IPv6Address), string(state), now)
		if err != nil {
			return fmt.Errorf("configure ingress pool %s: %w", pool.ID, err)
		}
		if tag.RowsAffected() != 1 {
			return ErrIngressPoolPinned
		}
		if err := configureIngressServicePorts(ctx, tx, string(pool.ID), pool.Ports); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE control.ingress_pools SET state='draining',updated_at=GREATEST(updated_at,$2) WHERE NOT(id=ANY($1::text[])) AND state='enabled'`, ids, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
