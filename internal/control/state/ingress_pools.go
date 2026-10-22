package state

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	ingresspool "github.com/tnldotdev/tnl/internal/ingress/pool"
)

const PrimaryIngressPoolID = string(ingresspool.PrimaryID)

type IngressPoolState string

const (
	IngressPoolDisabled IngressPoolState = "disabled"
	IngressPoolEnabled  IngressPoolState = "enabled"
	IngressPoolDraining IngressPoolState = "draining"
)

// IngressPool identifies one public ingress address group shared by ingress processes.
type IngressPool struct {
	ID          string
	IPv4Address netip.Addr
	IPv6Address netip.Addr
	State       IngressPoolState
}

// EnsurePrimaryIngressPool pins the public HTTP ingress address.
func (d *Database) EnsurePrimaryIngressPool(ctx context.Context, ipv4, ipv6 string, now time.Time) (retErr error) {
	if now.IsZero() {
		return ErrPublicURLInvalid
	}
	parse := func(value string, ipv4 bool) (*netip.Addr, error) {
		if value == "" {
			return nil, nil
		}
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.Is4() != ipv4 {
			return nil, ErrPublicURLInvalid
		}
		return &address, nil
	}
	v4, err := parse(ipv4, true)
	if err != nil {
		return err
	}
	v6, err := parse(ipv6, false)
	if err != nil || v4 == nil && v6 == nil {
		return ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: provision ingress pool: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "provision ingress pool", &retErr)()
	queries := controlstatedb.New(tx)
	pool, err := queries.LockIngressPoolForProvision(ctx, PrimaryIngressPoolID)
	if err != nil {
		return fmt.Errorf("controlstate: lock ingress-a: %w", err)
	}
	if IngressPoolState(pool.State) == IngressPoolDisabled {
		if _, err := queries.EnableIngressPool(ctx, controlstatedb.EnableIngressPoolParams{
			ID: PrimaryIngressPoolID, Ipv4Address: v4, Ipv6Address: v6, UpdatedAt: timestamptz(now),
		}); err != nil {
			return fmt.Errorf("controlstate: enable ingress-a: %w", err)
		}
	} else if IngressPoolState(pool.State) != IngressPoolEnabled || !sameIngressAddress(pool.Ipv4Address, v4) || !sameIngressAddress(pool.Ipv6Address, v6) {
		return errors.New("controlstate: ingress-a address differs from the enabled pool")
	}
	return tx.Commit(ctx)
}

func sameIngressAddress(left, right *netip.Addr) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (d *Database) GetIngressPool(ctx context.Context, id string) (IngressPool, error) {
	if !validStateText(id) {
		return IngressPool{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return IngressPool{}, err
	}
	row, err := controlstatedb.New(d.pool).GetIngressPool(ctx, id)
	if err != nil {
		return IngressPool{}, fmt.Errorf("controlstate: read ingress pool: %w", err)
	}
	result := IngressPool{ID: row.ID, State: IngressPoolState(row.State)}
	if row.Ipv4Address != nil {
		result.IPv4Address = *row.Ipv4Address
	}
	if row.Ipv6Address != nil {
		result.IPv6Address = *row.Ipv6Address
	}
	return result, nil
}
