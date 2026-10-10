package controlstate

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// IngressPool identifies one public ingress address group shared by ingress processes.
type IngressPool struct {
	ID          string
	IPv4Address netip.Addr
	IPv6Address netip.Addr
	State       string
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
	result := IngressPool{ID: row.ID, State: row.State}
	if row.Ipv4Address != nil {
		result.IPv4Address = *row.Ipv4Address
	}
	if row.Ipv6Address != nil {
		result.IPv6Address = *row.Ipv6Address
	}
	return result, nil
}
