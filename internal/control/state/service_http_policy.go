package state

import (
	"context"
	"errors"
	"net/netip"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// native transports retain the same applied IP restriction. HTTP publishers
// consume it from their prepared visitor policy, without a request-time RPC.
func (d *Database) serviceHTTPSourceAllowed(ctx context.Context, q *controlstatedb.Queries, service string, source netip.Addr) error {
	settings, err := d.serviceHTTPSettings(ctx, q, service)
	if err != nil {
		return err
	}
	if settings == nil || settings.Access == nil || len(settings.Access.IP) == 0 {
		return nil
	}
	for _, raw := range settings.Access.IP {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return ErrServiceAccess
		}
		if prefix.Contains(source.Unmap()) {
			return nil
		}
	}
	return ErrServiceAccess
}

func (d *Database) serviceHTTPSettings(ctx context.Context, q *controlstatedb.Queries, service string) (*config.HTTPService, error) {
	row, err := q.ServiceHTTPAppliedConfiguration(ctx, text(service))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c, err := d.openAppliedProject(controlstatedb.ControlAppliedProject{TeamID: row.TeamID, ProjectKey: row.ProjectKey, ConfigurationCiphertext: row.ConfigurationCiphertext, StorageKeyID: row.StorageKeyID})
	if err != nil {
		return nil, err
	}
	s, ok := c.Services[row.Service]
	if !ok {
		return nil, ErrServiceAccess
	}
	if err := config.ValidateGroupHTTP(s.HTTP); err != nil {
		return nil, errors.Join(ErrServiceAccess, err)
	}
	return s.HTTP, nil
}
