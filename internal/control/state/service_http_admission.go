package state

import (
	"context"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// AuthorizeServiceHTTPVisitor records the publisher's locally verified request
// permission. ingress alone acknowledges ordinary connection capacity.
func (d *Database) AuthorizeServiceHTTPVisitor(ctx context.Context, auth ServiceHTTPRun, visitor string, source netip.Addr, port int, now time.Time) (result ServiceVisitorValidity, retErr error) {
	if !auth.valid() || !opaqueid.Valid(visitor, opaqueid.VisitorConnectionPrefix) || !source.IsValid() || source.Zone() != "" || port != 443 {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize service HTTP visitor", &retErr)()
	if err = d.lockServiceHTTPRun(ctx, tx, auth, now); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	if _, err = d.serviceHTTPSourcePolicy(ctx, q, auth.Subject.ID, source); err != nil {
		return result, err
	}
	binding, err := q.ServiceHTTPTransportBinding(ctx, controlstatedb.ServiceHTTPTransportBindingParams{
		ServiceID: auth.Subject.ID, ServiceRunID: auth.RunID, RunNumber: auth.Number,
		VisitorConnectionID: visitor, SourceIp: source.Unmap(), DestinationPort: 443, Now: timestamptz(now),
	})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if !binding.ValidUntil.Time.After(now) {
		return result, ErrServiceAccess
	}
	until, err := q.AuthorizeServiceHTTPVisitor(ctx, controlstatedb.AuthorizeServiceHTTPVisitorParams{
		ServiceID: auth.Subject.ID, ServiceRunID: auth.RunID, RunNumber: auth.Number,
		VisitorConnectionID: visitor, SourceIp: source.Unmap(), Now: timestamptz(now), ValidUntil: binding.ValidUntil,
	})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	result = ServiceVisitorValidity{Allowed: true, Admitted: binding.Admitted, ValidUntil: until.Time}
	return result, tx.Commit(ctx)
}
