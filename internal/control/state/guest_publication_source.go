package state

import (
	"context"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

type publisherRequestSourceKey struct{}

// WithPublisherRequestSource carries the request peer observed by the control
// HTTP server. it grants no authority. guest run-token and publisher operations
// require it even if an earlier token exchange observed the same address.
// never populate it from a body, forwarded header, visitor source, or relay IP.
func WithPublisherRequestSource(ctx context.Context, source netip.Addr) context.Context {
	return context.WithValue(ctx, publisherRequestSourceKey{}, source)
}

func publisherRequestSource(ctx context.Context) netip.Addr {
	source, _ := ctx.Value(publisherRequestSourceKey{}).(netip.Addr)
	return source
}

// callers hold the trial before service/run locks. snapshot reads here never
// reverse that order, and the current clock is checked again after lock waits.
func (d *Database) guestServiceSource(ctx context.Context, q *controlstatedb.Queries, guest string, source netip.Addr, now time.Time) error {
	if guest == "" {
		return nil
	}
	if !source.IsValid() || source.Zone() != "" || source.Unmap().IsUnspecified() {
		return ErrPublisherIdentity
	}
	trial, err := q.GetGuestTrialByID(ctx, guest)
	if err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if !guestPublicationEligible(trial, now) {
		return ErrGuestTrialSpent
	}
	return d.guestSourceAddress(trial, source)
}

func (d *Database) guestSourceAddress(trial controlstatedb.ControlGuestTrial, source netip.Addr) error {
	if !source.IsValid() || source.Zone() != "" || source.Unmap().IsUnspecified() {
		return ErrPublisherIdentity
	}
	source = source.Unmap()
	match, err := d.GuestSourceMatches(guestTrialRecord(trial), netip.PrefixFrom(source, source.BitLen()).String())
	if err != nil {
		return err
	}
	if !match {
		return ErrPublisherIdentity
	}
	return nil
}
