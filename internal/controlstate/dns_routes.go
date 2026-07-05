package controlstate

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var (
	ErrDNSRouteWorkStale = errors.New("controlstate: DNS route work lease is stale")
	ErrDNSRouteInvalid   = errors.New("controlstate: DNS route work is invalid")
)

type DNSRouteWork struct {
	RouteID               string
	DomainID              string
	DNSAuthorityReference string
	CanonicalHostname     string
	State                 RouteDNSState
	DNSRevision           uint64
	Attempts              uint64
	AvailableAt           time.Time
	LastError             string
	WorkerID              string
	WorkEpoch             uint64
	WorkExpiresAt         time.Time
}

func (d *Database) ClaimDNSRouteWork(
	ctx context.Context,
	workerID string,
	now time.Time,
	leaseDuration time.Duration,
) (DNSRouteWork, bool, error) {
	if !validStateText(workerID) || now.IsZero() || leaseDuration <= 0 {
		return DNSRouteWork{}, false, ErrDNSRouteInvalid
	}
	if err := d.requireOpen(); err != nil {
		return DNSRouteWork{}, false, err
	}
	row, err := controlstatedb.New(d.pool).ClaimDNSRouteWork(ctx, controlstatedb.ClaimDNSRouteWorkParams{
		WorkOwner: text(workerID), WorkExpiresAt: timestamptz(now.Add(leaseDuration)), ClaimedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DNSRouteWork{}, false, nil
	}
	if err != nil {
		return DNSRouteWork{}, false, fmt.Errorf("controlstate: claim DNS route work: %w", err)
	}
	work, err := dnsRouteWork(row, true)
	return work, err == nil, err
}

func (d *Database) SaveDNSRouteWork(ctx context.Context, work DNSRouteWork, now time.Time) (DNSRouteWork, error) {
	if err := validateDNSRouteWork(work); err != nil || now.IsZero() {
		return DNSRouteWork{}, ErrDNSRouteInvalid
	}
	if err := d.requireOpen(); err != nil {
		return DNSRouteWork{}, err
	}
	var availableAt *time.Time
	if !work.AvailableAt.IsZero() {
		availableAt = &work.AvailableAt
	}
	row, err := controlstatedb.New(d.pool).SaveDNSRouteWork(ctx, controlstatedb.SaveDNSRouteWorkParams{
		DnsState: string(work.State), DnsAvailableAt: nullableTime(availableAt), DnsLastError: nullableText(work.LastError),
		CompletedAt: timestamptz(now), RouteID: work.RouteID, WorkOwner: text(work.WorkerID),
		WorkEpoch: positive(work.WorkEpoch), ExpectedDnsRevision: positive(work.DNSRevision),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DNSRouteWork{}, ErrDNSRouteWorkStale
	}
	if err != nil {
		return DNSRouteWork{}, fmt.Errorf("controlstate: save DNS route work: %w", err)
	}
	return dnsRouteWork(row, false)
}

func dnsRouteWork(row controlstatedb.ControlRoute, requireLease bool) (DNSRouteWork, error) {
	state := RouteDNSState(row.DnsState)
	if row.DnsRevision <= 0 || row.DnsAttempts <= 0 ||
		(state == RouteDNSPending || state == RouteDNSRemoving) != row.DnsAvailableAt.Valid ||
		requireLease && (!row.DnsWorkOwner.Valid || row.DnsWorkEpoch <= 0 || !row.DnsWorkExpiresAt.Valid) {
		return DNSRouteWork{}, errors.New("controlstate: invalid DNS route work row")
	}
	return DNSRouteWork{
		RouteID: row.ID, DomainID: row.DomainID, DNSAuthorityReference: row.DnsAuthorityReference.String,
		CanonicalHostname: row.CanonicalHostname, State: state, DNSRevision: uint64(row.DnsRevision),
		Attempts: uint64(row.DnsAttempts), AvailableAt: row.DnsAvailableAt.Time, LastError: row.DnsLastError.String,
		WorkerID: row.DnsWorkOwner.String, WorkEpoch: uint64(row.DnsWorkEpoch), WorkExpiresAt: row.DnsWorkExpiresAt.Time,
	}, nil
}

func validateDNSRouteWork(work DNSRouteWork) error {
	canonical, err := naming.CanonicalizeHostname(work.CanonicalHostname)
	if !opaqueid.Valid(work.RouteID, "route_") || !validStateText(work.DomainID) || err != nil || canonical != work.CanonicalHostname ||
		work.DNSAuthorityReference != "" && !validStateText(work.DNSAuthorityReference) ||
		work.State != RouteDNSPending && work.State != RouteDNSPublished && work.State != RouteDNSRemoving &&
			work.State != RouteDNSRemoved && work.State != RouteDNSFailed ||
		work.DNSRevision == 0 || work.DNSRevision > math.MaxInt64 || work.Attempts == 0 || work.Attempts > math.MaxInt64 ||
		!validStateText(work.WorkerID) || work.WorkEpoch == 0 || work.WorkEpoch > math.MaxInt64 ||
		work.WorkExpiresAt.IsZero() || len(work.LastError) > 1024 ||
		(work.State == RouteDNSPending || work.State == RouteDNSRemoving) && work.AvailableAt.IsZero() {
		return ErrDNSRouteInvalid
	}
	return nil
}
