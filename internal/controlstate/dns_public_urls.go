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
	ErrDNSPublicURLWorkStale = errors.New("controlstate: DNS route work lease is stale")
	ErrDNSPublicURLInvalid   = errors.New("controlstate: DNS route work is invalid")
)

type DNSPublicURLWork struct {
	PublicURLID           string
	DomainID              string
	DNSAuthorityReference string
	CanonicalHostname     string
	Namespace             string
	PublicURLScope        PublicURLScope
	State                 PublicURLDNSState
	DNSRevision           uint64
	Attempts              uint64
	AvailableAt           time.Time
	LastError             string
	WorkerID              string
	WorkEpoch             uint64
	WorkExpiresAt         time.Time
}

func (d *Database) ClaimDNSPublicURLWork(
	ctx context.Context,
	workerID string,
	now time.Time,
	leaseDuration time.Duration,
) (DNSPublicURLWork, bool, error) {
	if !validStateText(workerID) || now.IsZero() || leaseDuration <= 0 {
		return DNSPublicURLWork{}, false, ErrDNSPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return DNSPublicURLWork{}, false, err
	}
	row, err := controlstatedb.New(d.pool).ClaimDNSPublicURLWork(ctx, controlstatedb.ClaimDNSPublicURLWorkParams{
		WorkOwner: text(workerID), WorkExpiresAt: timestamptz(now.Add(leaseDuration)), ClaimedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DNSPublicURLWork{}, false, nil
	}
	if err != nil {
		return DNSPublicURLWork{}, false, fmt.Errorf("controlstate: claim DNS route work: %w", err)
	}
	work, err := dnsRouteWork(row, true)
	return work, err == nil, err
}

func (d *Database) SaveDNSPublicURLWork(ctx context.Context, work DNSPublicURLWork, now time.Time) (DNSPublicURLWork, error) {
	if err := validateDNSPublicURLWork(work); err != nil || now.IsZero() {
		return DNSPublicURLWork{}, ErrDNSPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return DNSPublicURLWork{}, err
	}
	var availableAt *time.Time
	if !work.AvailableAt.IsZero() {
		availableAt = &work.AvailableAt
	}
	row, err := controlstatedb.New(d.pool).SaveDNSPublicURLWork(ctx, controlstatedb.SaveDNSPublicURLWorkParams{
		DnsState: string(work.State), DnsAvailableAt: nullableTime(availableAt), DnsLastError: nullableText(work.LastError),
		CompletedAt: timestamptz(now), PublicURLID: work.PublicURLID, WorkOwner: text(work.WorkerID),
		WorkEpoch: positive(work.WorkEpoch), ExpectedDnsRevision: positive(work.DNSRevision),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DNSPublicURLWork{}, ErrDNSPublicURLWorkStale
	}
	if err != nil {
		return DNSPublicURLWork{}, fmt.Errorf("controlstate: save DNS route work: %w", err)
	}
	return dnsRouteWork(row, false)
}

func dnsRouteWork(row controlstatedb.ControlPublicUrl, requireLease bool) (DNSPublicURLWork, error) {
	state := PublicURLDNSState(row.DnsState)
	if row.DnsRevision <= 0 || row.DnsAttempts <= 0 ||
		(state == PublicURLDNSPending || state == PublicURLDNSRemoving) != row.DnsAvailableAt.Valid ||
		requireLease && (!row.DnsWorkOwner.Valid || row.DnsWorkEpoch <= 0 || !row.DnsWorkExpiresAt.Valid) {
		return DNSPublicURLWork{}, errors.New("controlstate: invalid DNS route work row")
	}
	return DNSPublicURLWork{
		PublicURLID: row.ID, DomainID: row.DomainID, DNSAuthorityReference: row.DnsAuthorityReference.String,
		CanonicalHostname: row.CanonicalHostname, Namespace: row.Namespace, PublicURLScope: PublicURLScope(row.PublicURLScope),
		State: state, DNSRevision: uint64(row.DnsRevision),
		Attempts: uint64(row.DnsAttempts), AvailableAt: row.DnsAvailableAt.Time, LastError: row.DnsLastError.String,
		WorkerID: row.DnsWorkOwner.String, WorkEpoch: uint64(row.DnsWorkEpoch), WorkExpiresAt: row.DnsWorkExpiresAt.Time,
	}, nil
}

func validateDNSPublicURLWork(work DNSPublicURLWork) error {
	canonical, err := naming.CanonicalizeHostname(work.CanonicalHostname)
	if !opaqueid.Valid(work.PublicURLID, opaqueid.PublicURLPrefix) || !validStateText(work.DomainID) || err != nil || canonical != work.CanonicalHostname ||
		work.DNSAuthorityReference != "" && !validStateText(work.DNSAuthorityReference) ||
		work.State != PublicURLDNSPending && work.State != PublicURLDNSPublished && work.State != PublicURLDNSRemoving &&
			work.State != PublicURLDNSRemoved && work.State != PublicURLDNSFailed ||
		work.DNSRevision == 0 || work.DNSRevision > math.MaxInt64 || work.Attempts == 0 || work.Attempts > math.MaxInt64 ||
		!validStateText(work.WorkerID) || work.WorkEpoch == 0 || work.WorkEpoch > math.MaxInt64 ||
		work.WorkExpiresAt.IsZero() || len(work.LastError) > 1024 ||
		(work.State == PublicURLDNSPending || work.State == PublicURLDNSRemoving) && work.AvailableAt.IsZero() {
		return ErrDNSPublicURLInvalid
	}
	return nil
}
