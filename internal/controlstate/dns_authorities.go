package controlstate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var (
	ErrDNSAuthorityWorkStale   = errors.New("controlstate: DNS authority work lease is stale")
	ErrDNSAuthorityIdempotency = errors.New("controlstate: DNS authority idempotency conflict")
	ErrDNSAuthorityInvalid     = errors.New("controlstate: DNS authority request is invalid")
	ErrDNSAuthorityNotFound    = errors.New("controlstate: DNS authority not found")
)

type CreateDNSAuthorityRequest struct {
	TeamID          string
	DomainID        string
	CanonicalDomain string
	IdempotencyKey  string
	RequestDigest   [32]byte
}

type DNSAuthority struct {
	Reference       string
	TeamID          string
	DomainID        string
	CanonicalDomain string
	State           string
	RequiredRecords []DNSRecord
	LastError       string
	ProviderZoneID  string
	Nameservers     []string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type DNSAuthorityWork struct {
	DNSAuthority
	Provider       string
	ProviderZoneID string
	Nameservers    []string
	WorkRevision   uint64
	Attempts       uint64
	AvailableAt    time.Time
	WorkerID       string
	WorkEpoch      uint64
	WorkExpiresAt  time.Time
}

func (d *Database) CreateDNSAuthority(
	ctx context.Context,
	request CreateDNSAuthorityRequest,
	now time.Time,
) (DNSAuthority, error) {
	canonical, err := naming.CanonicalizeHostname(request.CanonicalDomain)
	if err != nil || canonical != request.CanonicalDomain || !validStateText(request.TeamID) ||
		!validStateText(request.DomainID) || !validIdempotencyKey(request.IdempotencyKey) || now.IsZero() {
		return DNSAuthority{}, ErrDNSAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return DNSAuthority{}, err
	}
	reference, err := opaqueid.New("dns_authority_")
	if err != nil {
		return DNSAuthority{}, err
	}
	row, err := controlstatedb.New(d.pool).CreateOrGetDNSAuthority(ctx, controlstatedb.CreateOrGetDNSAuthorityParams{
		AuthorityReference: reference, TeamID: request.TeamID, DomainID: request.DomainID,
		CanonicalDomain: request.CanonicalDomain, CreateIdempotencyKey: request.IdempotencyKey,
		CreateRequestDigest: request.RequestDigest[:], CreatedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DNSAuthority{}, ErrDNSAuthorityIdempotency
	}
	if err != nil {
		if isUniqueViolation(err) {
			return DNSAuthority{}, ErrDNSAuthorityIdempotency
		}
		return DNSAuthority{}, fmt.Errorf("controlstate: create DNS authority: %w", err)
	}
	if subtle.ConstantTimeCompare(row.CreateRequestDigest, request.RequestDigest[:]) != 1 {
		return DNSAuthority{}, ErrDNSAuthorityIdempotency
	}
	return dnsAuthority(row)
}

func (d *Database) GetDNSAuthority(ctx context.Context, reference string) (DNSAuthority, error) {
	if !opaqueid.Valid(reference, "dns_authority_") {
		return DNSAuthority{}, ErrDNSAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return DNSAuthority{}, err
	}
	row, err := controlstatedb.New(d.pool).GetDNSAuthority(ctx, reference)
	if errors.Is(err, pgx.ErrNoRows) {
		return DNSAuthority{}, ErrDNSAuthorityNotFound
	}
	if err != nil {
		return DNSAuthority{}, fmt.Errorf("controlstate: get DNS authority: %w", err)
	}
	return dnsAuthority(row)
}

func (d *Database) ReleaseDNSAuthority(
	ctx context.Context,
	reference, idempotencyKey string,
	now time.Time,
) (result DNSAuthority, retErr error) {
	if !opaqueid.Valid(reference, "dns_authority_") || !validIdempotencyKey(idempotencyKey) || now.IsZero() {
		return DNSAuthority{}, ErrDNSAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return DNSAuthority{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return DNSAuthority{}, fmt.Errorf("controlstate: release DNS authority: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "release DNS authority", &retErr)()
	queries := controlstatedb.New(tx)
	existing, err := queries.GetDNSAuthorityByReleaseIdempotency(ctx, text(idempotencyKey))
	if err == nil && existing.AuthorityReference != reference {
		return DNSAuthority{}, ErrDNSAuthorityIdempotency
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return DNSAuthority{}, fmt.Errorf("controlstate: release DNS authority: read idempotency: %w", err)
	}
	row, err := queries.LockDNSAuthority(ctx, reference)
	if errors.Is(err, pgx.ErrNoRows) {
		return DNSAuthority{}, ErrDNSAuthorityNotFound
	}
	if err != nil {
		return DNSAuthority{}, fmt.Errorf("controlstate: release DNS authority: lock: %w", err)
	}
	if row.State != "releasing" && row.State != "released" {
		row, err = queries.BeginDNSAuthorityRelease(ctx, controlstatedb.BeginDNSAuthorityReleaseParams{
			ReleaseIdempotencyKey: text(idempotencyKey), UpdatedAt: timestamptz(now), AuthorityReference: reference,
		})
		if errors.Is(err, pgx.ErrNoRows) || isUniqueViolation(err) {
			return DNSAuthority{}, ErrDNSAuthorityIdempotency
		}
		if err != nil {
			return DNSAuthority{}, fmt.Errorf("controlstate: release DNS authority: update: %w", err)
		}
	}
	result, err = dnsAuthority(row)
	if err != nil {
		return DNSAuthority{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return DNSAuthority{}, fmt.Errorf("controlstate: release DNS authority: commit: %w", err)
	}
	return result, nil
}

func (d *Database) ClaimDNSAuthorityWork(
	ctx context.Context,
	workerID string,
	now time.Time,
	leaseDuration time.Duration,
) (DNSAuthorityWork, bool, error) {
	if !validStateText(workerID) || now.IsZero() || leaseDuration <= 0 {
		return DNSAuthorityWork{}, false, ErrDNSAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return DNSAuthorityWork{}, false, err
	}
	row, err := controlstatedb.New(d.pool).ClaimDNSAuthorityWork(ctx, controlstatedb.ClaimDNSAuthorityWorkParams{
		WorkOwner: text(workerID), WorkExpiresAt: timestamptz(now.Add(leaseDuration)), ClaimedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DNSAuthorityWork{}, false, nil
	}
	if err != nil {
		return DNSAuthorityWork{}, false, fmt.Errorf("controlstate: claim DNS authority work: %w", err)
	}
	work, err := dnsAuthorityWork(row, true)
	return work, err == nil, err
}

func (d *Database) SaveDNSAuthorityWork(
	ctx context.Context,
	work DNSAuthorityWork,
	now time.Time,
) (result DNSAuthorityWork, retErr error) {
	if err := validateDNSAuthorityWork(work); err != nil || now.IsZero() {
		return DNSAuthorityWork{}, ErrDNSAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return DNSAuthorityWork{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return DNSAuthorityWork{}, fmt.Errorf("controlstate: save DNS authority work: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "save DNS authority work", &retErr)()
	queries := controlstatedb.New(tx)
	if err := queries.LockDNSAuthorityLocalTeam(ctx, text(work.Reference)); err != nil {
		return DNSAuthorityWork{}, fmt.Errorf("controlstate: save DNS authority work: lock local team: %w", err)
	}
	if err := queries.LockDNSAuthorityLocalDomain(ctx, text(work.Reference)); err != nil {
		return DNSAuthorityWork{}, fmt.Errorf("controlstate: save DNS authority work: lock local domain: %w", err)
	}
	row, err := queries.SaveDNSAuthorityWork(ctx, controlstatedb.SaveDNSAuthorityWorkParams{
		ProviderZoneID: nullableText(work.ProviderZoneID), State: work.State, Nameservers: slices.Clone(work.Nameservers),
		AvailableAt: timestamptz(work.AvailableAt), LastError: nullableText(work.LastError), CompletedAt: timestamptz(now),
		AuthorityReference: work.Reference, WorkOwner: text(work.WorkerID), WorkEpoch: positive(work.WorkEpoch),
		ExpectedWorkRevision: positive(work.WorkRevision),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DNSAuthorityWork{}, ErrDNSAuthorityWorkStale
	}
	if err != nil {
		return DNSAuthorityWork{}, fmt.Errorf("controlstate: save DNS authority work: %w", err)
	}
	localDomain, err := queries.UpdateLocalDomainForDNSAuthority(ctx, controlstatedb.UpdateLocalDomainForDNSAuthorityParams{
		State: work.State, UpdatedAt: timestamptz(now), AuthorityReference: text(work.Reference),
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return DNSAuthorityWork{}, fmt.Errorf("controlstate: save DNS authority work: update local domain: %w", err)
	}
	if err == nil && work.State == "ready" && localDomain.MakeDefaultWhenReady {
		revision, revisionErr := queries.SetDNSReadyDomainDefault(ctx, controlstatedb.SetDNSReadyDomainDefaultParams{
			UpdatedAt: timestamptz(now), AuthorityReference: text(work.Reference),
		})
		if revisionErr != nil && !errors.Is(revisionErr, pgx.ErrNoRows) {
			return DNSAuthorityWork{}, fmt.Errorf("controlstate: save DNS authority work: set local default domain: %w", revisionErr)
		}
		if revisionErr == nil {
			if err := queries.SetDomainAuthorityRevision(ctx, controlstatedb.SetDomainAuthorityRevisionParams{
				AuthorityRevision: revision, UpdatedAt: timestamptz(now), AuthorityReference: text(work.Reference),
			}); err != nil {
				return DNSAuthorityWork{}, fmt.Errorf("controlstate: save DNS authority work: update local domain revision: %w", err)
			}
		}
	}
	result, err = dnsAuthorityWork(row, false)
	if err != nil {
		return DNSAuthorityWork{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return DNSAuthorityWork{}, fmt.Errorf("controlstate: save DNS authority work: commit: %w", err)
	}
	return result, nil
}

func (d *Database) DNSAuthorityReleaseReady(ctx context.Context, domainID string, now time.Time) (bool, error) {
	if !validStateText(domainID) || now.IsZero() {
		return false, ErrDNSAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return false, err
	}
	ready, err := controlstatedb.New(d.pool).DNSAuthorityReleaseReady(ctx, controlstatedb.DNSAuthorityReleaseReadyParams{
		AuthorityDomainID: domainID, ObservedAt: timestamptz(now),
	})
	if err != nil {
		return false, fmt.Errorf("controlstate: check DNS authority release readiness: %w", err)
	}
	if !ready.Valid {
		return false, errors.New("controlstate: DNS authority release readiness is null")
	}
	return ready.Bool, nil
}

func dnsAuthority(row controlstatedb.ControlDnsAuthority) (DNSAuthority, error) {
	if !row.CreatedAt.Valid || !row.UpdatedAt.Valid || len(row.CreateRequestDigest) != 32 {
		return DNSAuthority{}, errors.New("controlstate: invalid DNS authority row")
	}
	return DNSAuthority{
		Reference: row.AuthorityReference, TeamID: row.TeamID, DomainID: row.DomainID,
		CanonicalDomain: row.CanonicalDomain, State: row.State,
		RequiredRecords: nameserverRecords(row.CanonicalDomain, row.Nameservers), LastError: row.LastError.String,
		ProviderZoneID: row.ProviderZoneID.String, Nameservers: slices.Clone(row.Nameservers),
		CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time,
	}, nil
}

func dnsAuthorityWork(row controlstatedb.ControlDnsAuthority, requireLease bool) (DNSAuthorityWork, error) {
	authority, err := dnsAuthority(row)
	if err != nil || row.WorkRevision <= 0 || row.Attempts <= 0 || !row.AvailableAt.Valid ||
		requireLease && (!row.WorkOwner.Valid || row.WorkEpoch <= 0 || !row.WorkExpiresAt.Valid) {
		return DNSAuthorityWork{}, errors.New("controlstate: invalid DNS authority work row")
	}
	return DNSAuthorityWork{
		DNSAuthority: authority, Provider: row.Provider, ProviderZoneID: row.ProviderZoneID.String,
		Nameservers: slices.Clone(row.Nameservers), WorkRevision: uint64(row.WorkRevision),
		Attempts: uint64(row.Attempts), AvailableAt: row.AvailableAt.Time,
		WorkerID: row.WorkOwner.String, WorkEpoch: uint64(row.WorkEpoch), WorkExpiresAt: row.WorkExpiresAt.Time,
	}, nil
}

func validateDNSAuthorityWork(work DNSAuthorityWork) error {
	if !opaqueid.Valid(work.Reference, "dns_authority_") || !validStateText(work.TeamID) ||
		!validStateText(work.DomainID) || !validStateText(work.CanonicalDomain) || work.Provider != "route53" ||
		!validStateText(work.WorkerID) || work.WorkRevision == 0 || work.WorkRevision > math.MaxInt64 ||
		work.Attempts == 0 || work.Attempts > math.MaxInt64 || work.WorkEpoch == 0 || work.WorkEpoch > math.MaxInt64 ||
		work.WorkExpiresAt.IsZero() || work.AvailableAt.IsZero() || len(work.LastError) > 1024 ||
		work.State != "pending" && work.State != "ready" && work.State != "releasing" &&
			work.State != "released" && work.State != "failed" {
		return ErrDNSAuthorityInvalid
	}
	canonical, err := naming.CanonicalizeHostname(work.CanonicalDomain)
	if err != nil || canonical != work.CanonicalDomain {
		return ErrDNSAuthorityInvalid
	}
	for _, nameserver := range work.Nameservers {
		canonical, err := naming.CanonicalizeHostname(nameserver)
		if err != nil || canonical != nameserver {
			return ErrDNSAuthorityInvalid
		}
	}
	return nil
}
