package controlstate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const (
	publicURLPageSize                     = 100
	ephemeralPublicURLGracePeriod         = 2 * time.Minute
	maximumExpiredEphemeralPublicURLBatch = 100
)

var (
	ErrPublicURLAccess        = errors.New("controlstate: public URL access denied")
	ErrPublicURLConflict      = errors.New("controlstate: public URL hostname is already in use")
	ErrPublicURLCreationGated = errors.New("controlstate: public URL creation is disabled")
	ErrPublicURLIdempotency   = errors.New("controlstate: public URL idempotency conflict")
	ErrPublicURLInvalid       = errors.New("controlstate: public URL request is invalid")
	ErrPublishRunOpen         = errors.New("controlstate: public URL has an open publish run")
	ErrPublicURLMutationStale = errors.New("controlstate: authorized public URL state changed")
)

type PublicURL struct {
	ID                            string
	TeamID                        string
	DomainID                      string
	MembershipID                  string
	CanonicalHostname             string
	Target                        string
	PublicURLScope                PublicURLScope
	PolicyRevision                int64
	LifecycleState                PublicURLLifecycleState
	DNSAuthorityReference         string
	DNSState                      PublicURLDNSState
	AllowedIPPrefixes             []netip.Prefix
	NextPublishRunNumber          int64
	MutationRevision              uint64
	AuthorizationPublishRunNumber uint64
	Ephemeral                     bool
	ExpiresAt                     *time.Time
	OpenPublishRunID              string
	CreatedAt                     time.Time
	UpdatedAt                     time.Time
}

type CreatePublicURLRequest struct {
	GuestID               string
	TeamID                string
	DomainID              string
	MembershipID          string
	ActingIdentityID      string
	IdempotencyKey        string
	RequestDigest         [32]byte
	CanonicalHostname     string
	Target                string
	PublicURLScope        PublicURLScope
	AllowedIPPrefixes     []string
	DNSState              PublicURLDNSState
	DNSAuthorityReference string
	AuthorityIssuer       string
	PolicyRevision        uint64
	Ephemeral             bool
}

type AuthorizedPublicURLUpdateRequest struct {
	PublicURLID              string
	TeamID                   string
	ActingIdentityID         string
	Target                   string
	AllowedIPPrefixes        []string
	AuthorityIssuer          string
	PolicyRevision           uint64
	ExpectedMutationRevision uint64
}

type AuthorizedPublicURLDeleteRequest struct {
	PublicURLID              string
	TeamID                   string
	ActingIdentityID         string
	AuthorityIssuer          string
	PolicyRevision           uint64
	ExpectedMutationRevision uint64
}

type PublicURLPage struct {
	PublicURLs []PublicURL
	NextCursor string
}

func (d *Database) CreatePublicURL(ctx context.Context, request CreatePublicURLRequest, now time.Time) (result PublicURL, retErr error) {
	prefixes, err := validateCreatePublicURLRequest(request)
	if err != nil {
		return PublicURL{}, err
	}
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create route", &retErr)()
	queries := controlstatedb.New(tx)
	if request.AuthorityIssuer == "" {
		if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAccess
		} else if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create public_url: lock team: %w", err)
		}
	}
	if _, err := queries.LockPublicURLCreator(ctx, request.ActingIdentityID); errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, ErrPublicURLAccess
	} else if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: lock creator: %w", err)
	}
	policyRevision := int64(0)
	if request.AuthorityIssuer != "" {
		policyRevision = positive(request.PolicyRevision)
		if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
			Issuer: request.AuthorityIssuer, TeamID: request.TeamID,
			PolicyRevision: policyRevision, UpdatedAt: timestamptz(now),
		}); errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAuthority
		} else if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create public_url: observe authority revision: %w", err)
		}
	}

	existing, err := queries.GetPublicURLByCreatorIdempotency(ctx, controlstatedb.GetPublicURLByCreatorIdempotencyParams{
		IdentityID: request.ActingIdentityID, IdempotencyKey: request.IdempotencyKey,
	})
	if err == nil {
		if PublicURLLifecycleState(existing.LifecycleState) == PublicURLLifecycleDeleted {
			return PublicURL{}, ErrPublicURLIdempotency
		}
		storedDigest, _, digestErr := d.openSecret(existing.RequestDigestStorageKeyID.String,
			publicURLRequestDigestContext(existing.ID), existing.RequestDigestCiphertext)
		if digestErr != nil {
			return PublicURL{}, fmt.Errorf("controlstate: read private idempotency digest: %w", digestErr)
		}
		if subtle.ConstantTimeCompare(storedDigest, request.RequestDigest[:]) != 1 {
			return PublicURL{}, ErrPublicURLIdempotency
		}
		if err := tx.Commit(ctx); err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create public_url: commit retry: %w", err)
		}
		result := publicURLFromIdempotencyRow(existing)
		result.AllowedIPPrefixes, err = d.openIPPolicy(existing.ID, existing.AllowedIpPolicyStorageKeyID.String, existing.AllowedIpPolicyCiphertext)
		if err != nil {
			return PublicURL{}, err
		}
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: read idempotent public_url: %w", err)
	}
	if request.GuestID != "" {
		guest, err := queries.LockGuestTrialByID(ctx, request.GuestID)
		if errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAccess
		}
		if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: lock guest trial: %w", err)
		}
		if !guest.ExpiresAt.Time.After(now) || guest.UsedReadyNs >= int64(GuestReadyAllowance) || guest.UsedBytes >= GuestByteAllowance {
			return PublicURL{}, ErrGuestTrialSpent
		}
		if guest.LastDemoNumber < 1 || !strings.HasPrefix(request.CanonicalHostname, fmt.Sprintf("demo-%d.%s.", guest.LastDemoNumber, guest.NamespaceLabel)) ||
			request.DomainID != guest.DomainID ||
			request.DNSState != PublicURLDNSUnmanaged && request.DNSAuthorityReference != guest.DnsAuthorityReference {
			return PublicURL{}, ErrPublicURLAccess
		}
		count, err := queries.CountGuestCurrentPublicURLs(ctx, request.GuestID)
		if err != nil {
			return PublicURL{}, err
		}
		if count != 0 {
			return PublicURL{}, ErrPublishRunOpen
		}
	}

	enabled, err := queries.LockPublicURLCreationControl(ctx)
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: read maintenance control: %w", err)
	}
	if !enabled {
		return PublicURL{}, ErrPublicURLCreationGated
	}
	if request.AuthorityIssuer == "" {
		creation, err := queries.GetPublicURLCreationContext(ctx, controlstatedb.GetPublicURLCreationContextParams{
			IdentityID: request.ActingIdentityID, DomainID: request.DomainID, TeamID: request.TeamID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAccess
		}
		if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create public_url: read authority context: %w", err)
		}
		labels, err := queries.ListTeamNamespaceLabels(ctx, request.TeamID)
		if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create public_url: read namespaces: %w", err)
		}
		if err := authorizeRouteCreation(request, creation, labels); err != nil {
			return PublicURL{}, err
		}
		policyRevision = creation.PolicyRevision
	}

	publicURLID, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: generate route ID: %w", err)
	}
	policyCiphertext, policyHashes, policyKeyID, err := d.storeIPPolicy(publicURLID, prefixes, request.GuestID != "")
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: protect IP policy: %w", err)
	}
	digestCiphertext, err := d.sealSecret(publicURLRequestDigestContext(publicURLID), request.RequestDigest[:])
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: protect request digest: %w", err)
	}
	policyStorageKeyID := ""
	if len(policyCiphertext) != 0 {
		policyStorageKeyID = d.storageKey.CurrentID()
	}
	membershipID := pgtype.Text{}
	if request.MembershipID != "" {
		membershipID = text(request.MembershipID)
	}
	row, err := queries.InsertPublicURL(ctx, controlstatedb.InsertPublicURLParams{
		ID: publicURLID, TeamID: request.TeamID, DomainID: request.DomainID, MembershipID: membershipID,
		CreatedByIdentityID: request.ActingIdentityID, IdempotencyKey: request.IdempotencyKey,
		RequestDigestCiphertext:   digestCiphertext,
		RequestDigestStorageKeyID: text(d.storageKey.CurrentID()),
		CanonicalHostname:         request.CanonicalHostname, Target: request.Target,
		PublicURLScope: string(request.PublicURLScope), PolicyRevision: policyRevision, IpPolicy: string(routeIPPolicy(prefixes)),
		AllowedIpPolicyCiphertext:   policyCiphertext,
		AllowedIpPolicyStorageKeyID: nullableText(policyStorageKeyID),
		AllowedIpHashes:             policyHashes, AllowedIpHashKeyID: nullableText(policyKeyID),
		DnsAuthorityReference: nullableText(request.DNSAuthorityReference),
		DnsState:              string(request.DNSState), Ephemeral: request.Ephemeral,
		ExpiresAt: ephemeralRouteExpiry(request.Ephemeral, now), CreatedAt: timestamptz(now),
	})
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			switch postgresError.ConstraintName {
			case "public_urls_current_hostname":
				return PublicURL{}, ErrPublicURLConflict
			case "public_urls_creator_idempotency":
				return PublicURL{}, ErrPublicURLIdempotency
			}
		}
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: insert public_url: %w", err)
	}
	if request.GuestID != "" {
		if err := queries.InsertGuestPublicURL(ctx, controlstatedb.InsertGuestPublicURLParams{
			PublicURLID: publicURLID, GuestID: request.GuestID, CreatedAt: timestamptz(now),
		}); err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create guest public_url: %w", err)
		}
	}
	if err := queries.InsertPublicURLCreateAuditEvent(ctx, controlstatedb.InsertPublicURLCreateAuditEventParams{
		ActorIdentityID: text(request.ActingIdentityID), RequestID: request.IdempotencyKey,
		PublicURLID: publicURLID, OccurredAt: timestamptz(now),
	}); err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: insert audit event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: commit: %w", err)
	}
	result = publicURLFromModel(row, "")
	if request.GuestID == "" {
		result.AllowedIPPrefixes = append([]netip.Prefix(nil), prefixes...)
	} else {
		result.AllowedIPPrefixes = nil
	}
	return result, nil
}

func (d *Database) UpdateAuthorizedPublicURL(
	ctx context.Context,
	request AuthorizedPublicURLUpdateRequest,
	now time.Time,
) (result PublicURL, retErr error) {
	prefixes, err := validateAuthorizedPublicURLUpdateRequest(request)
	if err != nil {
		return PublicURL{}, err
	}
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "update route", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	policyRevision := positive(request.PolicyRevision)
	if request.AuthorityIssuer == "" {
		if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAccess
		} else if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: update public_url: lock team: %w", err)
		}
	} else if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
		Issuer: request.AuthorityIssuer, TeamID: request.TeamID,
		PolicyRevision: policyRevision, UpdatedAt: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, ErrPublicURLAuthority
	} else if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: observe authority revision: %w", err)
	}
	route, err := queries.LockPublicURLForRun(ctx, request.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil &&
		(route.TeamID != request.TeamID || PublicURLLifecycleState(route.LifecycleState) == PublicURLLifecycleDeleted) {
		return PublicURL{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: lock public_url: %w", err)
	}
	if PublicURLLifecycleState(route.LifecycleState) != PublicURLLifecycleEnabled {
		return PublicURL{}, ErrPublicURLNotEnabled
	}
	if !matchesPositiveInt64(route.MutationRevision, request.ExpectedMutationRevision) {
		return PublicURL{}, ErrPublicURLMutationStale
	}
	if route.PolicyRevision > policyRevision {
		return PublicURL{}, ErrPublicURLAuthority
	}
	hasOpenSession, _, err := expireStaleOpenPublishRun(ctx, queries, &pendingEvents, route, now)
	if err != nil {
		return PublicURL{}, err
	}
	if hasOpenSession {
		return PublicURL{}, ErrPublishRunOpen
	}
	if request.AuthorityIssuer == "" {
		membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
			TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAccess
		}
		if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: update public_url: read membership: %w", err)
		}
		if membership.PolicyRevision != policyRevision ||
			route.PublicURLScope == string(PublicURLScopeMember) && (!route.MembershipID.Valid || route.MembershipID.String != membership.ID) ||
			route.PublicURLScope == string(PublicURLScopeShared) && membership.Role != "admin" && membership.Role != "owner" {
			return PublicURL{}, ErrPublicURLAccess
		}
	}
	policyCiphertext, policyHashes, policyKeyID, err := d.storeIPPolicy(request.PublicURLID, prefixes, false)
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: protect updated IP policy: %w", err)
	}
	policyStorageKeyID := ""
	if len(policyCiphertext) != 0 {
		policyStorageKeyID = d.storageKey.CurrentID()
	}
	updated, err := queries.UpdatePublicURL(ctx, controlstatedb.UpdatePublicURLParams{
		Target: request.Target, PolicyRevision: policyRevision, IpPolicy: string(routeIPPolicy(prefixes)),
		AllowedIpPolicyCiphertext:   policyCiphertext,
		AllowedIpPolicyStorageKeyID: nullableText(policyStorageKeyID),
		AllowedIpHashes:             policyHashes, AllowedIpHashKeyID: nullableText(policyKeyID),
		UpdatedAt: timestamptz(now), PublicURLID: request.PublicURLID,
		ExpectedMutationRevision: positive(request.ExpectedMutationRevision),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, ErrPublicURLMutationStale
	}
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: update public_url: %w", err)
	}
	requestID, err := opaqueid.New(opaqueid.RequestPrefix)
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: generate request ID: %w", err)
	}
	if err := queries.InsertPublicURLUpdateAuditEvent(ctx, controlstatedb.InsertPublicURLUpdateAuditEventParams{
		ActorIdentityID: text(request.ActingIdentityID), RequestID: requestID,
		PublicURLID: request.PublicURLID, OccurredAt: timestamptz(now),
	}); err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: insert audit event: %w", err)
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return PublicURL{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: commit: %w", err)
	}
	result = publicURLFromModel(updated, "")
	result.AllowedIPPrefixes = append([]netip.Prefix(nil), prefixes...)
	return result, nil
}

// DeleteExpiredEphemeralPublicURLs removes a bounded batch of expired public
// URLs. it uses the same publish-run, routing-table, and DNS cleanup as explicit
// deletion.
func (d *Database) DeleteExpiredEphemeralPublicURLs(ctx context.Context, now time.Time) (count int, retErr error) {
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("controlstate: delete expired ephemeral public_urls: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "delete expired ephemeral routes", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	routes, err := queries.LockExpiredEphemeralPublicURLs(ctx, controlstatedb.LockExpiredEphemeralPublicURLsParams{
		Now: timestamptz(now), BatchSize: maximumExpiredEphemeralPublicURLBatch,
	})
	if err != nil {
		return 0, fmt.Errorf("controlstate: delete expired ephemeral public_urls: lock public_urls: %w", err)
	}
	for _, route := range routes {
		hasOpenSession, _, err := expireStaleOpenPublishRun(ctx, queries, &pendingEvents, route, now)
		if err != nil {
			return 0, err
		}
		if hasOpenSession {
			continue
		}
		updated, err := queries.DeletePublicURL(ctx, controlstatedb.DeletePublicURLParams{
			DeletedAt: timestamptz(now), PublicURLID: route.ID, ExpectedMutationRevision: route.MutationRevision,
		})
		if err != nil {
			return 0, fmt.Errorf("controlstate: delete expired ephemeral public_urls: update public_url: %w", err)
		}
		if updated != 1 {
			return 0, ErrPublicURLNotFound
		}
		if err := queries.InsertExpiredEphemeralPublicURLDeleteAuditEvent(
			ctx,
			controlstatedb.InsertExpiredEphemeralPublicURLDeleteAuditEventParams{
				RequestID: "ephemeral_expiry/" + route.ID, PublicURLID: route.ID, OccurredAt: timestamptz(now),
			},
		); err != nil {
			return 0, fmt.Errorf("controlstate: delete expired ephemeral public_urls: insert audit event: %w", err)
		}
		count++
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("controlstate: delete expired ephemeral public_urls: commit: %w", err)
	}
	return count, nil
}

func (d *Database) ListPublicURLs(ctx context.Context, identityID, teamID, cursor string) (PublicURLPage, error) {
	if !validStateText(identityID) || !validStateText(teamID) || cursor != "" && !validStateText(cursor) {
		return PublicURLPage{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURLPage{}, err
	}
	rows, err := controlstatedb.New(d.pool).ListIdentityPublicURLs(ctx, controlstatedb.ListIdentityPublicURLsParams{
		TeamID: teamID, Cursor: nullableText(cursor), IdentityID: identityID,
	})
	if err != nil {
		return PublicURLPage{}, fmt.Errorf("controlstate: list public_urls: %w", err)
	}
	if len(rows) == 0 {
		if _, err := d.GetTeam(ctx, identityID, teamID); err != nil {
			return PublicURLPage{}, err
		}
	}
	page := PublicURLPage{PublicURLs: make([]PublicURL, min(len(rows), publicURLPageSize))}
	for index := range page.PublicURLs {
		page.PublicURLs[index] = publicURLFromListRow(rows[index])
		if err := d.restorePublicURLPolicy(&page.PublicURLs[index], rows[index].AllowedIpPolicyStorageKeyID,
			rows[index].AllowedIpPolicyCiphertext, rows[index].AllowedIpHashes); err != nil {
			return PublicURLPage{}, err
		}
	}
	if len(rows) > publicURLPageSize {
		page.NextCursor = rows[publicURLPageSize-1].ID
	}
	return page, nil
}

// ListAuthorizedPublicURLs returns one team page after the caller has obtained a
// current authorization decision. it does not consult local memberships.
func (d *Database) ListAuthorizedPublicURLs(ctx context.Context, teamID, cursor string) (PublicURLPage, error) {
	if !validStateText(teamID) || cursor != "" && !validStateText(cursor) {
		return PublicURLPage{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURLPage{}, err
	}
	rows, err := controlstatedb.New(d.pool).ListExternalAuthorityPublicURLs(
		ctx,
		controlstatedb.ListExternalAuthorityPublicURLsParams{TeamID: teamID, Cursor: nullableText(cursor)},
	)
	if err != nil {
		return PublicURLPage{}, fmt.Errorf("controlstate: list authorized public_urls: %w", err)
	}
	page := PublicURLPage{PublicURLs: make([]PublicURL, min(len(rows), publicURLPageSize))}
	for index := range page.PublicURLs {
		page.PublicURLs[index] = publicURLFromExternalAuthorityListRow(rows[index])
		if err := d.restorePublicURLPolicy(&page.PublicURLs[index], rows[index].AllowedIpPolicyStorageKeyID,
			rows[index].AllowedIpPolicyCiphertext, rows[index].AllowedIpHashes); err != nil {
			return PublicURLPage{}, err
		}
	}
	if len(rows) > publicURLPageSize {
		page.NextCursor = rows[publicURLPageSize-1].ID
	}
	return page, nil
}

// GetAuthorizedPublicURLByHostname reads one non-deleted public URL after a current
// team-read authorization decision, using the existing hostname index.
func (d *Database) GetAuthorizedPublicURLByHostname(ctx context.Context, teamID, hostname string) (PublicURL, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if !validStateText(teamID) || err != nil || canonical != hostname {
		return PublicURL{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, err
	}
	row, err := controlstatedb.New(d.pool).GetAuthorizedPublicURLByHostname(ctx, controlstatedb.GetAuthorizedPublicURLByHostnameParams{
		TeamID: teamID, CanonicalHostname: hostname,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: get authorized route by hostname: %w", err)
	}
	result := publicURLFromExternalAuthorityListRow(controlstatedb.ListExternalAuthorityPublicURLsRow(row))
	if err := d.restorePublicURLPolicy(&result, row.AllowedIpPolicyStorageKeyID, row.AllowedIpPolicyCiphertext, row.AllowedIpHashes); err != nil {
		return PublicURL{}, err
	}
	return result, nil
}

func (d *Database) GetPublicURL(ctx context.Context, identityID, publicURLID string) (PublicURL, error) {
	if !validStateText(identityID) || !validStateText(publicURLID) {
		return PublicURL{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, err
	}
	row, err := controlstatedb.New(d.pool).GetIdentityPublicURL(ctx, controlstatedb.GetIdentityPublicURLParams{
		PublicURLID: publicURLID, IdentityID: identityID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: get public_url: %w", err)
	}
	result := publicURLFromIdentityRow(row)
	if err := d.restorePublicURLPolicy(&result, row.AllowedIpPolicyStorageKeyID, row.AllowedIpPolicyCiphertext, row.AllowedIpHashes); err != nil {
		return PublicURL{}, err
	}
	return result, nil
}

func (d *Database) DeletePublicURL(ctx context.Context, identityID, publicURLID string, now time.Time) (retErr error) {
	return d.deletePublicURL(ctx, AuthorizedPublicURLDeleteRequest{PublicURLID: publicURLID, ActingIdentityID: identityID}, now)
}

func (d *Database) DeleteAuthorizedPublicURL(
	ctx context.Context,
	request AuthorizedPublicURLDeleteRequest,
	now time.Time,
) error {
	return d.deletePublicURL(ctx, request, now)
}

func (d *Database) deletePublicURL(ctx context.Context, request AuthorizedPublicURLDeleteRequest, now time.Time) (retErr error) {
	identityID := request.ActingIdentityID
	publicURLID := request.PublicURLID
	if !validStateText(identityID) || !validStateText(publicURLID) {
		return ErrPublicURLInvalid
	}
	if request.AuthorityIssuer != "" && (!validStateText(request.AuthorityIssuer) || !validStateText(request.TeamID) ||
		request.PolicyRevision == 0 || request.ExpectedMutationRevision == 0) {
		return ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: delete public_url: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "delete route", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	var route controlstatedb.ControlPublicUrl
	if request.AuthorityIssuer == "" {
		if _, err := queries.LockLocalPublicURLTeamForMutation(ctx, publicURLID); errors.Is(err, pgx.ErrNoRows) {
			return ErrPublicURLNotFound
		} else if err != nil {
			return fmt.Errorf("controlstate: delete public_url: lock team: %w", err)
		}
		row, err := queries.LockIdentityPublicURLForDelete(ctx, controlstatedb.LockIdentityPublicURLForDeleteParams{
			IdentityID: identityID, PublicURLID: publicURLID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPublicURLNotFound
		}
		if err != nil {
			return fmt.Errorf("controlstate: delete public_url: lock public_url: %w", err)
		}
		if row.ActorRole == "member" && (!row.MembershipID.Valid || row.MembershipID.String != row.ActorMembershipID) {
			return ErrPublicURLAccess
		}
		route = publicURLModelFromDeleteRow(row)
	} else {
		if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
			Issuer: request.AuthorityIssuer, TeamID: request.TeamID,
			PolicyRevision: positive(request.PolicyRevision), UpdatedAt: timestamptz(now),
		}); errors.Is(err, pgx.ErrNoRows) {
			return ErrPublicURLAuthority
		} else if err != nil {
			return fmt.Errorf("controlstate: delete public_url: observe authority revision: %w", err)
		}
		var err error
		route, err = queries.LockPublicURLForRun(ctx, publicURLID)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && route.TeamID != request.TeamID {
			return ErrPublicURLNotFound
		}
		if err != nil {
			return fmt.Errorf("controlstate: delete public_url: lock public_url: %w", err)
		}
		if !matchesPositiveInt64(route.MutationRevision, request.ExpectedMutationRevision) {
			return ErrPublicURLMutationStale
		}
	}
	expectedMutationRevision := route.MutationRevision
	if request.ExpectedMutationRevision != 0 {
		if !matchesPositiveInt64(route.MutationRevision, request.ExpectedMutationRevision) {
			return ErrPublicURLMutationStale
		}
		expectedMutationRevision = positive(request.ExpectedMutationRevision)
	}
	if err := closeOpenPublishRun(ctx, queries, &pendingEvents, route, now, "public_url_deleted"); err != nil {
		return err
	}
	updated, err := queries.DeletePublicURL(ctx, controlstatedb.DeletePublicURLParams{
		DeletedAt: timestamptz(now), PublicURLID: publicURLID, ExpectedMutationRevision: expectedMutationRevision,
	})
	if err != nil {
		return fmt.Errorf("controlstate: delete public_url: update public_url: %w", err)
	}
	if updated != 1 {
		return ErrPublicURLNotFound
	}
	requestID, err := opaqueid.New(opaqueid.RequestPrefix)
	if err != nil {
		return fmt.Errorf("controlstate: delete public_url: generate request ID: %w", err)
	}
	if err := queries.InsertPublicURLDeleteAuditEvent(ctx, controlstatedb.InsertPublicURLDeleteAuditEventParams{
		ActorIdentityID: text(identityID), RequestID: requestID, PublicURLID: publicURLID, OccurredAt: timestamptz(now),
	}); err != nil {
		return fmt.Errorf("controlstate: delete public_url: insert audit event: %w", err)
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("controlstate: delete public_url: commit: %w", err)
	}
	return nil
}

func (d *Database) ClosePublishRun(ctx context.Context, publishRunID string, token credentials.PublishRunToken, now time.Time) (retErr error) {
	defer d.observeOperation("ClosePublishRun", &retErr)()
	if !validStateText(publishRunID) {
		return ErrPublishRunCredential
	}
	tokenID, tokenHash, err := credentials.ParsePublishRunToken(token)
	if err != nil {
		return ErrPublishRunCredential
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: close publish run: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "close publish run", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	before, err := queries.GetPublishRun(ctx, publishRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPublishRunCredential
	}
	if err != nil {
		return fmt.Errorf("controlstate: close publish run: read session: %w", err)
	}
	route, err := queries.LockPublicURLForRun(ctx, before.PublicURLID)
	if err != nil {
		return fmt.Errorf("controlstate: close publish run: lock public_url: %w", err)
	}
	session, err := queries.LockPublishRun(ctx, publishRunID)
	if err != nil {
		return fmt.Errorf("controlstate: close publish run: lock session: %w", err)
	}
	if tokenID.String() != session.PublishRunTokenID || !credentials.SecretHashMatches(session.PublishRunTokenDigest, tokenHash) {
		return ErrPublishRunCredential
	}
	if session.ClosedAt.Valid {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("controlstate: close publish run: commit retry: %w", err)
		}
		return nil
	}
	if err := closePublishRun(ctx, queries, &pendingEvents, route, session, PublishRunClosed, now, "publisher_closed"); err != nil {
		return err
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("controlstate: close publish run: commit: %w", err)
	}
	return nil
}

func closeOpenPublishRun(
	ctx context.Context,
	queries *controlstatedb.Queries,
	pendingEvents *pendingIngressRoutingTableEvents,
	route controlstatedb.ControlPublicUrl,
	now time.Time,
	reason string,
) error {
	session, err := queries.GetOpenPublishRun(ctx, route.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("controlstate: close publish run: read open session: %w", err)
	}
	return closePublishRun(ctx, queries, pendingEvents, route, session, PublishRunClosed, now, reason)
}

// the caller holds the public URL row through commit, keeping the live/expired
// result valid. Closed is false if another control closed the publish run first.
func expireStaleOpenPublishRun(
	ctx context.Context,
	queries *controlstatedb.Queries,
	pendingEvents *pendingIngressRoutingTableEvents,
	route controlstatedb.ControlPublicUrl,
	now time.Time,
) (live, closed bool, retErr error) {
	session, err := queries.GetOpenPublishRun(ctx, route.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("controlstate: expire publish run: read open session: %w", err)
	}
	closedAt := now
	reason := "publisher_expired"
	if session.PublisherExpiresAt.Valid {
		closedAt = session.PublisherExpiresAt.Time
	}
	guestID, err := queries.GuestForPublicURL(ctx, route.ID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, false, fmt.Errorf("controlstate: expire publish run: read guest owner: %w", err)
	}
	if err == nil {
		guest, err := queries.GetGuestTrialByID(ctx, guestID)
		if err != nil {
			return false, false, fmt.Errorf("controlstate: expire publish run: read guest trial: %w", err)
		}
		if guest.ExpiresAt.Valid && guest.ExpiresAt.Time.Before(closedAt) {
			closedAt, reason = guest.ExpiresAt.Time, "guest_expired"
		}
		if guest.ActiveReadyAt.Valid {
			remaining := GuestReadyAllowance - time.Duration(guest.UsedReadyNs)
			if remaining < 0 {
				remaining = 0
			}
			deadline := guest.ActiveReadyAt.Time.Add(remaining)
			if deadline.Before(closedAt) {
				closedAt, reason = deadline, "guest_ready_limit"
			}
		}
		if guest.UsedBytes >= GuestByteAllowance && now.Before(closedAt) {
			closedAt, reason = now, "guest_transfer_limit"
		}
	}
	if closedAt.After(now) {
		return true, false, nil
	}
	if err := closePublishRun(ctx, queries, pendingEvents, route, session, PublishRunExpired, closedAt, reason); err != nil {
		return false, false, err
	}
	return false, true, nil
}

func closePublishRun(
	ctx context.Context,
	queries *controlstatedb.Queries,
	pendingEvents *pendingIngressRoutingTableEvents,
	route controlstatedb.ControlPublicUrl,
	session controlstatedb.ControlPublishRun,
	state PublishRunState,
	now time.Time,
	reason string,
) error {
	if challengeExpiresAt, active, err := activePublishRunChallengeExpiry(ctx, queries, session.ID, now); err != nil {
		return err
	} else if active {
		entryRevision, err := queries.LatestIngressRoutingEntryRevision(ctx, controlstatedb.LatestIngressRoutingEntryRevisionParams{
			PublicURLID: route.ID, PublishRunNumber: session.PublishRunNumber,
		})
		if err != nil {
			return fmt.Errorf("controlstate: close publish run: read ingress routing-table entry revision: %w", err)
		}
		if entryRevision > 0 {
			if _, err := pendingEvents.addChallengeEvent(
				ctx, queries, route, session, nil, "challenge_tombstone", challengeExpiresAt, now,
			); err != nil {
				return err
			}
		}
	}
	if session.ReadyAt.Valid {
		if _, err := pendingEvents.addRouteEvent(ctx, queries, route, session, nil, "public_url_tombstone", now); err != nil {
			return err
		}
	}
	if err := queries.CancelPublishRunACMEOrders(ctx, controlstatedb.CancelPublishRunACMEOrdersParams{
		CanceledAt: timestamptz(now), PublishRunID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close publish run: cancel certificate orders: %w", err)
	}
	if err := queries.CancelPublishRunACMEAuthorizations(ctx, controlstatedb.CancelPublishRunACMEAuthorizationsParams{
		CanceledAt: timestamptz(now), PublishRunID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close publish run: cancel certificate authorizations: %w", err)
	}
	if _, err := queries.CancelOpenPublicURLRecoveryEpisode(ctx, controlstatedb.CancelOpenPublicURLRecoveryEpisodeParams{
		CanceledAt: timestamptz(now), PublicURLID: route.ID, PublishRunNumber: session.PublishRunNumber,
	}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("controlstate: close publish run: cancel recovery episode: %w", err)
	}
	if err := queries.ClosePublishRunConnections(ctx, controlstatedb.ClosePublishRunConnectionsParams{
		ClosedAt: timestamptz(now), PublishRunID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close publish run: close publisher connections: %w", err)
	}
	if _, err := queries.ClosePublishRun(ctx, controlstatedb.ClosePublishRunParams{
		State: string(state), ClosedAt: timestamptz(now), CloseReason: text(reason), PublishRunID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close publish run: update session: %w", err)
	}
	if _, err := queries.FinishGuestPublishRun(ctx, controlstatedb.FinishGuestPublishRunParams{
		PublishRunID: text(session.ID), ClosedAt: timestamptz(now), CloseReason: reason,
	}); err != nil {
		return fmt.Errorf("controlstate: finish guest publish run: %w", err)
	}
	return nil
}

func validateCreatePublicURLRequest(request CreatePublicURLRequest) ([]netip.Prefix, error) {
	for _, value := range []string{
		request.TeamID, request.DomainID, request.ActingIdentityID, request.IdempotencyKey,
		request.CanonicalHostname, request.Target, string(request.PublicURLScope), string(request.DNSState),
	} {
		if !validStateText(value) {
			return nil, ErrPublicURLInvalid
		}
	}
	if len(request.IdempotencyKey) > 128 || request.MembershipID != "" && !validStateText(request.MembershipID) ||
		request.DNSAuthorityReference != "" && !validStateText(request.DNSAuthorityReference) ||
		request.DNSState == PublicURLDNSUnmanaged && request.DNSAuthorityReference != "" ||
		request.PublicURLScope != PublicURLScopeMember && request.PublicURLScope != PublicURLScopeShared ||
		request.DNSState != PublicURLDNSUnmanaged && request.DNSState != PublicURLDNSPending {
		return nil, ErrPublicURLInvalid
	}
	if request.AuthorityIssuer != "" && (!validStateText(request.AuthorityIssuer) || request.PolicyRevision == 0) {
		return nil, ErrPublicURLInvalid
	}
	canonical, err := naming.CanonicalizeHostname(request.CanonicalHostname)
	if err != nil || canonical != request.CanonicalHostname {
		return nil, ErrPublicURLInvalid
	}
	if err := authorization.ValidateTarget(request.Target); err != nil {
		return nil, ErrPublicURLInvalid
	}
	canonicalPrefixes, err := authorization.CanonicalizeIPPrefixes(request.AllowedIPPrefixes)
	if err != nil || !slices.Equal(canonicalPrefixes, request.AllowedIPPrefixes) {
		return nil, ErrPublicURLInvalid
	}
	prefixes := make([]netip.Prefix, len(canonicalPrefixes))
	for index, value := range canonicalPrefixes {
		prefixes[index], _ = netip.ParsePrefix(value)
	}
	return prefixes, nil
}

func validateAuthorizedPublicURLUpdateRequest(request AuthorizedPublicURLUpdateRequest) ([]netip.Prefix, error) {
	for _, value := range []string{request.PublicURLID, request.TeamID, request.ActingIdentityID, request.Target} {
		if !validStateText(value) {
			return nil, ErrPublicURLInvalid
		}
	}
	if request.PolicyRevision == 0 || request.ExpectedMutationRevision == 0 ||
		request.AuthorityIssuer != "" && !validStateText(request.AuthorityIssuer) ||
		authorization.ValidateTarget(request.Target) != nil {
		return nil, ErrPublicURLInvalid
	}
	canonicalPrefixes, err := authorization.CanonicalizeIPPrefixes(request.AllowedIPPrefixes)
	if err != nil || request.AllowedIPPrefixes == nil || !slices.Equal(canonicalPrefixes, request.AllowedIPPrefixes) {
		return nil, ErrPublicURLInvalid
	}
	return prefixValues(canonicalPrefixes), nil
}

func ephemeralRouteExpiry(ephemeral bool, now time.Time) pgtype.Timestamptz {
	if !ephemeral {
		return pgtype.Timestamptz{}
	}
	return timestamptz(now.Add(ephemeralPublicURLGracePeriod))
}

func authorizeRouteCreation(
	request CreatePublicURLRequest,
	context controlstatedb.GetPublicURLCreationContextRow,
	labels []controlstatedb.ListTeamNamespaceLabelsRow,
) error {
	if context.DomainState != "ready" || context.DomainKind == "claimed" && context.DomainTeamID.String != request.TeamID ||
		context.DomainKind == "managed" && context.DomainTeamID.Valid || !hostnameWithin(request.CanonicalHostname, context.CanonicalDomain) {
		return ErrPublicURLAccess
	}
	if request.DNSState == PublicURLDNSPending && request.DNSAuthorityReference != context.DnsAuthorityReference.String {
		return ErrPublicURLAccess
	}
	actorLabel := context.ActorMemberSlug
	if context.DomainKind == "managed" {
		actorLabel = context.ActorManagedLabel
	}
	actorNamespace := actorLabel + "." + context.CanonicalDomain
	if request.PublicURLScope == "member" {
		if request.MembershipID != context.ActorMembershipID ||
			request.CanonicalHostname != actorNamespace && !oneLabelBeneath(request.CanonicalHostname, actorNamespace) {
			return ErrPublicURLAccess
		}
		return nil
	}
	if request.MembershipID != "" || context.ActorRole != "admin" && context.ActorRole != "owner" {
		return ErrPublicURLAccess
	}
	if context.DomainKind == "managed" {
		if context.TeamKind != "personal" || context.IdentityKind != "builtin" ||
			context.TeamCreatorIdentityID != request.ActingIdentityID ||
			!oneLabelBeneath(request.CanonicalHostname, context.CanonicalDomain) {
			return ErrPublicURLAccess
		}
		return nil
	}
	for _, label := range labels {
		namespace := label.MemberSlug + "." + context.CanonicalDomain
		if request.CanonicalHostname == namespace || strings.HasSuffix(request.CanonicalHostname, "."+namespace) {
			return ErrPublicURLAccess
		}
	}
	return nil
}

func hostnameWithin(hostname, domain string) bool {
	return hostname == domain || strings.HasSuffix(hostname, "."+domain)
}

func oneLabelBeneath(hostname, domain string) bool {
	suffix := "." + domain
	if !strings.HasSuffix(hostname, suffix) {
		return false
	}
	label := strings.TrimSuffix(hostname, suffix)
	return label != "" && !strings.Contains(label, ".")
}

func routeIPPolicy(prefixes []netip.Prefix) IPPolicy {
	if len(prefixes) == 0 {
		return IPPolicyAllowAll
	}
	return IPPolicyAllowlist
}

func nullableText(value string) pgtype.Text {
	if value == "" {
		return pgtype.Text{}
	}
	return text(value)
}

func publicURLFromModel(row controlstatedb.ControlPublicUrl, openPublishRunID string) PublicURL {
	return publicURLFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.PublicURLScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState,
		row.NextPublishRunNumber, row.MutationRevision, row.Ephemeral, row.ExpiresAt, openPublishRunID, row.CreatedAt, row.UpdatedAt,
	)
}

func publicURLFromIdempotencyRow(row controlstatedb.GetPublicURLByCreatorIdempotencyRow) PublicURL {
	return publicURLFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.PublicURLScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState,
		row.NextPublishRunNumber, row.MutationRevision, row.Ephemeral, row.ExpiresAt, row.OpenPublishRunID, row.CreatedAt, row.UpdatedAt,
	)
}

func publicURLFromIdentityRow(row controlstatedb.GetIdentityPublicURLRow) PublicURL {
	return publicURLFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.PublicURLScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState,
		row.NextPublishRunNumber, row.MutationRevision, row.Ephemeral, row.ExpiresAt, row.OpenPublishRunID, row.CreatedAt, row.UpdatedAt,
	)
}

func publicURLFromListRow(row controlstatedb.ListIdentityPublicURLsRow) PublicURL {
	return publicURLFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.PublicURLScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState,
		row.NextPublishRunNumber, row.MutationRevision, row.Ephemeral, row.ExpiresAt, row.OpenPublishRunID, row.CreatedAt, row.UpdatedAt,
	)
}

func publicURLFromExternalAuthorityListRow(row controlstatedb.ListExternalAuthorityPublicURLsRow) PublicURL {
	return publicURLFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.PublicURLScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState,
		row.NextPublishRunNumber, row.MutationRevision, row.Ephemeral, row.ExpiresAt, row.OpenPublishRunID, row.CreatedAt, row.UpdatedAt,
	)
}

func publicURLFromValues(
	id, teamID, domainID string,
	membershipID pgtype.Text,
	canonicalHostname, target, publicURLScope string,
	policyRevision int64,
	lifecycleState string,
	dnsAuthorityReference pgtype.Text,
	dnsState string,
	nextPublishRunNumber int64,
	mutationRevision int64,
	ephemeral bool,
	expiresAt pgtype.Timestamptz,
	openPublishRunID string,
	createdAt, updatedAt pgtype.Timestamptz,
) PublicURL {
	result := PublicURL{
		ID: id, TeamID: teamID, DomainID: domainID, MembershipID: membershipID.String,
		CanonicalHostname: canonicalHostname, Target: target, PublicURLScope: PublicURLScope(publicURLScope),
		PolicyRevision: policyRevision, LifecycleState: PublicURLLifecycleState(lifecycleState),
		DNSAuthorityReference: dnsAuthorityReference.String, DNSState: PublicURLDNSState(dnsState),
		NextPublishRunNumber: nextPublishRunNumber,
		MutationRevision:     uint64(mutationRevision), AuthorizationPublishRunNumber: uint64(nextPublishRunNumber),
		Ephemeral:        ephemeral,
		OpenPublishRunID: openPublishRunID, CreatedAt: createdAt.Time, UpdatedAt: updatedAt.Time,
	}
	if expiresAt.Valid {
		value := expiresAt.Time
		result.ExpiresAt = &value
	}
	return result
}

func publicURLModelFromDeleteRow(row controlstatedb.LockIdentityPublicURLForDeleteRow) controlstatedb.ControlPublicUrl {
	return controlstatedb.ControlPublicUrl{
		ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID, MembershipID: row.MembershipID,
		CreatedByIdentityID: row.CreatedByIdentityID, IdempotencyKey: row.IdempotencyKey,
		RequestDigestCiphertext:   row.RequestDigestCiphertext,
		RequestDigestStorageKeyID: row.RequestDigestStorageKeyID,
		CanonicalHostname:         row.CanonicalHostname, Target: row.Target,
		PublicURLScope: row.PublicURLScope, PolicyRevision: row.PolicyRevision, IpPolicy: row.IpPolicy,
		AllowedIpPolicyCiphertext:   row.AllowedIpPolicyCiphertext,
		AllowedIpPolicyStorageKeyID: row.AllowedIpPolicyStorageKeyID,
		AllowedIpHashes:             row.AllowedIpHashes, AllowedIpHashKeyID: row.AllowedIpHashKeyID,
		LifecycleState: row.LifecycleState,
		Ephemeral:      row.Ephemeral, ExpiresAt: row.ExpiresAt,
		DnsAuthorityReference: row.DnsAuthorityReference, DnsState: row.DnsState,
		DnsRevision: row.DnsRevision, NextPublishRunNumber: row.NextPublishRunNumber, MutationRevision: row.MutationRevision,
		SuspensionRevision: row.SuspensionRevision, SuspensionReason: row.SuspensionReason,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, SuspendedAt: row.SuspendedAt, DeletedAt: row.DeletedAt,
	}
}
