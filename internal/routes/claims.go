package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

const (
	hostnameClaimPageSize = 100
	randomClaimAttempts   = 16
)

type HostnameClaim struct {
	ID          string
	PrincipalID string
	Hostname    string
	Kind        string
	State       string
	Source      string
	CreatedAt   time.Time
	ActivatedAt time.Time
	ReleasedAt  time.Time
}

const (
	NameKindReserved          = "reserved"
	NameKindPersistentManaged = "persistent_managed"
	NameKindPersistentCustom  = "persistent_custom_domain"
	NameKindEphemeral         = "ephemeral"

	NameStateHeld          = "held"
	NameStatePendingDNS    = "pending_dns"
	NameStateActive        = "active"
	NameStateDNSUnready    = "dns_unready"
	NameStateReleasedOwned = "released_owned"
	NameStateReleased      = "released"
	NameStateBurned        = "burned"
	NameStateQuarantined   = "quarantined"

	NameSourceConfigured = "configured"
	NameSourceCustom     = "custom"
	NameSourceGenerated  = "generated"
)

func (s *Store) ClaimHostname(
	ctx context.Context,
	principalID, label, requestKey string,
) (claim HostnameClaim, err error) {
	return s.ClaimName(ctx, principalID, NameKindPersistentManaged, label, requestKey)
}

func (s *Store) ClaimName(
	ctx context.Context,
	principalID, kind, name, requestKey string,
) (claim HostnameClaim, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationHostnameClaim, started, err) }()
	if strings.TrimSpace(principalID) == "" || strings.TrimSpace(requestKey) != requestKey ||
		requestKey == "" || len(requestKey) > 128 {
		return HostnameClaim{}, ErrInvalidArgument
	}
	if kind != NameKindPersistentManaged && kind != NameKindEphemeral {
		return HostnameClaim{}, ErrInvalidArgument
	}
	if kind == NameKindEphemeral && name != "" {
		return HostnameClaim{}, ErrInvalidArgument
	}
	canonicalLabel, err := s.canonicalBaseName(name)
	if err != nil {
		return HostnameClaim{}, err
	}
	now := time.Unix(s.now().Unix(), 0).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: begin hostname claim: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)

	// Resolve request-key replays before quota checks or allocation.
	claim, requestedLabel, requestedKind, found, err := readClaimRequest(ctx, queries, principalID, requestKey)
	if err != nil {
		return HostnameClaim{}, err
	}
	if found {
		if requestedLabel != canonicalLabel || requestedKind != kind ||
			claim.State == NameStateBurned || claim.State == NameStateQuarantined {
			return HostnameClaim{}, ErrInvalidState
		}
		return claim, nil
	}
	if canonicalLabel != "" {
		claim, err = readClaimByHostname(ctx, queries, canonicalLabel+"."+s.routeSuffix)
		if err == nil {
			if claim.PrincipalID != principalID || claim.Kind != NameKindPersistentManaged {
				return HostnameClaim{}, ErrNameUnavailable
			}
			if claim.State == NameStateReleasedOwned {
				if err := s.checkActiveClaimQuota(ctx, queries, principalID); err != nil {
					return HostnameClaim{}, err
				}
				count, err := queries.ReactivatePersistentClaim(ctx, statedb.ReactivatePersistentClaimParams{
					ActivatedAt: now.Unix(), ID: claim.ID, PrincipalID: principalID,
				})
				if err != nil || count != 1 {
					return HostnameClaim{}, ErrInvalidState
				}
				claim.State = NameStateActive
				claim.ActivatedAt = now
				claim.ReleasedAt = time.Time{}
			} else if claim.State != NameStateActive {
				return HostnameClaim{}, ErrNameUnavailable
			}
			if err := s.recordClaimRequest(ctx, queries, principalID, requestKey, canonicalLabel, kind, claim.ID, now); err != nil {
				return HostnameClaim{}, err
			}
			if err := tx.Commit(); err != nil {
				return HostnameClaim{}, fmt.Errorf("routes: commit hostname claim: %w", err)
			}
			return claim, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return HostnameClaim{}, err
		}
	}
	if kind == NameKindPersistentManaged {
		if err := s.checkActiveClaimQuota(ctx, queries, principalID); err != nil {
			return HostnameClaim{}, err
		}
	}

	if canonicalLabel == "" {
		// Let the unique index arbitrate collisions and retry with fresh entropy.
		for range randomClaimAttempts {
			candidate, candidateErr := randomClaimLabel()
			if candidateErr != nil {
				return HostnameClaim{}, candidateErr
			}
			claim, found, err = s.insertClaim(ctx, queries, principalID, candidate, kind, NameSourceGenerated, now)
			if err != nil {
				return HostnameClaim{}, err
			}
			if found {
				break
			}
		}
		if !found {
			return HostnameClaim{}, errors.New("routes: allocate hostname")
		}
	} else {
		claim, found, err = s.insertClaim(ctx, queries, principalID, canonicalLabel, kind, NameSourceCustom, now)
		if err != nil {
			return HostnameClaim{}, err
		}
		if !found {
			claim, err = readClaimByHostname(ctx, queries, canonicalLabel+"."+s.routeSuffix)
			if err != nil {
				return HostnameClaim{}, err
			}
			if claim.PrincipalID != principalID || claim.Kind != kind || claim.State != NameStateActive {
				return HostnameClaim{}, ErrNameUnavailable
			}
		}
	}
	if err := s.recordClaimRequest(ctx, queries, principalID, requestKey, canonicalLabel, kind, claim.ID, now); err != nil {
		return HostnameClaim{}, err
	}
	if err := tx.Commit(); err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: commit hostname claim: %w", err)
	}
	return claim, nil
}

func (s *Store) checkActiveClaimQuota(ctx context.Context, queries *statedb.Queries, principalID string) error {
	active, err := queries.CountActivePersistentClaims(ctx, principalID)
	if err != nil {
		return fmt.Errorf("routes: count hostname claims: %w", err)
	}
	if active >= int64(s.maxActiveHostnameClaims) {
		return ErrInvalidState
	}
	return nil
}

// FriendlyNameCapacity returns total allocator capacity and a conservative
// remaining count. Every managed base is counted because a custom label may
// also be a member of the friendly corpus.
func (s *Store) FriendlyNameCapacity(ctx context.Context) (int64, int64, error) {
	manifest, err := naming.FriendlyCorpusManifest()
	if err != nil {
		return 0, 0, err
	}
	consumed, err := s.queries.CountFriendlyNameCapacityConsumers(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("routes: count friendly name capacity: %w", err)
	}
	remaining := manifest.RemainingNamespaceCapacity - consumed
	if remaining < 0 {
		remaining = 0
	}
	return manifest.RemainingNamespaceCapacity, remaining, nil
}

func (s *Store) ListHostnameClaims(ctx context.Context, principalID string) ([]HostnameClaim, error) {
	var claims []HostnameClaim
	cursor := ""
	for {
		page, next, err := s.ListHostnameClaimsPage(ctx, principalID, cursor)
		if err != nil {
			return nil, err
		}
		claims = append(claims, page...)
		if next == "" {
			return claims, nil
		}
		cursor = next
	}
}

func (s *Store) ListHostnameClaimsPage(
	ctx context.Context,
	principalID, cursor string,
) ([]HostnameClaim, string, error) {
	dbClaims, err := s.queries.ListActiveClaimsPage(ctx, statedb.ListActiveClaimsPageParams{
		PrincipalID: principalID,
		Cursor:      cursor,
		Limit:       hostnameClaimPageSize + 1,
	})
	if err != nil {
		return nil, "", fmt.Errorf("routes: list hostname claims: %w", err)
	}
	var claims []HostnameClaim
	for _, claim := range dbClaims {
		claims = append(claims, hostnameClaimFromDB(claim))
	}
	if len(claims) <= hostnameClaimPageSize {
		return claims, "", nil
	}
	next := claims[hostnameClaimPageSize-1].ID
	return claims[:hostnameClaimPageSize], next, nil
}

func (s *Store) ActiveRouteIDForClaim(ctx context.Context, principalID, claimID string) (string, error) {
	routeIDs, err := s.ActiveRouteIDsForClaim(ctx, principalID, claimID)
	if err != nil {
		return "", err
	}
	if len(routeIDs) == 0 {
		return "", nil
	}
	return routeIDs[0], nil
}

func (s *Store) ActiveRouteIDsForClaim(ctx context.Context, principalID, claimID string) ([]string, error) {
	routes, err := s.queries.ListActiveRoutesForClaim(ctx, statedb.ListActiveRoutesForClaimParams{
		ClaimID:     claimID,
		PrincipalID: principalID,
	})
	if err != nil {
		return nil, fmt.Errorf("routes: find claim routes: %w", err)
	}
	result := make([]string, 0, len(routes))
	for _, routeID := range routes {
		if routeID.Valid {
			result = append(result, routeID.String)
		}
	}
	if len(routes) == 0 {
		return nil, ErrNotFound
	}
	return result, nil
}

func (s *Store) ReleaseHostnameClaim(ctx context.Context, principalID, claimID string) (err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationHostnameRelease, started, err) }()
	now := time.Unix(s.now().Unix(), 0).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin hostname release: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	claim, err := queries.GetClaimByID(ctx, claimID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && claim.PrincipalID != principalID {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("routes: read released hostname: %w", err)
	}
	var count int64
	switch claim.Kind {
	case NameKindPersistentManaged:
		count, err = queries.ReleasePersistentClaim(ctx, statedb.ReleasePersistentClaimParams{
			ReleasedAt: now.Unix(), ID: claimID, PrincipalID: principalID,
		})
	case NameKindPersistentCustom:
		count, err = queries.ReleaseCustomDomainClaim(ctx, statedb.ReleaseCustomDomainClaimParams{
			ReleasedAt: now.Unix(), ID: claimID, PrincipalID: principalID,
		})
	default:
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("routes: release hostname: %w", err)
	}
	if err := requireCount(count, ErrNotFound); err != nil {
		return err
	}
	if _, err := s.stopClaimRoutes(ctx, queries, claimID, now); err != nil {
		return err
	}
	if claim.Kind == NameKindPersistentCustom {
		if err := queries.InvalidateDomainChallengesForClaim(ctx, statedb.InvalidateDomainChallengesForClaimParams{
			InvalidatedAt: sql.NullInt64{Int64: now.Unix(), Valid: true}, Domain: claim.Hostname,
		}); err != nil {
			return fmt.Errorf("routes: invalidate released domain challenges: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit hostname release: %w", err)
	}
	return nil
}

func (s *Store) stopClaimRoutes(
	ctx context.Context,
	queries *statedb.Queries,
	claimID string,
	now time.Time,
) ([]string, error) {
	routes, err := queries.ListActiveClaimRouteGenerations(ctx, claimID)
	if err != nil {
		return nil, fmt.Errorf("routes: list stopped routes: %w", err)
	}
	if err := queries.DeleteClaimRoutes(ctx, statedb.DeleteClaimRoutesParams{DeletedAt: now.Unix(), ClaimID: claimID}); err != nil {
		return nil, fmt.Errorf("routes: delete stopped routes: %w", err)
	}
	if err := queries.RevokeClaimRouteCredentials(ctx, statedb.RevokeClaimRouteCredentialsParams{RevokedAt: now.Unix(), ClaimID: claimID}); err != nil {
		return nil, fmt.Errorf("routes: revoke stopped routes: %w", err)
	}
	if err := queries.ExpireClaimRouteLeases(ctx, claimID); err != nil {
		return nil, fmt.Errorf("routes: expire stopped routes: %w", err)
	}
	result := make([]string, 0, len(routes))
	for _, route := range routes {
		result = append(result, route.ID)
		generation := uint64(route.Generation)
		if err := s.recordLifecycle(ctx, queries, route.ID, generation, now, LifecycleDisconnected); err != nil {
			return nil, err
		}
		if err := s.recordLifecycle(ctx, queries, route.ID, generation, now, LifecycleDeleted); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s *Store) insertClaim(
	ctx context.Context,
	queries *statedb.Queries,
	principalID, label, kind, source string,
	now time.Time,
) (HostnameClaim, bool, error) {
	id, err := newID("claim")
	if err != nil {
		return HostnameClaim{}, false, err
	}
	hostname := label + "." + s.routeSuffix
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return HostnameClaim{}, false, ErrInvalidArgument
	}
	var count int64
	if kind == NameKindEphemeral {
		count, err = queries.InsertEphemeralClaim(ctx, statedb.InsertEphemeralClaimParams{
			ID: id, PrincipalID: principalID, Hostname: hostname, CreatedAt: now.Unix(),
		})
	} else if source == NameSourceGenerated {
		count, err = queries.InsertGeneratedPersistentClaim(ctx, statedb.InsertGeneratedPersistentClaimParams{
			ID: id, PrincipalID: principalID, Hostname: hostname, CreatedAt: now.Unix(),
		})
	} else {
		count, err = queries.InsertClaim(ctx, statedb.InsertClaimParams{
			ID: id, PrincipalID: principalID, Hostname: hostname, CreatedAt: now.Unix(),
		})
	}
	if err != nil {
		return HostnameClaim{}, false, fmt.Errorf("routes: insert hostname claim: %w", err)
	}
	if count == 0 {
		return HostnameClaim{}, false, nil
	}
	state := NameStateActive
	activatedAt := now
	if kind == NameKindEphemeral {
		state = NameStateHeld
		activatedAt = time.Time{}
	}
	return HostnameClaim{
		ID: id, PrincipalID: principalID, Hostname: hostname, Kind: kind, State: state,
		Source: source, CreatedAt: now, ActivatedAt: activatedAt,
	}, true, nil
}

func (s *Store) recordClaimRequest(
	ctx context.Context,
	queries *statedb.Queries,
	principalID, requestKey, requestedLabel, requestedKind, claimID string,
	now time.Time,
) error {
	requests, err := queries.CountClaimRequests(ctx, principalID)
	if err != nil {
		return fmt.Errorf("routes: count hostname claim requests: %w", err)
	}
	if requests >= int64(s.maxHostnameClaimRequests) {
		return ErrInvalidState
	}
	if err := queries.InsertClaimRequest(ctx, statedb.InsertClaimRequestParams{
		PrincipalID:    principalID,
		RequestKey:     requestKey,
		RequestedLabel: requestedLabel,
		RequestedKind:  requestedKind,
		ClaimID:        claimID,
		CreatedAt:      now.Unix(),
	}); err != nil {
		return fmt.Errorf("routes: record hostname claim request: %w", err)
	}
	return nil
}

func (s *Store) canonicalLabel(label string) (string, error) {
	if label == "" {
		return "", nil
	}
	canonical, err := naming.CanonicalizeHostname(label)
	if err != nil || strings.Contains(canonical, ".") {
		return "", ErrInvalidArgument
	}
	if _, reserved := s.reservedRouteNames[canonical]; reserved {
		return "", ErrNameUnavailable
	}
	return canonical, nil
}

func (s *Store) canonicalBaseName(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	canonical, err := naming.CanonicalizeHostname(name)
	if err != nil {
		return "", ErrInvalidArgument
	}
	if !strings.Contains(canonical, ".") {
		return s.canonicalLabel(canonical)
	}
	label, found := strings.CutSuffix(canonical, "."+s.routeSuffix)
	if !found || label == "" || strings.Contains(label, ".") {
		return "", ErrInvalidArgument
	}
	return s.canonicalLabel(label)
}

func (s *Store) canonicalHostname(hostname string) (string, error) {
	return s.canonicalRouteHostname(hostname)
}

func (s *Store) canonicalRouteHostname(hostname string) (string, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil {
		return "", err
	}
	return canonical, nil
}

func randomClaimLabel() (string, error) {
	return naming.FriendlyName()
}

func hostnameClaimFromDB(claim statedb.HostnameClaim) HostnameClaim {
	result := HostnameClaim{
		ID:          claim.ID,
		PrincipalID: claim.PrincipalID,
		Hostname:    claim.Hostname,
		Kind:        claim.Kind,
		State:       claim.State,
		Source:      claim.Source,
		CreatedAt:   time.Unix(claim.CreatedAt, 0).UTC(),
	}
	if claim.ActivatedAt.Valid {
		result.ActivatedAt = time.Unix(claim.ActivatedAt.Int64, 0).UTC()
	}
	if claim.ReleasedAt.Valid {
		result.ReleasedAt = time.Unix(claim.ReleasedAt.Int64, 0).UTC()
	}
	return result
}

func readClaimByHostname(ctx context.Context, queries *statedb.Queries, hostname string) (HostnameClaim, error) {
	claim, err := queries.GetClaimByHostname(ctx, hostname)
	if err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: scan hostname claim: %w", err)
	}
	return hostnameClaimFromDB(claim), nil
}

func readClaimRequest(
	ctx context.Context,
	queries *statedb.Queries,
	principalID, requestKey string,
) (HostnameClaim, string, string, bool, error) {
	request, err := queries.GetClaimRequest(ctx, statedb.GetClaimRequestParams{
		PrincipalID: principalID,
		RequestKey:  requestKey,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return HostnameClaim{}, "", "", false, nil
	}
	if err != nil {
		return HostnameClaim{}, "", "", false, fmt.Errorf("routes: read hostname claim request: %w", err)
	}
	return hostnameClaimFromDB(request.HostnameClaim), request.RequestedLabel, request.RequestedKind, true, nil
}
