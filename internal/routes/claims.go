package routes

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/naming"
	"github.com/0xcadams/tnl/internal/state/statedb"
)

const (
	hostnameClaimPageSize   = 100
	randomClaimAttempts     = 16
	randomClaimMaterialSize = 10
)

var reservedClaimLabels = map[string]struct{}{
	"account":  {},
	"accounts": {},
	"control":  {},
	"dns":      {},
	"health":   {},
	"mail":     {},
	"metrics":  {},
}

type HostnameClaim struct {
	ID           string
	PrincipalID  string
	Hostname     string
	Irreversible bool
	TombstonedAt time.Time
	CreatedAt    time.Time
}

func (s *Store) ClaimHostname(
	ctx context.Context,
	principalID, label, requestKey string,
) (claim HostnameClaim, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationHostnameClaim, started, err) }()
	if strings.TrimSpace(principalID) == "" || strings.TrimSpace(requestKey) != requestKey ||
		requestKey == "" || len(requestKey) > 128 {
		return HostnameClaim{}, ErrInvalidArgument
	}
	canonicalLabel, err := s.canonicalLabel(label)
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
	claim, requestedLabel, found, err := readClaimRequest(ctx, queries, principalID, requestKey)
	if err != nil {
		return HostnameClaim{}, err
	}
	if found {
		if requestedLabel != canonicalLabel || !claim.TombstonedAt.IsZero() {
			return HostnameClaim{}, ErrInvalidState
		}
		return claim, nil
	}
	if canonicalLabel != "" {
		claim, err = readClaimByHostname(ctx, queries, canonicalLabel+"."+s.routeSuffix)
		if err == nil {
			if claim.PrincipalID != principalID || !claim.TombstonedAt.IsZero() {
				return HostnameClaim{}, ErrNameUnavailable
			}
			if err := s.recordClaimRequest(ctx, queries, principalID, requestKey, canonicalLabel, claim.ID, now); err != nil {
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
	active, err := queries.CountActiveClaims(ctx, principalID)
	if err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: count hostname claims: %w", err)
	}
	if active >= int64(s.maxActiveHostnameClaims) {
		return HostnameClaim{}, ErrInvalidState
	}

	if canonicalLabel == "" {
		// Let the unique index arbitrate collisions and retry with fresh entropy.
		for range randomClaimAttempts {
			candidate, candidateErr := randomClaimLabel()
			if candidateErr != nil {
				return HostnameClaim{}, candidateErr
			}
			claim, found, err = s.insertClaim(ctx, queries, principalID, candidate, now)
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
		claim, found, err = s.insertClaim(ctx, queries, principalID, canonicalLabel, now)
		if err != nil {
			return HostnameClaim{}, err
		}
		if !found {
			claim, err = readClaimByHostname(ctx, queries, canonicalLabel+"."+s.routeSuffix)
			if err != nil {
				return HostnameClaim{}, err
			}
			if claim.PrincipalID != principalID || !claim.TombstonedAt.IsZero() {
				return HostnameClaim{}, ErrNameUnavailable
			}
		}
	}
	if err := s.recordClaimRequest(ctx, queries, principalID, requestKey, canonicalLabel, claim.ID, now); err != nil {
		return HostnameClaim{}, err
	}
	if err := tx.Commit(); err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: commit hostname claim: %w", err)
	}
	return claim, nil
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
	routeID, err := s.queries.GetActiveRouteForClaim(ctx, statedb.GetActiveRouteForClaimParams{
		ClaimID:     claimID,
		PrincipalID: principalID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("routes: find claim route: %w", err)
	}
	return routeID.String, nil
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
	// Tombstone the claim and revoke all route authority in one transaction.
	count, err := queries.TombstoneClaim(ctx, statedb.TombstoneClaimParams{
		TombstonedAt: now.Unix(),
		ID:           claimID,
		PrincipalID:  principalID,
	})
	if err != nil {
		return fmt.Errorf("routes: release hostname: %w", err)
	}
	if err := requireCount(count, ErrNotFound); err != nil {
		return err
	}
	if err := queries.DeleteClaimRoutes(ctx, statedb.DeleteClaimRoutesParams{
		DeletedAt: now.Unix(),
		ClaimID:   claimID,
	}); err != nil {
		return fmt.Errorf("routes: delete released routes: %w", err)
	}
	if err := queries.RevokeClaimRouteCredentials(ctx, statedb.RevokeClaimRouteCredentialsParams{
		RevokedAt: now.Unix(),
		ClaimID:   claimID,
	}); err != nil {
		return fmt.Errorf("routes: revoke released routes: %w", err)
	}
	if err := queries.ExpireClaimRouteLeases(ctx, claimID); err != nil {
		return fmt.Errorf("routes: expire released routes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit hostname release: %w", err)
	}
	return nil
}

func (s *Store) insertClaim(
	ctx context.Context,
	queries *statedb.Queries,
	principalID, label string,
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
	count, err := queries.InsertClaim(ctx, statedb.InsertClaimParams{
		ID:          id,
		PrincipalID: principalID,
		Hostname:    hostname,
		CreatedAt:   now.Unix(),
	})
	if err != nil {
		return HostnameClaim{}, false, fmt.Errorf("routes: insert hostname claim: %w", err)
	}
	if count == 0 {
		return HostnameClaim{}, false, nil
	}
	return HostnameClaim{ID: id, PrincipalID: principalID, Hostname: hostname, CreatedAt: now}, true, nil
}

func (s *Store) recordClaimRequest(
	ctx context.Context,
	queries *statedb.Queries,
	principalID, requestKey, requestedLabel, claimID string,
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
	if _, reserved := reservedClaimLabels[canonical]; reserved {
		return "", ErrNameUnavailable
	}
	return canonical, nil
}

func (s *Store) canonicalHostname(hostname string) (string, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil {
		return "", err
	}
	suffix := "." + s.routeSuffix
	if !strings.HasSuffix(canonical, suffix) {
		return "", ErrNameUnavailable
	}
	label := strings.TrimSuffix(canonical, suffix)
	if _, err := s.canonicalLabel(label); err != nil {
		return "", err
	}
	return canonical, nil
}

func randomClaimLabel() (string, error) {
	var material [randomClaimMaterialSize]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("routes: generate hostname label: %w", err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(material[:])), nil
}

func hostnameClaimFromDB(claim statedb.HostnameClaim) HostnameClaim {
	result := HostnameClaim{
		ID:           claim.ID,
		PrincipalID:  claim.PrincipalID,
		Hostname:     claim.Hostname,
		Irreversible: claim.Irreversible != 0,
		CreatedAt:    time.Unix(claim.CreatedAt, 0).UTC(),
	}
	if claim.TombstonedAt.Valid {
		result.TombstonedAt = time.Unix(claim.TombstonedAt.Int64, 0).UTC()
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
) (HostnameClaim, string, bool, error) {
	request, err := queries.GetClaimRequest(ctx, statedb.GetClaimRequestParams{
		PrincipalID: principalID,
		RequestKey:  requestKey,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return HostnameClaim{}, "", false, nil
	}
	if err != nil {
		return HostnameClaim{}, "", false, fmt.Errorf("routes: read hostname claim request: %w", err)
	}
	return hostnameClaimFromDB(request.HostnameClaim), request.RequestedLabel, true, nil
}
