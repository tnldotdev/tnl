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

	// Resolve request-key replays before quota checks or allocation.
	claim, requestedLabel, found, err := readClaimRequest(ctx, tx, principalID, requestKey)
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
		claim, err = readClaimByHostname(ctx, tx, canonicalLabel+"."+s.routeSuffix)
		if err == nil {
			if claim.PrincipalID != principalID || !claim.TombstonedAt.IsZero() {
				return HostnameClaim{}, ErrNameUnavailable
			}
			if err := s.recordClaimRequest(ctx, tx, principalID, requestKey, canonicalLabel, claim.ID, now); err != nil {
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
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM hostname_claims
		WHERE principal_id = ? AND tombstoned_at IS NULL`, principalID).Scan(&active); err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: count hostname claims: %w", err)
	}
	if active >= s.maxActiveHostnameClaims {
		return HostnameClaim{}, ErrInvalidState
	}

	if canonicalLabel == "" {
		// Let the unique index arbitrate collisions and retry with fresh entropy.
		for range randomClaimAttempts {
			candidate, candidateErr := randomClaimLabel()
			if candidateErr != nil {
				return HostnameClaim{}, candidateErr
			}
			claim, found, err = s.insertClaim(ctx, tx, principalID, candidate, now)
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
		claim, found, err = s.insertClaim(ctx, tx, principalID, canonicalLabel, now)
		if err != nil {
			return HostnameClaim{}, err
		}
		if !found {
			claim, err = readClaimByHostname(ctx, tx, canonicalLabel+"."+s.routeSuffix)
			if err != nil {
				return HostnameClaim{}, err
			}
			if claim.PrincipalID != principalID || !claim.TombstonedAt.IsZero() {
				return HostnameClaim{}, ErrNameUnavailable
			}
		}
	}
	if err := s.recordClaimRequest(ctx, tx, principalID, requestKey, canonicalLabel, claim.ID, now); err != nil {
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
	rows, err := s.db.QueryContext(ctx, `SELECT id, principal_id, hostname, irreversible, tombstoned_at, created_at
		FROM hostname_claims WHERE principal_id = ? AND tombstoned_at IS NULL AND (? = '' OR id > ?)
		ORDER BY id LIMIT ?`, principalID, cursor, cursor, hostnameClaimPageSize+1)
	if err != nil {
		return nil, "", fmt.Errorf("routes: list hostname claims: %w", err)
	}
	defer rows.Close()
	var claims []HostnameClaim
	for rows.Next() {
		claim, err := scanClaim(rows)
		if err != nil {
			return nil, "", err
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("routes: list hostname claims: %w", err)
	}
	if len(claims) <= hostnameClaimPageSize {
		return claims, "", nil
	}
	next := claims[hostnameClaimPageSize-1].ID
	return claims[:hostnameClaimPageSize], next, nil
}

func (s *Store) ActiveRouteIDForClaim(ctx context.Context, principalID, claimID string) (string, error) {
	var routeID sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT r.id FROM hostname_claims c
		LEFT JOIN routes r ON r.claim_id = c.id AND r.state = 'active'
		WHERE c.id = ? AND c.principal_id = ? AND c.tombstoned_at IS NULL`, claimID, principalID).Scan(&routeID)
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
	// Tombstone the claim and revoke all route authority in one transaction.
	result, err := tx.ExecContext(ctx, `UPDATE hostname_claims SET tombstoned_at = ?
		WHERE id = ? AND principal_id = ? AND tombstoned_at IS NULL`, now.Unix(), claimID, principalID)
	if err != nil {
		return fmt.Errorf("routes: release hostname: %w", err)
	}
	if err := requireUpdated(result, ErrNotFound); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE routes SET state = 'deleted', deleted_at = ?
		WHERE claim_id = ? AND state = 'active'`, now.Unix(), claimID); err != nil {
		return fmt.Errorf("routes: delete released routes: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE route_credentials SET revoked_at = COALESCE(revoked_at, ?)
		WHERE route_id IN (SELECT id FROM routes WHERE claim_id = ?)`, now.Unix(), claimID); err != nil {
		return fmt.Errorf("routes: revoke released routes: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE route_leases SET status = 'expired'
		WHERE route_id IN (SELECT id FROM routes WHERE claim_id = ?) AND status != 'expired'`, claimID); err != nil {
		return fmt.Errorf("routes: expire released routes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit hostname release: %w", err)
	}
	return nil
}

func (s *Store) insertClaim(
	ctx context.Context,
	tx *sql.Tx,
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
	result, err := tx.ExecContext(ctx, `INSERT INTO hostname_claims
		(id, principal_id, hostname, irreversible, created_at) VALUES (?, ?, ?, 0, ?)
		ON CONFLICT (hostname) DO NOTHING`, id, principalID, hostname, now.Unix())
	if err != nil {
		return HostnameClaim{}, false, fmt.Errorf("routes: insert hostname claim: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return HostnameClaim{}, false, err
	}
	if count == 0 {
		return HostnameClaim{}, false, nil
	}
	return HostnameClaim{ID: id, PrincipalID: principalID, Hostname: hostname, CreatedAt: now}, true, nil
}

func (s *Store) recordClaimRequest(
	ctx context.Context,
	tx *sql.Tx,
	principalID, requestKey, requestedLabel, claimID string,
	now time.Time,
) error {
	var requests int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM hostname_claim_requests
		WHERE principal_id = ?`, principalID).Scan(&requests); err != nil {
		return fmt.Errorf("routes: count hostname claim requests: %w", err)
	}
	if requests >= s.maxHostnameClaimRequests {
		return ErrInvalidState
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO hostname_claim_requests
		(principal_id, request_key, requested_label, claim_id, created_at) VALUES (?, ?, ?, ?, ?)`,
		principalID, requestKey, requestedLabel, claimID, now.Unix()); err != nil {
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

type claimScanner interface {
	Scan(...any) error
}

func scanClaim(row claimScanner) (HostnameClaim, error) {
	var claim HostnameClaim
	var irreversible int
	var tombstonedAt sql.NullInt64
	var createdAt int64
	if err := row.Scan(&claim.ID, &claim.PrincipalID, &claim.Hostname, &irreversible, &tombstonedAt, &createdAt); err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: scan hostname claim: %w", err)
	}
	claim.Irreversible = irreversible != 0
	claim.CreatedAt = time.Unix(createdAt, 0).UTC()
	if tombstonedAt.Valid {
		claim.TombstonedAt = time.Unix(tombstonedAt.Int64, 0).UTC()
	}
	return claim, nil
}

func readClaimByHostname(ctx context.Context, tx *sql.Tx, hostname string) (HostnameClaim, error) {
	return scanClaim(tx.QueryRowContext(ctx, `SELECT
		id, principal_id, hostname, irreversible, tombstoned_at, created_at
		FROM hostname_claims WHERE hostname = ?`, hostname))
}

func readClaimRequest(
	ctx context.Context,
	tx *sql.Tx,
	principalID, requestKey string,
) (HostnameClaim, string, bool, error) {
	var claim HostnameClaim
	var requestedLabel string
	var irreversible int
	var tombstonedAt sql.NullInt64
	var createdAt int64
	err := tx.QueryRowContext(ctx, `SELECT
		c.id, c.principal_id, c.hostname, c.irreversible, c.tombstoned_at, c.created_at, r.requested_label
		FROM hostname_claim_requests r JOIN hostname_claims c ON c.id = r.claim_id
		WHERE r.principal_id = ? AND r.request_key = ?`, principalID, requestKey).Scan(
		&claim.ID, &claim.PrincipalID, &claim.Hostname, &irreversible, &tombstonedAt, &createdAt, &requestedLabel,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return HostnameClaim{}, "", false, nil
	}
	if err != nil {
		return HostnameClaim{}, "", false, fmt.Errorf("routes: read hostname claim request: %w", err)
	}
	claim.Irreversible = irreversible != 0
	claim.CreatedAt = time.Unix(createdAt, 0).UTC()
	if tombstonedAt.Valid {
		claim.TombstonedAt = time.Unix(tombstonedAt.Int64, 0).UTC()
	}
	return claim, requestedLabel, true, nil
}
