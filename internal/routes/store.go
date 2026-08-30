package routes

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/naming"
)

const LeaseLifetime = 45 * time.Second

var (
	ErrNameUnavailable = errors.New("routes: name unavailable")
	ErrRouteExists     = errors.New("routes: route already exists")
	ErrNotFound        = errors.New("routes: not found")
	ErrUnauthenticated = errors.New("routes: unauthenticated")
	ErrStaleLease      = errors.New("routes: stale lease")
	ErrInvalidState    = errors.New("routes: invalid state")
)

type Route struct {
	ID            string
	PrincipalID   string
	Hostname      string
	DisplayTarget string
	State         string
	Generation    uint64
	CreatedAt     time.Time
}

type Lease struct {
	ID              string
	RouteID         string
	Generation      uint64
	Status          string
	BootEpoch       string
	ServerPublicKey string
	RelayProfile    string
	CreatedAt       time.Time
	LastHeartbeat   time.Time
	ExpiresAt       time.Time
}

type Provisioning struct {
	Route      Route
	Lease      Lease
	LeaseToken credentials.LeaseToken
}

type Store struct {
	db            *sql.DB
	now           func() time.Time
	leaseLifetime time.Duration
}

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("routes: nil state database")
	}
	return &Store{db: db, now: time.Now, leaseLifetime: LeaseLifetime}, nil
}

func (s *Store) Create(
	ctx context.Context,
	principalID, hostname, displayTarget, bootEpoch string,
	routeToken credentials.RouteToken,
) (Provisioning, error) {
	hostname, err := naming.CanonicalizeHostname(hostname)
	if err != nil {
		return Provisioning{}, err
	}
	if strings.TrimSpace(principalID) == "" || strings.TrimSpace(displayTarget) == "" || strings.TrimSpace(bootEpoch) == "" {
		return Provisioning{}, errors.New("routes: principal, target, and boot epoch are required")
	}

	routeCredentialID, routeHash, err := credentials.ParseRouteToken(routeToken)
	if err != nil {
		return Provisioning{}, ErrUnauthenticated
	}
	leaseToken, leaseCredentialID, leaseHash, err := credentials.NewLeaseToken()
	if err != nil {
		return Provisioning{}, err
	}
	claimID, err := newID("claim")
	if err != nil {
		return Provisioning{}, err
	}
	routeID, err := newID("route")
	if err != nil {
		return Provisioning{}, err
	}
	leaseID, err := newID("lease")
	if err != nil {
		return Provisioning{}, err
	}
	now := time.Unix(s.now().Unix(), 0).UTC()
	expiresAt := now.Add(s.leaseLifetime)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Provisioning{}, fmt.Errorf("routes: begin create: %w", err)
	}
	defer tx.Rollback()
	// Claims remain bound to their principal after route deletion.
	if _, err := tx.ExecContext(ctx, `INSERT INTO hostname_claims
		(id, principal_id, hostname, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (hostname) DO NOTHING`, claimID, principalID, hostname, now.Unix()); err != nil {
		return Provisioning{}, fmt.Errorf("routes: claim hostname: %w", err)
	}
	var claimPrincipal string
	if err := tx.QueryRowContext(ctx,
		`SELECT id, principal_id FROM hostname_claims WHERE hostname = ?`, hostname,
	).Scan(&claimID, &claimPrincipal); err != nil {
		return Provisioning{}, fmt.Errorf("routes: read hostname claim: %w", err)
	}
	if claimPrincipal != principalID {
		return Provisioning{}, ErrNameUnavailable
	}
	var existing Route
	var existingCreatedAt int64
	err = tx.QueryRowContext(ctx, `SELECT
		id, principal_id, hostname, display_target, state, generation, created_at
		FROM routes WHERE claim_id = ? AND state = 'active'`, claimID).Scan(
		&existing.ID, &existing.PrincipalID, &existing.Hostname, &existing.DisplayTarget,
		&existing.State, &existing.Generation, &existingCreatedAt,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Provisioning{}, fmt.Errorf("routes: check existing route: %w", err)
	}
	if err == nil {
		// Recreate in place, rotating credentials and fencing the old agent.
		generation := existing.Generation + 1
		result, err := tx.ExecContext(ctx, `UPDATE route_credentials
			SET id = ?, secret_hash = ?, created_at = ?, revoked_at = NULL WHERE route_id = ?`,
			routeCredentialID.String(), routeHash[:], now.Unix(), existing.ID)
		if err != nil {
			return Provisioning{}, fmt.Errorf("routes: rotate route credential: %w", err)
		}
		if err := requireUpdated(result, ErrInvalidState); err != nil {
			return Provisioning{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE route_leases SET status = 'expired'
			WHERE route_id = ? AND status != 'expired'`, existing.ID); err != nil {
			return Provisioning{}, fmt.Errorf("routes: expire replaced lease: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE routes SET display_target = ?, generation = ? WHERE id = ?`,
			displayTarget, generation, existing.ID); err != nil {
			return Provisioning{}, fmt.Errorf("routes: advance replaced route: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO route_leases
			(id, route_id, generation, status, credential_id, secret_hash, boot_epoch, created_at, last_heartbeat, expires_at)
			VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)`,
			leaseID, existing.ID, generation, leaseCredentialID.String(), leaseHash[:], bootEpoch,
			now.Unix(), now.Unix(), expiresAt.Unix()); err != nil {
			return Provisioning{}, fmt.Errorf("routes: create replacement lease: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return Provisioning{}, fmt.Errorf("routes: commit route replacement: %w", err)
		}
		existing.DisplayTarget = displayTarget
		existing.Generation = generation
		existing.CreatedAt = time.Unix(existingCreatedAt, 0).UTC()
		return Provisioning{
			Route: existing,
			Lease: Lease{
				ID: leaseID, RouteID: existing.ID, Generation: generation, Status: "pending",
				BootEpoch: bootEpoch, CreatedAt: now, LastHeartbeat: now, ExpiresAt: expiresAt,
			},
			LeaseToken: leaseToken,
		}, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO routes
		(id, claim_id, principal_id, hostname, display_target, state, generation, created_at)
		VALUES (?, ?, ?, ?, ?, 'active', 1, ?)`,
		routeID, claimID, principalID, hostname, displayTarget, now.Unix()); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create route: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO route_credentials
		(id, route_id, secret_hash, created_at) VALUES (?, ?, ?, ?)`,
		routeCredentialID.String(), routeID, routeHash[:], now.Unix()); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create route credential: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO route_leases
		(id, route_id, generation, status, credential_id, secret_hash, boot_epoch, created_at, last_heartbeat, expires_at)
		VALUES (?, ?, 1, 'pending', ?, ?, ?, ?, ?, ?)`,
		leaseID, routeID, leaseCredentialID.String(), leaseHash[:], bootEpoch,
		now.Unix(), now.Unix(), expiresAt.Unix()); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create lease: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Provisioning{}, fmt.Errorf("routes: commit create: %w", err)
	}
	return Provisioning{
		Route:      Route{ID: routeID, PrincipalID: principalID, Hostname: hostname, DisplayTarget: displayTarget, State: "active", Generation: 1, CreatedAt: now},
		Lease:      Lease{ID: leaseID, RouteID: routeID, Generation: 1, Status: "pending", BootEpoch: bootEpoch, CreatedAt: now, LastHeartbeat: now, ExpiresAt: expiresAt},
		LeaseToken: leaseToken,
	}, nil
}

func (s *Store) Acquire(
	ctx context.Context,
	principalID, routeID, bootEpoch string,
	routeToken credentials.RouteToken,
) (Provisioning, error) {
	credentialID, candidate, err := credentials.ParseRouteToken(routeToken)
	if err != nil {
		return Provisioning{}, ErrUnauthenticated
	}
	leaseToken, leaseCredentialID, leaseHash, err := credentials.NewLeaseToken()
	if err != nil {
		return Provisioning{}, err
	}
	leaseID, err := newID("lease")
	if err != nil {
		return Provisioning{}, err
	}
	now := time.Unix(s.now().Unix(), 0).UTC()
	expiresAt := now.Add(s.leaseLifetime)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Provisioning{}, fmt.Errorf("routes: begin acquire: %w", err)
	}
	defer tx.Rollback()
	route, storedHash, revoked, err := readRouteCredential(ctx, tx, routeID, credentialID)
	if err != nil {
		return Provisioning{}, err
	}
	if route.PrincipalID != principalID || revoked || !credentials.SecretHashMatches(storedHash, candidate) {
		return Provisioning{}, ErrUnauthenticated
	}
	if route.State != "active" {
		return Provisioning{}, ErrInvalidState
	}
	generation := route.Generation + 1
	if _, err := tx.ExecContext(ctx, `UPDATE route_leases SET status = 'expired'
		WHERE route_id = ? AND status != 'expired'`, routeID); err != nil {
		return Provisioning{}, fmt.Errorf("routes: expire previous lease: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE routes SET generation = ? WHERE id = ?`, generation, routeID); err != nil {
		return Provisioning{}, fmt.Errorf("routes: advance generation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO route_leases
		(id, route_id, generation, status, credential_id, secret_hash, boot_epoch, created_at, last_heartbeat, expires_at)
		VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)`,
		leaseID, routeID, generation, leaseCredentialID.String(), leaseHash[:], bootEpoch,
		now.Unix(), now.Unix(), expiresAt.Unix()); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create replacement lease: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Provisioning{}, fmt.Errorf("routes: commit acquire: %w", err)
	}
	route.Generation = generation
	return Provisioning{
		Route:      route,
		Lease:      Lease{ID: leaseID, RouteID: routeID, Generation: generation, Status: "pending", BootEpoch: bootEpoch, CreatedAt: now, LastHeartbeat: now, ExpiresAt: expiresAt},
		LeaseToken: leaseToken,
	}, nil
}

func (s *Store) AuthorizeRoute(
	ctx context.Context,
	principalID, routeID string,
	token credentials.RouteToken,
) (Route, error) {
	credentialID, candidate, err := credentials.ParseRouteToken(token)
	if err != nil {
		return Route{}, ErrUnauthenticated
	}
	route, storedHash, revoked, err := readRouteCredential(ctx, s.db, routeID, credentialID)
	if err != nil {
		return Route{}, err
	}
	if route.PrincipalID != principalID || revoked || !credentials.SecretHashMatches(storedHash, candidate) {
		return Route{}, ErrUnauthenticated
	}
	if route.State != "active" {
		return Route{}, ErrInvalidState
	}
	return route, nil
}

func (s *Store) AuthorizePrincipal(ctx context.Context, principalID, routeID string) error {
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM routes
		WHERE id = ? AND principal_id = ? AND state = 'active'`, routeID, principalID).Scan(&exists); err != nil {
		return fmt.Errorf("routes: authorize principal: %w", err)
	}
	if exists == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ActiveRouteID(ctx context.Context, principalID, hostname string) (string, error) {
	hostname, err := naming.CanonicalizeHostname(hostname)
	if err != nil {
		return "", err
	}
	var routeID string
	err = s.db.QueryRowContext(ctx, `SELECT id FROM routes
		WHERE principal_id = ? AND hostname = ? AND state = 'active'`, principalID, hostname).Scan(&routeID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("routes: find active route: %w", err)
	}
	return routeID, nil
}

func (s *Store) AuthenticateLease(
	ctx context.Context,
	routeID string,
	generation uint64,
	token credentials.LeaseToken,
	bootEpoch string,
) (Lease, error) {
	credentialID, candidate, err := credentials.ParseLeaseToken(token)
	if err != nil {
		return Lease{}, ErrUnauthenticated
	}
	var lease Lease
	var storedHash []byte
	var createdAt, lastHeartbeat, expiresAt int64
	var serverPublicKey, relayProfile sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT
		l.id, l.route_id, l.generation, l.status, l.boot_epoch,
		l.server_public_key, l.relay_profile, l.secret_hash,
		l.created_at, l.last_heartbeat, l.expires_at
		FROM route_leases l
		JOIN routes r ON r.id = l.route_id
		WHERE l.route_id = ? AND l.generation = ? AND l.credential_id = ?
		AND r.state = 'active' AND r.generation = l.generation`,
		routeID, generation, credentialID.String()).Scan(
		&lease.ID, &lease.RouteID, &lease.Generation, &lease.Status, &lease.BootEpoch,
		&serverPublicKey, &relayProfile, &storedHash, &createdAt, &lastHeartbeat, &expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		// Known credentials are stale; unknown IDs remain unauthenticated.
		var known int
		knownErr := s.db.QueryRowContext(
			ctx, `SELECT 1 FROM route_leases WHERE credential_id = ?`, credentialID.String(),
		).Scan(&known)
		if errors.Is(knownErr, sql.ErrNoRows) {
			return Lease{}, ErrUnauthenticated
		}
		if knownErr != nil {
			return Lease{}, fmt.Errorf("routes: identify lease credential: %w", knownErr)
		}
		return Lease{}, ErrStaleLease
	}
	if err != nil {
		return Lease{}, fmt.Errorf("routes: read lease: %w", err)
	}
	now := s.now()
	if lease.BootEpoch != bootEpoch || lease.Status == "expired" || now.Unix() >= expiresAt {
		return Lease{}, ErrStaleLease
	}
	if !credentials.SecretHashMatches(storedHash, candidate) {
		return Lease{}, ErrUnauthenticated
	}
	lease.ServerPublicKey = serverPublicKey.String
	lease.RelayProfile = relayProfile.String
	lease.CreatedAt = time.Unix(createdAt, 0).UTC()
	lease.LastHeartbeat = time.Unix(lastHeartbeat, 0).UTC()
	lease.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	return lease, nil
}

func (s *Store) RegisterTransport(
	ctx context.Context,
	lease Lease,
	serverPublicKey, relayProfile string,
) error {
	if strings.TrimSpace(serverPublicKey) == "" || strings.TrimSpace(relayProfile) == "" {
		return errors.New("routes: transport descriptor is incomplete")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE route_leases
		SET server_public_key = ?, relay_profile = ?, status = 'starting'
		WHERE id = ? AND route_id = ? AND generation = ? AND status IN ('pending', 'starting')`,
		serverPublicKey, relayProfile, lease.ID, lease.RouteID, lease.Generation)
	if err != nil {
		return fmt.Errorf("routes: register transport: %w", err)
	}
	return requireUpdated(result, ErrStaleLease)
}

func (s *Store) Ready(ctx context.Context, lease Lease) error {
	result, err := s.db.ExecContext(ctx, `UPDATE route_leases SET status = 'ready'
		WHERE id = ? AND route_id = ? AND generation = ? AND status IN ('starting', 'ready')`,
		lease.ID, lease.RouteID, lease.Generation)
	if err != nil {
		return fmt.Errorf("routes: mark ready: %w", err)
	}
	return requireUpdated(result, ErrInvalidState)
}

func (s *Store) Heartbeat(ctx context.Context, lease Lease) (time.Time, error) {
	now := time.Unix(s.now().Unix(), 0).UTC()
	expiresAt := now.Add(s.leaseLifetime)
	result, err := s.db.ExecContext(ctx, `UPDATE route_leases
		SET last_heartbeat = ?, expires_at = ?
		WHERE id = ? AND route_id = ? AND generation = ? AND status != 'expired'`,
		now.Unix(), expiresAt.Unix(), lease.ID, lease.RouteID, lease.Generation)
	if err != nil {
		return time.Time{}, fmt.Errorf("routes: heartbeat: %w", err)
	}
	if err := requireUpdated(result, ErrStaleLease); err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}

func (s *Store) InvalidateOtherBoots(ctx context.Context, bootEpoch string) error {
	if strings.TrimSpace(bootEpoch) == "" {
		return errors.New("routes: boot epoch is required")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE route_leases SET status = 'expired'
		WHERE boot_epoch != ? AND status != 'expired'`, bootEpoch); err != nil {
		return fmt.Errorf("routes: invalidate old boot leases: %w", err)
	}
	return nil
}

func (s *Store) Expire(ctx context.Context, routeID string, generation uint64) error {
	result, err := s.db.ExecContext(ctx, `UPDATE route_leases SET status = 'expired'
		WHERE route_id = ? AND generation = ? AND status != 'expired'`, routeID, generation)
	if err != nil {
		return fmt.Errorf("routes: expire lease: %w", err)
	}
	return requireUpdated(result, ErrStaleLease)
}

func (s *Store) List(ctx context.Context, principalID string) ([]Route, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		id, principal_id, hostname, display_target, state, generation, created_at
		FROM routes WHERE principal_id = ? AND state = 'active' ORDER BY created_at, id`, principalID)
	if err != nil {
		return nil, fmt.Errorf("routes: list: %w", err)
	}
	defer rows.Close()
	var result []Route
	for rows.Next() {
		var route Route
		var createdAt int64
		if err := rows.Scan(&route.ID, &route.PrincipalID, &route.Hostname, &route.DisplayTarget, &route.State, &route.Generation, &createdAt); err != nil {
			return nil, fmt.Errorf("routes: scan list: %w", err)
		}
		route.CreatedAt = time.Unix(createdAt, 0).UTC()
		result = append(result, route)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("routes: list rows: %w", err)
	}
	return result, nil
}

func (s *Store) Delete(ctx context.Context, principalID, routeID string) error {
	now := time.Unix(s.now().Unix(), 0).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin delete: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE routes SET state = 'deleted', deleted_at = ?
		WHERE id = ? AND principal_id = ? AND state = 'active'`, now.Unix(), routeID, principalID)
	if err != nil {
		return fmt.Errorf("routes: delete: %w", err)
	}
	if err := requireUpdated(result, ErrNotFound); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE route_credentials SET revoked_at = COALESCE(revoked_at, ?)
		WHERE route_id = ?`, now.Unix(), routeID); err != nil {
		return fmt.Errorf("routes: revoke route credential: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE route_leases SET status = 'expired'
		WHERE route_id = ? AND status != 'expired'`, routeID); err != nil {
		return fmt.Errorf("routes: expire deleted route: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit delete: %w", err)
	}
	return nil
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readRouteCredential(
	ctx context.Context,
	query queryRower,
	routeID string,
	credentialID credentials.CredentialID,
) (Route, []byte, bool, error) {
	var route Route
	var storedHash []byte
	var createdAt int64
	var revokedAt sql.NullInt64
	err := query.QueryRowContext(ctx, `SELECT
		r.id, r.principal_id, r.hostname, r.display_target, r.state, r.generation, r.created_at,
		c.secret_hash, c.revoked_at
		FROM routes r JOIN route_credentials c ON c.route_id = r.id
		WHERE r.id = ? AND c.id = ?`, routeID, credentialID.String()).Scan(
		&route.ID, &route.PrincipalID, &route.Hostname, &route.DisplayTarget, &route.State,
		&route.Generation, &createdAt, &storedHash, &revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Route{}, nil, false, ErrUnauthenticated
	}
	if err != nil {
		return Route{}, nil, false, fmt.Errorf("routes: read route credential: %w", err)
	}
	route.CreatedAt = time.Unix(createdAt, 0).UTC()
	return route, storedHash, revokedAt.Valid, nil
}

func requireUpdated(result sql.Result, missing error) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return missing
	}
	return nil
}

func newID(prefix string) (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("routes: generate %s ID: %w", prefix, err)
	}
	return prefix + "_" + hex.EncodeToString(material[:]), nil
}
