package routes

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/naming"
	"github.com/0xcadams/tnl/internal/state/statedb"
)

const (
	LeaseLifetime                   = 45 * time.Second
	DefaultMaxActiveHostnameClaims  = 128
	DefaultMaxHostnameClaimRequests = 1024
	maximumHostnameClaimQuota       = 100_000
)

var (
	ErrNameUnavailable = errors.New("routes: name unavailable")
	ErrInvalidArgument = errors.New("routes: invalid argument")
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

type StoreConfig struct {
	MaxActiveHostnameClaims  int
	MaxHostnameClaimRequests int
	ObserveOperation         StoreObserver
	LifecycleRecorder        LifecycleRecorder
}

type Store struct {
	db                       *sql.DB
	queries                  *statedb.Queries
	routeSuffix              string
	now                      func() time.Time
	leaseLifetime            time.Duration
	maxActiveHostnameClaims  int
	maxHostnameClaimRequests int
	observeOperation         StoreObserver
	lifecycleRecorder        LifecycleRecorder
}

func NewStore(db *sql.DB, routeSuffix string, configs ...StoreConfig) (*Store, error) {
	if db == nil {
		return nil, errors.New("routes: nil state database")
	}
	if len(configs) > 1 {
		return nil, errors.New("routes: multiple store configurations")
	}
	config := StoreConfig{
		MaxActiveHostnameClaims:  DefaultMaxActiveHostnameClaims,
		MaxHostnameClaimRequests: DefaultMaxHostnameClaimRequests,
	}
	if len(configs) == 1 {
		config = configs[0]
		if config.MaxActiveHostnameClaims == 0 {
			config.MaxActiveHostnameClaims = DefaultMaxActiveHostnameClaims
		}
		if config.MaxHostnameClaimRequests == 0 {
			config.MaxHostnameClaimRequests = DefaultMaxHostnameClaimRequests
		}
	}
	if config.MaxActiveHostnameClaims <= 0 || config.MaxHostnameClaimRequests <= 0 {
		return nil, errors.New("routes: hostname claim quotas must be positive")
	}
	if config.MaxActiveHostnameClaims > maximumHostnameClaimQuota ||
		config.MaxHostnameClaimRequests > maximumHostnameClaimQuota {
		return nil, fmt.Errorf("routes: hostname claim quotas must not exceed %d", maximumHostnameClaimQuota)
	}
	if config.MaxHostnameClaimRequests < config.MaxActiveHostnameClaims {
		return nil, errors.New("routes: hostname claim request quota must be at least the active claim quota")
	}
	canonical, err := naming.CanonicalizeHostname(routeSuffix)
	if err != nil || canonical != routeSuffix || len(canonical) > naming.MaxHostnameBytes-naming.MaxLabelBytes-1 {
		return nil, errors.New("routes: route suffix must be canonical and leave room for one DNS label")
	}
	return &Store{
		db:                       db,
		queries:                  statedb.New(db),
		routeSuffix:              routeSuffix,
		now:                      time.Now,
		leaseLifetime:            LeaseLifetime,
		maxActiveHostnameClaims:  config.MaxActiveHostnameClaims,
		maxHostnameClaimRequests: config.MaxHostnameClaimRequests,
		observeOperation:         config.ObserveOperation,
		lifecycleRecorder:        config.LifecycleRecorder,
	}, nil
}

func (s *Store) Create(
	ctx context.Context,
	principalID, hostname, displayTarget, bootEpoch string,
	routeToken credentials.RouteToken,
) (provisioning Provisioning, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationRouteCreate, started, err) }()
	hostname, err = s.canonicalHostname(hostname)
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
	queries := s.queries.WithTx(tx)
	// Claim ownership and irreversibility commit with route creation or rotation.
	claim, err := queries.GetRouteClaimByHostname(ctx, hostname)
	if errors.Is(err, sql.ErrNoRows) {
		return Provisioning{}, ErrNameUnavailable
	} else if err != nil {
		return Provisioning{}, fmt.Errorf("routes: read hostname claim: %w", err)
	}
	if claim.PrincipalID != principalID || claim.TombstonedAt.Valid {
		return Provisioning{}, ErrNameUnavailable
	}
	if err := queries.MarkRouteClaimIrreversible(ctx, claim.ID); err != nil {
		return Provisioning{}, fmt.Errorf("routes: mark hostname irreversible: %w", err)
	}
	existingRoute, err := queries.GetActiveRouteByClaim(ctx, claim.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Provisioning{}, fmt.Errorf("routes: check existing route: %w", err)
	}
	if err == nil {
		// Recreate in place, rotating credentials and fencing the old agent.
		existing := routeFromDB(existingRoute)
		generation := existing.Generation + 1
		if err := s.recordLifecycle(ctx, queries, existing.ID, existing.Generation, now, LifecycleDisconnected); err != nil {
			return Provisioning{}, err
		}
		count, err := queries.RotateRouteCredential(ctx, statedb.RotateRouteCredentialParams{
			CredentialID: routeCredentialID.String(),
			SecretHash:   routeHash[:],
			CreatedAt:    now.Unix(),
			RouteID:      existing.ID,
		})
		if err != nil {
			return Provisioning{}, fmt.Errorf("routes: rotate route credential: %w", err)
		}
		if err := requireCount(count, ErrInvalidState); err != nil {
			return Provisioning{}, err
		}
		if err := queries.ExpireRouteLeases(ctx, existing.ID); err != nil {
			return Provisioning{}, fmt.Errorf("routes: expire replaced lease: %w", err)
		}
		dbGeneration, err := generationToInt64(generation)
		if err != nil {
			return Provisioning{}, fmt.Errorf("routes: advance replaced route: %w", err)
		}
		if err := queries.ReplaceRoute(ctx, statedb.ReplaceRouteParams{
			DisplayTarget: displayTarget,
			Generation:    dbGeneration,
			RouteID:       existing.ID,
		}); err != nil {
			return Provisioning{}, fmt.Errorf("routes: advance replaced route: %w", err)
		}
		if err := queries.InsertRouteLease(ctx, statedb.InsertRouteLeaseParams{
			LeaseID:      leaseID,
			RouteID:      existing.ID,
			Generation:   dbGeneration,
			CredentialID: leaseCredentialID.String(),
			SecretHash:   leaseHash[:],
			BootEpoch:    bootEpoch,
			CreatedAt:    now.Unix(),
			ExpiresAt:    expiresAt.Unix(),
		}); err != nil {
			return Provisioning{}, fmt.Errorf("routes: create replacement lease: %w", err)
		}
		if err := s.recordLifecycle(ctx, queries, existing.ID, generation, now, LifecycleGenerationStarted); err != nil {
			return Provisioning{}, err
		}
		if err := tx.Commit(); err != nil {
			return Provisioning{}, fmt.Errorf("routes: commit route replacement: %w", err)
		}
		existing.DisplayTarget = displayTarget
		existing.Generation = generation
		return Provisioning{
			Route: existing,
			Lease: Lease{
				ID: leaseID, RouteID: existing.ID, Generation: generation, Status: "pending",
				BootEpoch: bootEpoch, CreatedAt: now, LastHeartbeat: now, ExpiresAt: expiresAt,
			},
			LeaseToken: leaseToken,
		}, nil
	}
	if err := queries.InsertRoute(ctx, statedb.InsertRouteParams{
		RouteID:       routeID,
		ClaimID:       claim.ID,
		PrincipalID:   principalID,
		Hostname:      hostname,
		DisplayTarget: displayTarget,
		CreatedAt:     now.Unix(),
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create route: %w", err)
	}
	if err := queries.InsertRouteCredential(ctx, statedb.InsertRouteCredentialParams{
		CredentialID: routeCredentialID.String(),
		RouteID:      routeID,
		SecretHash:   routeHash[:],
		CreatedAt:    now.Unix(),
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create route credential: %w", err)
	}
	if err := queries.InsertInitialRouteLease(ctx, statedb.InsertInitialRouteLeaseParams{
		LeaseID:      leaseID,
		RouteID:      routeID,
		CredentialID: leaseCredentialID.String(),
		SecretHash:   leaseHash[:],
		BootEpoch:    bootEpoch,
		CreatedAt:    now.Unix(),
		ExpiresAt:    expiresAt.Unix(),
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create lease: %w", err)
	}
	if err := s.recordLifecycle(ctx, queries, routeID, 1, now, LifecycleGenerationStarted); err != nil {
		return Provisioning{}, err
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
) (provisioning Provisioning, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationRouteAcquire, started, err) }()
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
	queries := s.queries.WithTx(tx)
	route, storedHash, revoked, err := readRouteCredential(ctx, queries, routeID, credentialID)
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
	if err := s.recordLifecycle(ctx, queries, routeID, route.Generation, now, LifecycleDisconnected); err != nil {
		return Provisioning{}, err
	}
	if err := queries.ExpireRouteLeases(ctx, routeID); err != nil {
		return Provisioning{}, fmt.Errorf("routes: expire previous lease: %w", err)
	}
	dbGeneration, err := generationToInt64(generation)
	if err != nil {
		return Provisioning{}, fmt.Errorf("routes: advance generation: %w", err)
	}
	if err := queries.AdvanceRouteGeneration(ctx, statedb.AdvanceRouteGenerationParams{
		Generation: dbGeneration,
		RouteID:    routeID,
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: advance generation: %w", err)
	}
	if err := queries.InsertRouteLease(ctx, statedb.InsertRouteLeaseParams{
		LeaseID:      leaseID,
		RouteID:      routeID,
		Generation:   dbGeneration,
		CredentialID: leaseCredentialID.String(),
		SecretHash:   leaseHash[:],
		BootEpoch:    bootEpoch,
		CreatedAt:    now.Unix(),
		ExpiresAt:    expiresAt.Unix(),
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create replacement lease: %w", err)
	}
	if err := s.recordLifecycle(ctx, queries, routeID, generation, now, LifecycleGenerationStarted); err != nil {
		return Provisioning{}, err
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
	route, storedHash, revoked, err := readRouteCredential(ctx, s.queries, routeID, credentialID)
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
	exists, err := s.queries.CountActiveRoutesByPrincipal(ctx, statedb.CountActiveRoutesByPrincipalParams{
		RouteID:     routeID,
		PrincipalID: principalID,
	})
	if err != nil {
		return fmt.Errorf("routes: authorize principal: %w", err)
	}
	if exists == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ActiveRouteID(ctx context.Context, principalID, hostname string) (string, error) {
	hostname, err := s.canonicalHostname(hostname)
	if err != nil {
		return "", err
	}
	routeID, err := s.queries.GetActiveRouteIDByHostname(ctx, statedb.GetActiveRouteIDByHostnameParams{
		PrincipalID: principalID,
		Hostname:    hostname,
	})
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
) (result Lease, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationLeaseAuthenticate, started, err) }()
	credentialID, candidate, err := credentials.ParseLeaseToken(token)
	if err != nil {
		return Lease{}, ErrUnauthenticated
	}
	dbGeneration, err := generationToInt64(generation)
	if err != nil {
		return Lease{}, fmt.Errorf("routes: read lease: %w", err)
	}
	dbLease, err := s.queries.GetRouteLeaseForAuthentication(ctx, statedb.GetRouteLeaseForAuthenticationParams{
		RouteID:      routeID,
		Generation:   dbGeneration,
		CredentialID: credentialID.String(),
	})
	if errors.Is(err, sql.ErrNoRows) {
		// Known credentials are stale; unknown IDs remain unauthenticated.
		_, knownErr := s.queries.GetKnownRouteLeaseCredentialMarker(ctx, credentialID.String())
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
	if dbLease.BootEpoch != bootEpoch || dbLease.Status == "expired" || now.Unix() >= dbLease.ExpiresAt {
		return Lease{}, ErrStaleLease
	}
	if !credentials.SecretHashMatches(dbLease.SecretHash, candidate) {
		return Lease{}, ErrUnauthenticated
	}
	return leaseFromDB(dbLease), nil
}

func (s *Store) RegisterTransport(
	ctx context.Context,
	lease Lease,
	serverPublicKey, relayProfile string,
) (err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationTransportRegister, started, err) }()
	if strings.TrimSpace(serverPublicKey) == "" || strings.TrimSpace(relayProfile) == "" {
		return errors.New("routes: transport descriptor is incomplete")
	}
	dbGeneration, err := generationToInt64(lease.Generation)
	if err != nil {
		return fmt.Errorf("routes: register transport: %w", err)
	}
	count, err := s.queries.RegisterRouteLeaseTransport(ctx, statedb.RegisterRouteLeaseTransportParams{
		ServerPublicKey: sql.NullString{String: serverPublicKey, Valid: true},
		RelayProfile:    sql.NullString{String: relayProfile, Valid: true},
		LeaseID:         lease.ID,
		RouteID:         lease.RouteID,
		Generation:      dbGeneration,
	})
	if err != nil {
		return fmt.Errorf("routes: register transport: %w", err)
	}
	return requireCount(count, ErrStaleLease)
}

func (s *Store) Ready(ctx context.Context, lease Lease) (err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationRouteReady, started, err) }()
	dbGeneration, err := generationToInt64(lease.Generation)
	if err != nil {
		return fmt.Errorf("routes: mark ready: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin ready: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	status, err := queries.GetRouteLeaseStatus(ctx, statedb.GetRouteLeaseStatusParams{
		LeaseID: lease.ID, RouteID: lease.RouteID, Generation: dbGeneration,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidState
	}
	if err != nil {
		return fmt.Errorf("routes: read ready state: %w", err)
	}
	if status == "ready" {
		return nil
	}
	count, err := queries.ReadyRouteLease(ctx, statedb.ReadyRouteLeaseParams{
		LeaseID:    lease.ID,
		RouteID:    lease.RouteID,
		Generation: dbGeneration,
	})
	if err != nil {
		return fmt.Errorf("routes: mark ready: %w", err)
	}
	if err := requireCount(count, ErrInvalidState); err != nil {
		return err
	}
	if err := s.recordLifecycle(ctx, queries, lease.RouteID, lease.Generation, s.now().UTC(), LifecycleReady); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit ready: %w", err)
	}
	return nil
}

func (s *Store) Heartbeat(ctx context.Context, lease Lease) (expiresAt time.Time, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationLeaseHeartbeat, started, err) }()
	now := time.Unix(s.now().Unix(), 0).UTC()
	expiresAt = now.Add(s.leaseLifetime)
	dbGeneration, err := generationToInt64(lease.Generation)
	if err != nil {
		return time.Time{}, fmt.Errorf("routes: heartbeat: %w", err)
	}
	count, err := s.queries.HeartbeatRouteLease(ctx, statedb.HeartbeatRouteLeaseParams{
		LastHeartbeat: now.Unix(),
		ExpiresAt:     expiresAt.Unix(),
		LeaseID:       lease.ID,
		RouteID:       lease.RouteID,
		Generation:    dbGeneration,
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("routes: heartbeat: %w", err)
	}
	if err := requireCount(count, ErrStaleLease); err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}

func (s *Store) InvalidateOtherBoots(ctx context.Context, bootEpoch string) error {
	if strings.TrimSpace(bootEpoch) == "" {
		return errors.New("routes: boot epoch is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin old boot invalidation: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	leases, err := queries.ListOtherBootRouteLeases(ctx, bootEpoch)
	if err != nil {
		return fmt.Errorf("routes: list old boot leases: %w", err)
	}
	if err := queries.InvalidateOtherBootRouteLeases(ctx, bootEpoch); err != nil {
		return fmt.Errorf("routes: invalidate old boot leases: %w", err)
	}
	now := s.now().UTC()
	for _, lease := range leases {
		if err := s.recordLifecycle(ctx, queries, lease.RouteID, uint64(lease.Generation), now, LifecycleDisconnected); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit old boot invalidation: %w", err)
	}
	return nil
}

func (s *Store) Expire(ctx context.Context, routeID string, generation uint64) (err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationLeaseExpire, started, err) }()
	dbGeneration, err := generationToInt64(generation)
	if err != nil {
		return fmt.Errorf("routes: expire lease: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin expire lease: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	count, err := queries.ExpireRouteLease(ctx, statedb.ExpireRouteLeaseParams{
		RouteID:    routeID,
		Generation: dbGeneration,
	})
	if err != nil {
		return fmt.Errorf("routes: expire lease: %w", err)
	}
	if err := requireCount(count, ErrStaleLease); err != nil {
		return err
	}
	if err := s.recordLifecycle(ctx, queries, routeID, generation, s.now().UTC(), LifecycleDisconnected); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit expire lease: %w", err)
	}
	return nil
}

func (s *Store) List(ctx context.Context, principalID string) ([]Route, error) {
	routes, err := s.queries.ListActiveRoutes(ctx, principalID)
	if err != nil {
		return nil, fmt.Errorf("routes: list: %w", err)
	}
	var result []Route
	for _, route := range routes {
		result = append(result, routeFromDB(route))
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
	queries := s.queries.WithTx(tx)
	generation, err := queries.GetRouteGeneration(ctx, routeID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("routes: read deleted route: %w", err)
	}
	count, err := queries.DeleteActiveRoute(ctx, statedb.DeleteActiveRouteParams{
		DeletedAt:   now.Unix(),
		RouteID:     routeID,
		PrincipalID: principalID,
	})
	if err != nil {
		return fmt.Errorf("routes: delete: %w", err)
	}
	if err := requireCount(count, ErrNotFound); err != nil {
		return err
	}
	if err := queries.RevokeRouteCredential(ctx, statedb.RevokeRouteCredentialParams{
		RevokedAt: now.Unix(),
		RouteID:   routeID,
	}); err != nil {
		return fmt.Errorf("routes: revoke route credential: %w", err)
	}
	if err := queries.ExpireRouteLeases(ctx, routeID); err != nil {
		return fmt.Errorf("routes: expire deleted route: %w", err)
	}
	if err := s.recordLifecycle(ctx, queries, routeID, uint64(generation), now, LifecycleDisconnected); err != nil {
		return err
	}
	if err := s.recordLifecycle(ctx, queries, routeID, uint64(generation), now, LifecycleDeleted); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit delete: %w", err)
	}
	return nil
}

func readRouteCredential(
	ctx context.Context,
	queries *statedb.Queries,
	routeID string,
	credentialID credentials.CredentialID,
) (Route, []byte, bool, error) {
	credential, err := queries.GetRouteCredential(ctx, statedb.GetRouteCredentialParams{
		RouteID:      routeID,
		CredentialID: credentialID.String(),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Route{}, nil, false, ErrUnauthenticated
	}
	if err != nil {
		return Route{}, nil, false, fmt.Errorf("routes: read route credential: %w", err)
	}
	return routeFromDB(credential.Route), credential.SecretHash, credential.RevokedAt.Valid, nil
}

func requireCount(count int64, missing error) error {
	if count == 0 {
		return missing
	}
	return nil
}

func routeFromDB(route statedb.Route) Route {
	return Route{
		ID:            route.ID,
		PrincipalID:   route.PrincipalID,
		Hostname:      route.Hostname,
		DisplayTarget: route.DisplayTarget,
		State:         route.State,
		Generation:    uint64(route.Generation),
		CreatedAt:     time.Unix(route.CreatedAt, 0).UTC(),
	}
}

func leaseFromDB(lease statedb.RouteLease) Lease {
	return Lease{
		ID:              lease.ID,
		RouteID:         lease.RouteID,
		Generation:      uint64(lease.Generation),
		Status:          lease.Status,
		BootEpoch:       lease.BootEpoch,
		ServerPublicKey: lease.ServerPublicKey.String,
		RelayProfile:    lease.RelayProfile.String,
		CreatedAt:       time.Unix(lease.CreatedAt, 0).UTC(),
		LastHeartbeat:   time.Unix(lease.LastHeartbeat, 0).UTC(),
		ExpiresAt:       time.Unix(lease.ExpiresAt, 0).UTC(),
	}
}

func generationToInt64(generation uint64) (int64, error) {
	if generation > math.MaxInt64 {
		return 0, errors.New("uint64 generation exceeds database integer range")
	}
	return int64(generation), nil
}

func newID(prefix string) (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("routes: generate %s ID: %w", prefix, err)
	}
	return prefix + "_" + hex.EncodeToString(material[:]), nil
}

func (s *Store) observe(operation StoreOperation, started time.Time, err error) {
	if s.observeOperation != nil {
		s.observeOperation(operation, time.Since(started), err)
	}
}

func (s *Store) recordLifecycle(
	ctx context.Context,
	queries *statedb.Queries,
	routeID string,
	generation uint64,
	occurredAt time.Time,
	transition LifecycleTransition,
) error {
	if s.lifecycleRecorder == nil {
		return nil
	}
	if err := s.lifecycleRecorder.RecordLifecycle(ctx, queries, LifecycleChange{
		RouteID: routeID, Generation: generation, OccurredAt: occurredAt, Transition: transition,
	}); err != nil {
		return fmt.Errorf("routes: record lifecycle: %w", err)
	}
	return nil
}
