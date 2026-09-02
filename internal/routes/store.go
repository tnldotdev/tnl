package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

const (
	SessionLifetime              = 45 * time.Second
	DefaultMaxActiveHostnames    = 128
	DefaultMaxHostnameRequests   = 1024
	maximumHostnameQuota         = 100_000
	MaximumSubdomainDepth        = 8
	TemporaryReacquisitionWindow = 5 * time.Minute
)

var (
	ErrNameUnavailable            = errors.New("routes: name unavailable")
	ErrInvalidArgument            = errors.New("routes: invalid argument")
	ErrRouteExists                = errors.New("routes: route already exists")
	ErrNotFound                   = errors.New("routes: not found")
	ErrUnauthenticated            = errors.New("routes: unauthenticated")
	ErrStaleSession               = errors.New("routes: stale session")
	ErrInvalidStatus              = errors.New("routes: invalid status")
	ErrUnavailable                = errors.New("routes: temporarily unavailable")
	ErrAuthorizationReuseRejected = errors.New("routes: authorization reuse rejected")
)

type RouteStatus string

const (
	RouteStatusEnabled   RouteStatus = "enabled"
	RouteStatusSuspended RouteStatus = "suspended"
	RouteStatusDeleted   RouteStatus = "deleted"
)

type SessionStatus string

const (
	SessionStatusPending  SessionStatus = "pending"
	SessionStatusStarting SessionStatus = "starting"
	SessionStatusReady    SessionStatus = "ready"
	SessionStatusExpired  SessionStatus = "expired"
)

type Route struct {
	ID                        string
	HostnameID                string
	IdentityID                string
	Hostname                  string
	LocalTarget               string
	Status                    RouteStatus
	RouteVersion              uint64
	SuspensionRevision        uint64
	SuspensionReason          string
	SuspendedAt               time.Time
	AuthorizationIssuer       string
	AuthorizationID           string
	AuthorizationKeyID        string
	AuthorizationRetryID      string
	AuthorizationRevision     uint64
	AuthorizationExpiresAt    time.Time
	AuthorizationRequestHash  authorization.Digest
	AuthorizationIPPolicyHash *authorization.Digest
	AllowedIPPrefixes         []string
	CreatedAt                 time.Time
	DeletedAt                 time.Time
}

type Session struct {
	ID                 string
	RouteID            string
	RouteVersion       uint64
	Status             SessionStatus
	ServerInstanceID   string
	PublisherPublicKey string
	RelayRegion        string
	CreatedAt          time.Time
	LastHeartbeatAt    time.Time
	ExpiresAt          time.Time
}

type Provisioning struct {
	Route        Route
	Session      Session
	SessionToken credentials.SessionToken
	ReusedResult bool
	Restored     bool
}

type SignedRequest struct {
	Token             string
	RequestHash       authorization.Digest
	IPPolicyHash      *authorization.Digest
	AllowedIPPrefixes []string
}

type StoreConfig struct {
	MaxActiveHostnames    int
	MaxHostnameRequests   int
	ReservedRouteNames    []string
	ObserveOperation      StoreObserver
	LifecycleRecorder     LifecycleRecorder
	VerificationSuffix    string
	DomainVerifier        DomainVerifier
	AuthorizationVerifier *authorization.Verifier
}

type Store struct {
	db                    *sql.DB
	queries               *statedb.Queries
	hostnameSuffix        string
	now                   func() time.Time
	sessionLifetime       time.Duration
	maxActiveHostnames    int
	maxHostnameRequests   int
	reservedRouteNames    map[string]struct{}
	observeOperation      StoreObserver
	lifecycleRecorder     LifecycleRecorder
	verificationSuffix    string
	domainVerifier        DomainVerifier
	authorizationVerifier *authorization.Verifier
}

func NewStore(db *sql.DB, hostnameSuffix string, configs ...StoreConfig) (*Store, error) {
	if db == nil {
		return nil, errors.New("routes: nil state database")
	}
	if len(configs) > 1 {
		return nil, errors.New("routes: multiple store configurations")
	}
	config := StoreConfig{
		MaxActiveHostnames:  DefaultMaxActiveHostnames,
		MaxHostnameRequests: DefaultMaxHostnameRequests,
	}
	if len(configs) == 1 {
		config = configs[0]
		if config.MaxActiveHostnames == 0 {
			config.MaxActiveHostnames = DefaultMaxActiveHostnames
		}
		if config.MaxHostnameRequests == 0 {
			config.MaxHostnameRequests = DefaultMaxHostnameRequests
		}
	}
	if config.MaxActiveHostnames <= 0 || config.MaxHostnameRequests <= 0 {
		return nil, errors.New("routes: hostname quotas must be positive")
	}
	if config.MaxActiveHostnames > maximumHostnameQuota ||
		config.MaxHostnameRequests > maximumHostnameQuota {
		return nil, fmt.Errorf("routes: hostname quotas must not exceed %d", maximumHostnameQuota)
	}
	if config.MaxHostnameRequests < config.MaxActiveHostnames {
		return nil, errors.New("routes: hostname request quota must be at least the active hostname quota")
	}
	canonical, err := naming.CanonicalizeHostname(hostnameSuffix)
	if err != nil || canonical != hostnameSuffix || len(canonical) > naming.MaxHostnameBytes-naming.MaxLabelBytes-1 {
		return nil, errors.New("routes: hostname suffix must be canonical and leave room for one DNS label")
	}
	store := &Store{
		db:                    db,
		queries:               statedb.New(db),
		hostnameSuffix:        hostnameSuffix,
		now:                   time.Now,
		sessionLifetime:       SessionLifetime,
		maxActiveHostnames:    config.MaxActiveHostnames,
		maxHostnameRequests:   config.MaxHostnameRequests,
		reservedRouteNames:    make(map[string]struct{}, len(config.ReservedRouteNames)),
		observeOperation:      config.ObserveOperation,
		lifecycleRecorder:     config.LifecycleRecorder,
		verificationSuffix:    config.VerificationSuffix,
		domainVerifier:        config.DomainVerifier,
		authorizationVerifier: config.AuthorizationVerifier,
	}
	if config.VerificationSuffix != "" {
		verificationSuffix, err := naming.CanonicalizeHostname(config.VerificationSuffix)
		if err != nil || verificationSuffix != config.VerificationSuffix {
			return nil, errors.New("routes: verification suffix must be canonical")
		}
		store.verificationSuffix = verificationSuffix
	}
	if (store.verificationSuffix == "") != (store.domainVerifier == nil) {
		return nil, errors.New("routes: domain verification configuration is incomplete")
	}
	if err := store.seedReservedRouteNames(config.ReservedRouteNames); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) seedReservedRouteNames(labels []string) error {
	ctx := context.Background()
	for _, label := range labels {
		canonical, err := naming.CanonicalizeHostname(label)
		if err != nil || canonical != label || strings.Contains(label, ".") {
			return fmt.Errorf("routes: invalid reserved route name %q", label)
		}
		if _, err := s.queries.GetHostnameByHostname(ctx, label+"."+s.hostnameSuffix); err == nil {
			return fmt.Errorf("routes: reserved route name %q is already owned", label)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("routes: read route reservation %q: %w", label, err)
		}
		s.reservedRouteNames[label] = struct{}{}
	}
	return nil
}

func (s *Store) Create(
	ctx context.Context,
	identityID, hostname, localTarget, serverInstanceID string,
	routeToken credentials.RouteToken,
	allowedIPPrefixes []string,
) (provisioning Provisioning, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationRouteCreate, started, err) }()
	hostname, err = s.canonicalRouteHostname(hostname)
	if err != nil {
		return Provisioning{}, err
	}
	if strings.TrimSpace(identityID) == "" || strings.TrimSpace(localTarget) == "" || strings.TrimSpace(serverInstanceID) == "" {
		return Provisioning{}, errors.New("routes: identity, target, and server instance ID are required")
	}
	allowedIPPrefixes, err = validateAllowedIPPrefixes(allowedIPPrefixes)
	if err != nil {
		return Provisioning{}, err
	}

	routeCredentialID, routeHash, err := credentials.ParseRouteToken(routeToken)
	if err != nil {
		return Provisioning{}, ErrUnauthenticated
	}
	sessionToken, sessionTokenID, sessionHash, err := credentials.NewSessionToken()
	if err != nil {
		return Provisioning{}, err
	}
	routeID, err := newID("route")
	if err != nil {
		return Provisioning{}, err
	}
	sessionID, err := newID("session")
	if err != nil {
		return Provisioning{}, err
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	expiresAt := now.Add(s.sessionLifetime)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Provisioning{}, fmt.Errorf("routes: begin create: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	// Hostname authorization commit with route creation or rotation.
	authorizingHostname, err := queries.GetAuthorizingRouteHostname(ctx, statedb.GetAuthorizingRouteHostnameParams{
		IdentityID: identityID,
		Hostname:   hostname,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Provisioning{}, ErrNameUnavailable
	} else if err != nil {
		return Provisioning{}, fmt.Errorf("routes: read hostname: %w", err)
	}
	if authorizingHostname.IdentityID.String != identityID ||
		(authorizingHostname.Kind == HostnameKindManaged || authorizingHostname.Kind == HostnameKindCustomDomain) && authorizingHostname.Status != HostnameStatusActive ||
		authorizingHostname.Kind == HostnameKindTemporary && (authorizingHostname.Status != HostnameStatusPendingRoute && authorizingHostname.Status != HostnameStatusActive) ||
		authorizingHostname.Kind == HostnameKindTemporary && authorizingHostname.Hostname != hostname ||
		authorizingHostname.Kind != HostnameKindManaged && authorizingHostname.Kind != HostnameKindCustomDomain && authorizingHostname.Kind != HostnameKindTemporary {
		return Provisioning{}, ErrNameUnavailable
	}
	depth, authorized := naming.ChildDepth(hostname, authorizingHostname.Hostname)
	if !authorized || depth > MaximumSubdomainDepth {
		return Provisioning{}, ErrInvalidArgument
	}
	existingRoute, err := queries.GetCurrentRouteByHostname(ctx, hostname)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Provisioning{}, fmt.Errorf("routes: check existing route: %w", err)
	}
	if err == nil {
		// Recreate in place, rotating credentials and fencing the old tlschallenge.
		existing := routeFromDB(existingRoute)
		if existing.Status != RouteStatusEnabled {
			return Provisioning{}, ErrInvalidStatus
		}
		routeVersion := existing.RouteVersion + 1
		if err := s.recordLifecycle(ctx, queries, existing.ID, existing.RouteVersion, now, LifecycleDisconnected); err != nil {
			return Provisioning{}, err
		}
		count, err := queries.RotateRouteCredential(ctx, statedb.RotateRouteCredentialParams{
			CredentialID: routeCredentialID.String(),
			SecretHash:   routeHash[:],
			CreatedAt:    now.UnixNano(),
			RouteID:      existing.ID,
		})
		if err != nil {
			return Provisioning{}, fmt.Errorf("routes: rotate route credential: %w", err)
		}
		if err := requireCount(count, ErrInvalidStatus); err != nil {
			return Provisioning{}, err
		}
		if err := queries.ExpireRouteSessions(ctx, existing.ID); err != nil {
			return Provisioning{}, fmt.Errorf("routes: expire replaced session: %w", err)
		}
		dbRouteVersion, err := routeVersionToInt64(routeVersion)
		if err != nil {
			return Provisioning{}, fmt.Errorf("routes: advance replaced route: %w", err)
		}
		if err := queries.ReplaceRoute(ctx, statedb.ReplaceRouteParams{
			LocalTarget:  localTarget,
			RouteVersion: dbRouteVersion,
			RouteID:      existing.ID,
		}); err != nil {
			return Provisioning{}, fmt.Errorf("routes: advance replaced route: %w", err)
		}
		if err := insertAllowedIPPrefixes(ctx, queries, existing.ID, routeVersion, allowedIPPrefixes); err != nil {
			return Provisioning{}, err
		}
		if err := queries.InsertRouteSession(ctx, statedb.InsertRouteSessionParams{
			SessionID:        sessionID,
			RouteID:          existing.ID,
			RouteVersion:     dbRouteVersion,
			TokenID:          sessionTokenID.String(),
			SecretHash:       sessionHash[:],
			ServerInstanceID: serverInstanceID,
			CreatedAt:        now.UnixNano(),
			ExpiresAt:        expiresAt.UnixNano(),
		}); err != nil {
			return Provisioning{}, fmt.Errorf("routes: create replacement session: %w", err)
		}
		if err := s.recordLifecycle(ctx, queries, existing.ID, routeVersion, now, LifecycleRouteVersionStarted); err != nil {
			return Provisioning{}, err
		}
		if err := tx.Commit(); err != nil {
			return Provisioning{}, fmt.Errorf("routes: commit route replacement: %w", err)
		}
		existing.LocalTarget = localTarget
		existing.RouteVersion = routeVersion
		existing.AllowedIPPrefixes = slices.Clone(allowedIPPrefixes)
		return Provisioning{
			Route: existing,
			Session: Session{
				ID: sessionID, RouteID: existing.ID, RouteVersion: routeVersion, Status: SessionStatusPending,
				ServerInstanceID: serverInstanceID, CreatedAt: now, LastHeartbeatAt: now, ExpiresAt: expiresAt,
			},
			SessionToken: sessionToken,
		}, nil
	}
	if err := queries.InsertRoute(ctx, statedb.InsertRouteParams{
		RouteID:     routeID,
		HostnameID:  sql.NullString{String: authorizingHostname.ID, Valid: true},
		IdentityID:  identityID,
		Hostname:    hostname,
		LocalTarget: localTarget,
		CreatedAt:   now.UnixNano(),
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create route: %w", err)
	}
	if err := insertAllowedIPPrefixes(ctx, queries, routeID, 1, allowedIPPrefixes); err != nil {
		return Provisioning{}, err
	}
	if authorizingHostname.Kind == HostnameKindTemporary {
		count, err := queries.ActivateTemporaryHostname(ctx, statedb.ActivateTemporaryHostnameParams{
			ActivatedAt: now.UnixNano(), HostnameID: authorizingHostname.ID, IdentityID: identityID,
		})
		if err != nil {
			return Provisioning{}, fmt.Errorf("routes: bind temporary hostname: %w", err)
		}
		if err := requireCount(count, ErrInvalidStatus); err != nil {
			return Provisioning{}, err
		}
	}
	if err := queries.InsertRouteCredential(ctx, statedb.InsertRouteCredentialParams{
		CredentialID: routeCredentialID.String(),
		RouteID:      routeID,
		SecretHash:   routeHash[:],
		CreatedAt:    now.UnixNano(),
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create route credential: %w", err)
	}
	if err := queries.InsertInitialRouteSession(ctx, statedb.InsertInitialRouteSessionParams{
		SessionID:        sessionID,
		RouteID:          routeID,
		TokenID:          sessionTokenID.String(),
		SecretHash:       sessionHash[:],
		ServerInstanceID: serverInstanceID,
		CreatedAt:        now.UnixNano(),
		ExpiresAt:        expiresAt.UnixNano(),
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create session: %w", err)
	}
	if err := s.recordLifecycle(ctx, queries, routeID, 1, now, LifecycleRouteVersionStarted); err != nil {
		return Provisioning{}, err
	}
	if err := tx.Commit(); err != nil {
		return Provisioning{}, fmt.Errorf("routes: commit create: %w", err)
	}
	return Provisioning{
		Route: Route{
			ID: routeID, IdentityID: identityID, Hostname: hostname, LocalTarget: localTarget,
			Status: RouteStatusEnabled, RouteVersion: 1, AllowedIPPrefixes: slices.Clone(allowedIPPrefixes), CreatedAt: now,
		},
		Session:      Session{ID: sessionID, RouteID: routeID, RouteVersion: 1, Status: SessionStatusPending, ServerInstanceID: serverInstanceID, CreatedAt: now, LastHeartbeatAt: now, ExpiresAt: expiresAt},
		SessionToken: sessionToken,
	}, nil
}

func (s *Store) CreateSession(
	ctx context.Context,
	identityID, routeID, serverInstanceID string,
	routeToken credentials.RouteToken,
	allowedIPPrefixes []string,
) (provisioning Provisioning, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationSessionCreate, started, err) }()
	allowedIPPrefixes, err = validateAllowedIPPrefixes(allowedIPPrefixes)
	if err != nil {
		return Provisioning{}, err
	}
	credentialID, candidate, err := credentials.ParseRouteToken(routeToken)
	if err != nil {
		return Provisioning{}, ErrUnauthenticated
	}
	sessionToken, sessionTokenID, sessionHash, err := credentials.NewSessionToken()
	if err != nil {
		return Provisioning{}, err
	}
	sessionID, err := newID("session")
	if err != nil {
		return Provisioning{}, err
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	expiresAt := now.Add(s.sessionLifetime)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Provisioning{}, fmt.Errorf("routes: begin session creation: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	route, storedHash, revoked, err := readRouteCredential(ctx, queries, routeID, credentialID)
	if err != nil {
		return Provisioning{}, err
	}
	if route.IdentityID != identityID || revoked || !credentials.SecretHashMatches(storedHash, candidate) {
		return Provisioning{}, ErrUnauthenticated
	}
	if route.Status != RouteStatusEnabled {
		return Provisioning{}, ErrInvalidStatus
	}
	routeVersion := route.RouteVersion + 1
	if err := s.recordLifecycle(ctx, queries, routeID, route.RouteVersion, now, LifecycleDisconnected); err != nil {
		return Provisioning{}, err
	}
	if err := queries.ExpireRouteSessions(ctx, routeID); err != nil {
		return Provisioning{}, fmt.Errorf("routes: expire previous session: %w", err)
	}
	dbRouteVersion, err := routeVersionToInt64(routeVersion)
	if err != nil {
		return Provisioning{}, fmt.Errorf("routes: advance version: %w", err)
	}
	if err := queries.AdvanceRouteVersion(ctx, statedb.AdvanceRouteVersionParams{
		RouteVersion: dbRouteVersion,
		RouteID:      routeID,
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: advance version: %w", err)
	}
	if err := insertAllowedIPPrefixes(ctx, queries, routeID, routeVersion, allowedIPPrefixes); err != nil {
		return Provisioning{}, err
	}
	if err := queries.InsertRouteSession(ctx, statedb.InsertRouteSessionParams{
		SessionID:        sessionID,
		RouteID:          routeID,
		RouteVersion:     dbRouteVersion,
		TokenID:          sessionTokenID.String(),
		SecretHash:       sessionHash[:],
		ServerInstanceID: serverInstanceID,
		CreatedAt:        now.UnixNano(),
		ExpiresAt:        expiresAt.UnixNano(),
	}); err != nil {
		return Provisioning{}, fmt.Errorf("routes: create replacement session: %w", err)
	}
	if err := s.recordLifecycle(ctx, queries, routeID, routeVersion, now, LifecycleRouteVersionStarted); err != nil {
		return Provisioning{}, err
	}
	if err := tx.Commit(); err != nil {
		return Provisioning{}, fmt.Errorf("routes: commit session creation: %w", err)
	}
	route.RouteVersion = routeVersion
	route.AllowedIPPrefixes = slices.Clone(allowedIPPrefixes)
	return Provisioning{
		Route:        route,
		Session:      Session{ID: sessionID, RouteID: routeID, RouteVersion: routeVersion, Status: SessionStatusPending, ServerInstanceID: serverInstanceID, CreatedAt: now, LastHeartbeatAt: now, ExpiresAt: expiresAt},
		SessionToken: sessionToken,
	}, nil
}

func (s *Store) AuthorizeRoute(
	ctx context.Context,
	identityID, routeID string,
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
	if route.IdentityID != identityID || revoked || !credentials.SecretHashMatches(storedHash, candidate) {
		return Route{}, ErrUnauthenticated
	}
	if route.Status != RouteStatusEnabled {
		return Route{}, ErrInvalidStatus
	}
	return route, nil
}

func (s *Store) AuthorizeIdentity(ctx context.Context, identityID, routeID string) error {
	exists, err := s.queries.CountEnabledRoutesByIdentity(ctx, statedb.CountEnabledRoutesByIdentityParams{
		RouteID:    routeID,
		IdentityID: identityID,
	})
	if err != nil {
		return fmt.Errorf("routes: authorize identity: %w", err)
	}
	if exists == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) EnabledRouteID(ctx context.Context, identityID, hostname string) (string, error) {
	hostname, err := s.canonicalHostname(hostname)
	if err != nil {
		return "", err
	}
	routeID, err := s.queries.GetEnabledRouteIDByHostname(ctx, statedb.GetEnabledRouteIDByHostnameParams{
		IdentityID: identityID,
		Hostname:   hostname,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("routes: find enabled route: %w", err)
	}
	return routeID, nil
}

func (s *Store) AuthenticateSession(
	ctx context.Context,
	routeID string,
	routeVersion uint64,
	token credentials.SessionToken,
	serverInstanceID string,
) (result Session, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationSessionAuthenticate, started, err) }()
	tokenID, candidate, err := credentials.ParseSessionToken(token)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	dbRouteVersion, err := routeVersionToInt64(routeVersion)
	if err != nil {
		return Session{}, fmt.Errorf("routes: read session: %w", err)
	}
	dbSession, err := s.queries.GetRouteSessionForAuthentication(ctx, statedb.GetRouteSessionForAuthenticationParams{
		RouteID:      routeID,
		RouteVersion: dbRouteVersion,
		TokenID:      tokenID.String(),
		Now:          s.now().UnixNano(),
	})
	if errors.Is(err, sql.ErrNoRows) {
		// Known tokens are stale; unknown IDs remain unauthenticated.
		_, knownErr := s.queries.GetKnownRouteSessionTokenMarker(ctx, tokenID.String())
		if errors.Is(knownErr, sql.ErrNoRows) {
			return Session{}, ErrUnauthenticated
		}
		if knownErr != nil {
			return Session{}, fmt.Errorf("routes: identify session token: %w", knownErr)
		}
		return Session{}, ErrStaleSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("routes: read session: %w", err)
	}
	if dbSession.ServerInstanceID != serverInstanceID {
		return Session{}, ErrStaleSession
	}
	if !credentials.SecretHashMatches(dbSession.SecretHash, candidate) {
		return Session{}, ErrUnauthenticated
	}
	return sessionFromDB(dbSession), nil
}

func (s *Store) AuthenticateSessionForRenewal(
	ctx context.Context,
	routeID string,
	routeVersion uint64,
	token credentials.SessionToken,
	serverInstanceID string,
) (session Session, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationSessionAuthenticate, started, err) }()
	dbRouteVersion, err := routeVersionToInt64(routeVersion)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	tokenID, candidate, err := credentials.ParseSessionToken(token)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}
	dbSession, err := s.queries.GetRouteSessionByVersion(ctx, statedb.GetRouteSessionByVersionParams{
		RouteID: routeID, RouteVersion: dbRouteVersion,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrUnauthenticated
	}
	if err != nil {
		return Session{}, fmt.Errorf("routes: authenticate renewal session: %w", err)
	}
	if SessionStatus(dbSession.Status) == SessionStatusExpired || dbSession.ServerInstanceID != serverInstanceID ||
		dbSession.TokenID != tokenID.String() || !credentials.SecretHashMatches(dbSession.SecretHash, candidate) {
		return Session{}, ErrUnauthenticated
	}
	return sessionFromDB(dbSession), nil
}

func (s *Store) AttachRouteTransport(
	ctx context.Context,
	session Session,
	publisherPublicKey, relayRegion string,
) (err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationTransportRegister, started, err) }()
	if strings.TrimSpace(publisherPublicKey) == "" || strings.TrimSpace(relayRegion) == "" {
		return errors.New("routes: transport descriptor is incomplete")
	}
	dbRouteVersion, err := routeVersionToInt64(session.RouteVersion)
	if err != nil {
		return fmt.Errorf("routes: register transport: %w", err)
	}
	count, err := s.queries.RegisterRouteSessionTransport(ctx, statedb.RegisterRouteSessionTransportParams{
		PublisherPublicKey: sql.NullString{String: publisherPublicKey, Valid: true},
		RelayRegion:        sql.NullString{String: relayRegion, Valid: true},
		SessionID:          session.ID,
		RouteID:            session.RouteID,
		RouteVersion:       dbRouteVersion,
		Now:                s.now().UnixNano(),
	})
	if err != nil {
		return fmt.Errorf("routes: register transport: %w", err)
	}
	return requireCount(count, ErrStaleSession)
}

func (s *Store) Ready(ctx context.Context, session Session) (err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationRouteReady, started, err) }()
	dbRouteVersion, err := routeVersionToInt64(session.RouteVersion)
	if err != nil {
		return fmt.Errorf("routes: mark ready: %w", err)
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin ready: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	status, err := queries.GetRouteSessionStatus(ctx, statedb.GetRouteSessionStatusParams{
		SessionID: session.ID, RouteID: session.RouteID, RouteVersion: dbRouteVersion,
		Now: now.UnixNano(),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidStatus
	}
	if err != nil {
		return fmt.Errorf("routes: read ready status: %w", err)
	}
	if SessionStatus(status) == SessionStatusReady {
		return nil
	}
	count, err := queries.ReadyRouteSession(ctx, statedb.ReadyRouteSessionParams{
		SessionID:    session.ID,
		RouteID:      session.RouteID,
		RouteVersion: dbRouteVersion,
		Now:          now.UnixNano(),
	})
	if err != nil {
		return fmt.Errorf("routes: mark ready: %w", err)
	}
	if err := requireCount(count, ErrInvalidStatus); err != nil {
		return err
	}
	if err := s.recordLifecycle(ctx, queries, session.RouteID, session.RouteVersion, now, LifecycleReady); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit ready: %w", err)
	}
	return nil
}

func (s *Store) Heartbeat(ctx context.Context, session Session) (expiresAt time.Time, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationSessionHeartbeat, started, err) }()
	now := time.Unix(0, s.now().UnixNano()).UTC()
	expiresAt = now.Add(s.sessionLifetime)
	dbRouteVersion, err := routeVersionToInt64(session.RouteVersion)
	if err != nil {
		return time.Time{}, fmt.Errorf("routes: heartbeat: %w", err)
	}
	count, err := s.queries.HeartbeatRouteSession(ctx, statedb.HeartbeatRouteSessionParams{
		LastHeartbeatAt: now.UnixNano(),
		ExpiresAt:       expiresAt.UnixNano(),
		SessionID:       session.ID,
		RouteID:         session.RouteID,
		RouteVersion:    dbRouteVersion,
		Now:             now.UnixNano(),
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("routes: heartbeat: %w", err)
	}
	if err := requireCount(count, ErrStaleSession); err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}

func (s *Store) InvalidateOtherServerInstances(ctx context.Context, serverInstanceID string) error {
	if strings.TrimSpace(serverInstanceID) == "" {
		return errors.New("routes: server instance ID is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin prior server instance invalidation: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	sessions, err := queries.ListOtherServerInstanceRouteSessions(ctx, serverInstanceID)
	if err != nil {
		return fmt.Errorf("routes: list prior server instance sessions: %w", err)
	}
	if err := queries.InvalidateOtherServerInstanceRouteSessions(ctx, serverInstanceID); err != nil {
		return fmt.Errorf("routes: invalidate prior server instance sessions: %w", err)
	}
	now := s.now().UTC()
	for _, session := range sessions {
		if err := s.recordLifecycle(ctx, queries, session.RouteID, uint64(session.RouteVersion), now, LifecycleDisconnected); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit prior server instance invalidation: %w", err)
	}
	return nil
}

func (s *Store) Expire(ctx context.Context, routeID string, routeVersion uint64) (err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationSessionExpire, started, err) }()
	dbRouteVersion, err := routeVersionToInt64(routeVersion)
	if err != nil {
		return fmt.Errorf("routes: expire session: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin expire session: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	count, err := queries.ExpireRouteSession(ctx, statedb.ExpireRouteSessionParams{
		RouteID:      routeID,
		RouteVersion: dbRouteVersion,
	})
	if err != nil {
		return fmt.Errorf("routes: expire session: %w", err)
	}
	if err := requireCount(count, ErrStaleSession); err != nil {
		return err
	}
	if err := s.recordLifecycle(ctx, queries, routeID, routeVersion, s.now().UTC(), LifecycleDisconnected); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit expire session: %w", err)
	}
	return nil
}

func (s *Store) List(ctx context.Context, identityID string) ([]Route, error) {
	routes, err := s.queries.ListEnabledRoutes(ctx, identityID)
	if err != nil {
		return nil, fmt.Errorf("routes: list: %w", err)
	}
	var result []Route
	for _, route := range routes {
		result = append(result, routeFromDB(route))
	}
	return result, nil
}

func (s *Store) Delete(ctx context.Context, identityID, routeID string) error {
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin delete: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	routeVersion, err := queries.GetRouteVersion(ctx, routeID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("routes: read deleted route: %w", err)
	}
	count, err := queries.DeleteEnabledRoute(ctx, statedb.DeleteEnabledRouteParams{
		DeletedAt:  now.UnixNano(),
		RouteID:    routeID,
		IdentityID: identityID,
	})
	if err != nil {
		return fmt.Errorf("routes: delete: %w", err)
	}
	if err := requireCount(count, ErrNotFound); err != nil {
		return err
	}
	if err := queries.RevokeRouteCredential(ctx, statedb.RevokeRouteCredentialParams{
		RevokedAt: now.UnixNano(),
		RouteID:   routeID,
	}); err != nil {
		return fmt.Errorf("routes: revoke route credential: %w", err)
	}
	if err := queries.ExpireRouteSessions(ctx, routeID); err != nil {
		return fmt.Errorf("routes: expire deleted route: %w", err)
	}
	if err := queries.RetireTemporaryHostnameByRoute(ctx, statedb.RetireTemporaryHostnameByRouteParams{
		DeactivatedAt: now.UnixNano(), RouteID: routeID,
	}); err != nil {
		return fmt.Errorf("routes: retire temporary hostname: %w", err)
	}
	if err := s.recordLifecycle(ctx, queries, routeID, uint64(routeVersion), now, LifecycleDisconnected); err != nil {
		return err
	}
	if err := s.recordLifecycle(ctx, queries, routeID, uint64(routeVersion), now, LifecycleDeleted); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit delete: %w", err)
	}
	return nil
}

func (s *Store) CleanupAbandonedTemporary(ctx context.Context, now time.Time) ([]string, error) {
	cutoff := now.Add(-TemporaryReacquisitionWindow)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("routes: begin temporary cleanup: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	if err := queries.RetireAbandonedTemporaryHostnames(ctx, statedb.RetireAbandonedTemporaryHostnamesParams{
		DeactivatedAt: now.UnixNano(), CreatedBefore: cutoff.UnixNano(),
	}); err != nil {
		return nil, fmt.Errorf("routes: burn abandoned holds: %w", err)
	}
	abandoned, err := queries.ListAbandonedTemporaryRoutes(ctx, cutoff.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("routes: list abandoned temporary routes: %w", err)
	}
	removed := make([]string, 0, len(abandoned))
	for _, route := range abandoned {
		routeIDs, err := s.stopHostnameRoutes(ctx, queries, route.HostnameID, now)
		if err != nil {
			return nil, err
		}
		if err := queries.RetireTemporaryHostnameByRoute(ctx, statedb.RetireTemporaryHostnameByRouteParams{
			DeactivatedAt: now.UnixNano(), RouteID: route.RouteID,
		}); err != nil {
			return nil, fmt.Errorf("routes: retire abandoned temporary hostname: %w", err)
		}
		removed = append(removed, routeIDs...)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("routes: commit temporary cleanup: %w", err)
	}
	return removed, nil
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

func validateAllowedIPPrefixes(values []string) ([]string, error) {
	canonical, err := authorization.CanonicalizeIPPrefixes(values)
	if err != nil || (values == nil) != (canonical == nil) || !slices.Equal(values, canonical) {
		return nil, ErrInvalidArgument
	}
	return canonical, nil
}

func requireCount(count int64, missing error) error {
	if count == 0 {
		return missing
	}
	return nil
}

func routeFromDB(route statedb.Route) Route {
	result := Route{
		ID:                 route.ID,
		HostnameID:         route.HostnameID.String,
		IdentityID:         route.IdentityID.String,
		Hostname:           route.Hostname,
		LocalTarget:        route.LocalTarget,
		Status:             RouteStatus(route.Status),
		RouteVersion:       uint64(route.RouteVersion),
		SuspensionRevision: uint64(route.SuspensionRevision),
		SuspensionReason:   route.SuspensionReason.String,
		CreatedAt:          time.Unix(0, route.CreatedAt).UTC(),
	}
	if route.SuspendedAt.Valid {
		result.SuspendedAt = time.Unix(0, route.SuspendedAt.Int64).UTC()
	}
	if route.DeletedAt.Valid {
		result.DeletedAt = time.Unix(0, route.DeletedAt.Int64).UTC()
	}
	if route.AuthorizationID.Valid {
		result.AuthorizationIssuer = route.AuthorizationIssuer.String
		result.AuthorizationID = route.AuthorizationID.String
		result.AuthorizationKeyID = route.AuthorizationKeyID.String
		result.AuthorizationRetryID = route.AuthorizationRetryID.String
		result.AuthorizationRevision = uint64(route.AuthorizationRevision.Int64)
		result.AuthorizationExpiresAt = time.Unix(0, route.AuthorizationExpiresAt.Int64).UTC()
		copy(result.AuthorizationRequestHash[:], route.AuthorizationRequestHash)
		if len(route.AuthorizationIpPolicyHash) != 0 {
			digest := new(authorization.Digest)
			copy(digest[:], route.AuthorizationIpPolicyHash)
			result.AuthorizationIPPolicyHash = digest
		}
	}
	return result
}

func sessionFromDB(session statedb.RouteSession) Session {
	return Session{
		ID:                 session.ID,
		RouteID:            session.RouteID,
		RouteVersion:       uint64(session.RouteVersion),
		Status:             SessionStatus(session.Status),
		ServerInstanceID:   session.ServerInstanceID,
		PublisherPublicKey: session.PublisherPublicKey.String,
		RelayRegion:        session.RelayRegion.String,
		CreatedAt:          time.Unix(0, session.CreatedAt).UTC(),
		LastHeartbeatAt:    time.Unix(0, session.LastHeartbeatAt).UTC(),
		ExpiresAt:          time.Unix(0, session.ExpiresAt).UTC(),
	}
}

func routeVersionToInt64(routeVersion uint64) (int64, error) {
	if routeVersion > math.MaxInt64 {
		return 0, errors.New("uint64 route version exceeds database integer range")
	}
	return int64(routeVersion), nil
}

func newID(prefix string) (string, error) {
	id, err := opaqueid.New(prefix + "_")
	if err != nil {
		return "", fmt.Errorf("routes: generate %s ID: %w", prefix, err)
	}
	return id, nil
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
	routeVersion uint64,
	occurredAt time.Time,
	transition LifecycleTransition,
) error {
	if s.lifecycleRecorder == nil {
		return nil
	}
	if err := s.lifecycleRecorder.RecordLifecycle(ctx, queries, LifecycleChange{
		RouteID: routeID, RouteVersion: routeVersion, OccurredAt: occurredAt, Transition: transition,
	}); err != nil {
		return fmt.Errorf("routes: record lifecycle: %w", err)
	}
	return nil
}

func (s *Store) recordRegistration(
	ctx context.Context,
	queries *statedb.Queries,
	registration RouteRegistration,
) error {
	if s.lifecycleRecorder == nil {
		return nil
	}
	if err := s.lifecycleRecorder.RecordRegistration(ctx, queries, registration); err != nil {
		return fmt.Errorf("routes: record registration: %w", err)
	}
	return nil
}
