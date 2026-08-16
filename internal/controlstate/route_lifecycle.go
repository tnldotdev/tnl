package controlstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
)

var (
	ErrRouteSessionCredential = errors.New("controlstate: route-session credential is invalid")
	ErrRouteSessionStale      = errors.New("controlstate: route session identity or version is stale")
	ErrRouteSessionNotReady   = errors.New("controlstate: route session is not ready")
	ErrRouteCertificate       = errors.New("controlstate: route certificate acknowledgement is invalid")
)

// RouteSessionAuthentication binds a route session credential to one exact route version.
type RouteSessionAuthentication struct {
	RouteSessionID    string
	RouteID           string
	RouteVersion      uint64
	RouteSessionToken credentials.RouteSessionToken
}

// RouteSessionLifecycle reports saved readiness and current publisher connection availability.
type RouteSessionLifecycle struct {
	RouteSessionID                string
	RouteID                       string
	TeamID                        string
	MembershipID                  string
	RouteVersion                  uint64
	PolicyRevision                uint64
	State                         RouteSessionState
	CreatedAt                     time.Time
	ExpiresAt                     time.Time
	ReadyAt                       *time.Time
	CertificateAt                 *time.Time
	ClosedAt                      *time.Time
	ReadyPublisherConnectionCount int
	Routable                      bool
	RoutingTableRevision          uint64
	RouteEntryRevision            uint64
}

func (d *Database) RouteSessionAuthentication(
	ctx context.Context,
	routeSessionID string,
	routeVersion uint64,
	token credentials.RouteSessionToken,
) (RouteSessionAuthentication, error) {
	if err := d.requireOpen(); err != nil {
		return RouteSessionAuthentication{}, err
	}
	if !validStateText(routeSessionID) {
		return RouteSessionAuthentication{}, ErrRouteSessionCredential
	}
	if _, ok := positiveInt64(routeVersion); !ok {
		return RouteSessionAuthentication{}, ErrRouteSessionCredential
	}
	tokenID, tokenHash, err := credentials.ParseRouteSessionToken(token)
	if err != nil {
		return RouteSessionAuthentication{}, ErrRouteSessionCredential
	}
	session, err := controlstatedb.New(d.pool).GetRouteSession(ctx, routeSessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return RouteSessionAuthentication{}, ErrRouteSessionCredential
	}
	if err != nil {
		return RouteSessionAuthentication{}, fmt.Errorf("controlstate: read route session authentication: %w", err)
	}
	if !matchesPositiveInt64(session.RouteVersion, routeVersion) || tokenID.String() != session.SessionTokenID ||
		!credentials.SecretHashMatches(session.SessionTokenDigest, tokenHash) {
		return RouteSessionAuthentication{}, ErrRouteSessionCredential
	}
	return RouteSessionAuthentication{
		RouteSessionID: routeSessionID, RouteID: session.RouteID, RouteVersion: routeVersion, RouteSessionToken: token,
	}, nil
}

func (d *Database) MarkRouteSessionReady(
	ctx context.Context,
	authentication RouteSessionAuthentication,
	now time.Time,
) (result RouteSessionLifecycle, retErr error) {
	if err := validateRouteSessionAuthentication(authentication); err != nil {
		return RouteSessionLifecycle{}, err
	}
	if err := d.requireOpen(); err != nil {
		return RouteSessionLifecycle{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return RouteSessionLifecycle{}, fmt.Errorf("controlstate: mark route session ready: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "mark route session ready", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	route, session, err := lockAuthenticatedRouteSession(ctx, queries, authentication, now)
	if err != nil {
		return RouteSessionLifecycle{}, err
	}
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return RouteSessionLifecycle{}, err
	}
	var publishedEvent *publishedIngressRoutingTableEvent
	if !session.ReadyAt.Valid {
		if !session.CertificateInstalledAt.Valid || len(connections) != routeSessionConnectionCount {
			return RouteSessionLifecycle{}, ErrRouteSessionNotReady
		}
		session, err = queries.MarkRouteSessionReady(ctx, controlstatedb.MarkRouteSessionReadyParams{
			ReadyAt: timestamptz(now), RouteSessionID: session.ID,
			RouteID: route.ID, RouteVersion: session.RouteVersion,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return RouteSessionLifecycle{}, ErrRouteSessionStale
		}
		if err != nil {
			return RouteSessionLifecycle{}, fmt.Errorf("controlstate: mark route session ready: update session: %w", err)
		}
		publishedEvent, err = pendingEvents.addRouteEvent(
			ctx, queries, route, session, connections, "route_upsert", now,
		)
		if err != nil {
			return RouteSessionLifecycle{}, err
		}
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return RouteSessionLifecycle{}, err
	}
	var routingTableRevision, routeEntryRevision int64
	if publishedEvent != nil {
		routingTableRevision = publishedEvent.routingTableRevision
		routeEntryRevision = publishedEvent.entryRevision
	}
	if err := tx.Commit(ctx); err != nil {
		return RouteSessionLifecycle{}, fmt.Errorf("controlstate: mark route session ready: commit: %w", err)
	}
	return routeSessionLifecycle(session, connections, routingTableRevision, routeEntryRevision), nil
}

// IngressRoutingTableProjection is the stored route view used by ingress.
type IngressRoutingTableProjection struct {
	RouteSessionID       string                                   `json:"route_session_id"`
	RouteID              string                                   `json:"route_id"`
	RouteVersion         uint64                                   `json:"route_version"`
	CanonicalHostname    string                                   `json:"canonical_hostname"`
	PolicyRevision       uint64                                   `json:"policy_revision"`
	IPPolicy             string                                   `json:"ip_policy"`
	AllowedIPPrefixes    []netip.Prefix                           `json:"allowed_ip_prefixes"`
	RouteExpiresAt       time.Time                                `json:"route_expires_at"`
	RecoveryEpisodeID    *uint64                                  `json:"recovery_episode_id,omitempty"`
	PublisherConnections []IngressRoutingTablePublisherConnection `json:"publisher_connections"`
}

// IngressRoutingTablePublisherConnection identifies one connected relay that
// ingress may use for a visitor connection.
type IngressRoutingTablePublisherConnection struct {
	ConnectionSlot               int       `json:"connection_slot"`
	PublisherConnectionID        string    `json:"publisher_connection_id"`
	ConnectionAssignmentRevision uint64    `json:"connection_assignment_revision"`
	RelayServiceID               string    `json:"relay_service_id"`
	RelayID                      string    `json:"relay_id"`
	RelayRunID                   string    `json:"relay_run_id"`
	RelayLeaseRevision           uint64    `json:"relay_lease_revision"`
	InternalRelayAddress         string    `json:"internal_relay_address"`
	TLSServerName                string    `json:"tls_server_name"`
	LeaseExpiresAt               time.Time `json:"lease_expires_at"`
}

// MarkRouteCertificateInstalled records publisher acknowledgement of the
// installed route certificate. First routability still requires both connections.
func (d *Database) MarkRouteCertificateInstalled(
	ctx context.Context,
	authentication RouteSessionAuthentication,
	issuanceID string,
	notAfter time.Time,
	now time.Time,
) (result RouteSessionLifecycle, retErr error) {
	if err := validateRouteSessionAuthentication(authentication); err != nil {
		return RouteSessionLifecycle{}, err
	}
	if !validStateText(issuanceID) || !notAfter.After(now) {
		return RouteSessionLifecycle{}, ErrRouteCertificate
	}
	if err := d.requireOpen(); err != nil {
		return RouteSessionLifecycle{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return RouteSessionLifecycle{}, fmt.Errorf("controlstate: install route certificate: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "install route certificate", &retErr)()
	queries := controlstatedb.New(tx)
	route, session, err := lockAuthenticatedRouteSession(ctx, queries, authentication, now)
	if err != nil {
		return RouteSessionLifecycle{}, err
	}
	order, err := queries.LockACMEOrderForInstall(ctx, controlstatedb.LockACMEOrderForInstallParams{
		IssuanceID: issuanceID, TeamID: session.TeamID, CertificateCacheKey: session.CertificateCacheKey,
		CertificateScope: session.CertificateScope, CertificateIdentifiers: session.CertificateIdentifiers,
		ChallengeMethod: session.CertificateChallenge,
		NotAfter:        timestamptz(notAfter), InstalledAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RouteSessionLifecycle{}, ErrRouteCertificate
	} else if err != nil {
		return RouteSessionLifecycle{}, fmt.Errorf("controlstate: install route certificate: lock issuance: %w", err)
	}
	if !validInstalledCertificate(order, route.CanonicalHostname, now) {
		return RouteSessionLifecycle{}, ErrRouteCertificate
	}
	if _, err := queries.MarkACMEOrderInstalled(ctx, controlstatedb.MarkACMEOrderInstalledParams{
		InstalledAt: timestamptz(now), IssuanceID: issuanceID,
	}); errors.Is(err, pgx.ErrNoRows) {
		return RouteSessionLifecycle{}, ErrRouteCertificate
	} else if err != nil {
		return RouteSessionLifecycle{}, fmt.Errorf("controlstate: install route certificate: update issuance: %w", err)
	}
	session, err = queries.MarkRouteSessionCertificateInstalled(ctx, controlstatedb.MarkRouteSessionCertificateInstalledParams{
		InstalledAt: timestamptz(now), IssuanceID: text(issuanceID), NotAfter: timestamptz(notAfter),
		RouteSessionID: session.ID, RouteID: session.RouteID, RouteVersion: session.RouteVersion,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RouteSessionLifecycle{}, ErrRouteCertificate
	}
	if err != nil {
		return RouteSessionLifecycle{}, fmt.Errorf("controlstate: install route certificate: update session: %w", err)
	}
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return RouteSessionLifecycle{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RouteSessionLifecycle{}, fmt.Errorf("controlstate: install route certificate: commit: %w", err)
	}
	return routeSessionLifecycle(session, connections, 0, 0), nil
}

// HeartbeatRouteSession extends one route session and returns current or
// replacement publisher connection assignments.
func (d *Database) HeartbeatRouteSession(
	ctx context.Context,
	authentication RouteSessionAuthentication,
	now time.Time,
	leaseDuration time.Duration,
	connectionCredentialDuration time.Duration,
) (result RouteSessionSetup, retErr error) {
	if err := validateRouteSessionAuthentication(authentication); err != nil {
		return RouteSessionSetup{}, err
	}
	if leaseDuration <= 0 || connectionCredentialDuration <= 0 {
		return RouteSessionSetup{}, errors.New("controlstate: route-session heartbeat durations must be positive")
	}
	if err := d.requireOpen(); err != nil {
		return RouteSessionSetup{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: heartbeat route session: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "heartbeat route session", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	route, session, err := lockAuthenticatedRouteSession(ctx, queries, authentication, now)
	if err != nil {
		return RouteSessionSetup{}, err
	}
	if route.Ephemeral {
		if _, err := queries.RenewEphemeralRouteExpiry(ctx, controlstatedb.RenewEphemeralRouteExpiryParams{
			ExpiresAt: timestamptz(now.Add(ephemeralRouteGracePeriod)), RouteID: route.ID,
		}); err != nil {
			return RouteSessionSetup{}, fmt.Errorf("controlstate: heartbeat route session: renew ephemeral route: %w", err)
		}
	}
	previousExpiresAt := session.PublisherExpiresAt.Time
	session, err = queries.HeartbeatRouteSession(ctx, controlstatedb.HeartbeatRouteSessionParams{
		HeartbeatAt: timestamptz(now), ExpiresAt: timestamptz(now.Add(leaseDuration)),
		RouteSessionID: session.ID, RouteID: route.ID, RouteVersion: session.RouteVersion,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RouteSessionSetup{}, ErrRouteSessionStale
	}
	if err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: heartbeat route session: update lease: %w", err)
	}
	leaseExtended := session.PublisherExpiresAt.Time.After(previousExpiresAt)
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return RouteSessionSetup{}, err
	}
	removedReadyConnection := false
	if len(connections) != routeSessionConnectionCount {
		removedReadyConnection, err = replenishRouteSessionConnections(
			ctx, queries, session, authentication.RouteSessionToken, now, connectionCredentialDuration,
		)
		if err != nil {
			return RouteSessionSetup{}, err
		}
		connections, err = validReadyPublisherConnections(ctx, queries, session.ID, now)
		if err != nil {
			return RouteSessionSetup{}, err
		}
	}
	if session.PolicyDenials < 0 {
		return RouteSessionSetup{}, errors.New("controlstate: heartbeat route session: invalid policy denial count")
	}
	if session.ReadyAt.Valid && removedReadyConnection {
		if err := openRouteRecoveryEpisode(ctx, queries, route.ID, session.RouteVersion, now); err != nil {
			return RouteSessionSetup{}, err
		}
	}
	if session.ReadyAt.Valid && (leaseExtended && len(connections) > 0 || removedReadyConnection) {
		eventKind := routeRoutingTableEventKind(len(connections) > 0)
		if _, err := pendingEvents.addRouteEvent(ctx, queries, route, session, connections, eventKind, now); err != nil {
			return RouteSessionSetup{}, err
		}
	}
	if leaseExtended && len(connections) > 0 || removedReadyConnection {
		if err := pendingEvents.addCurrentChallengeEvent(ctx, queries, route, session, connections, now); err != nil {
			return RouteSessionSetup{}, err
		}
	}
	setup, err := loadRouteSessionSetupWithToken(ctx, queries, authentication.RouteSessionToken, session)
	if err != nil {
		return RouteSessionSetup{}, err
	}
	setup.PolicyDenials = uint64(session.PolicyDenials)
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return RouteSessionSetup{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RouteSessionSetup{}, fmt.Errorf("controlstate: heartbeat route session: commit: %w", err)
	}
	return setup, nil
}

func (d *Database) markPublisherConnectionReady(
	ctx context.Context,
	request PublisherConnectionClaimRequest,
	now time.Time,
) (result ClaimedPublisherConnection, retErr error) {
	if err := validatePublisherConnectionClaim(request); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if err := d.requireOpen(); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: mark publisher connection ready: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "mark publisher connection ready", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	route, session, err := lockRouteSessionForPublisherConnection(ctx, queries, request, now)
	if err != nil {
		return ClaimedPublisherConnection{}, err
	}
	before, err := queries.GetPublisherConnectionForClaim(ctx, request.PublisherConnectionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrPublisherConnectionUnavailable
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: mark publisher connection ready: lock assignment: %w", err)
	}
	beforeState := PublisherConnectionState(before.State)
	if !storedConnectionAssignmentMatches(before, request.ConnectionAssignmentIdentity) ||
		!publisherConnectionClaimMatches(before, request) ||
		beforeState != PublisherConnectionConnected && beforeState != PublisherConnectionReady {
		return ClaimedPublisherConnection{}, ErrConnectionAssignmentStale
	}
	lease, err := queries.GetRelayLeaseForClaim(ctx, request.RelayID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrRelayLeaseStale
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: mark publisher connection ready: lock relay lease: %w", err)
	}
	if err := validateClaimRelayLease(lease, request.RelayLeaseIdentity, before.RelayServiceID, now); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	row, err := queries.MarkPublisherConnectionReady(ctx, publisherConnectionClaimParams(request, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrConnectionAssignmentStale
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: mark publisher connection ready: update assignment: %w", err)
	}
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if beforeState != PublisherConnectionReady {
		if err := pendingEvents.addPublisherConnectionChanges(ctx, queries, route, session, connections, now); err != nil {
			return ClaimedPublisherConnection{}, err
		}
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: mark publisher connection ready: commit: %w", err)
	}
	return claimedPublisherConnection(row)
}

func (d *Database) disconnectPublisherConnection(
	ctx context.Context,
	request PublisherConnectionClaimRequest,
	now time.Time,
	unexpected bool,
) (result ClaimedPublisherConnection, retErr error) {
	if err := validatePublisherConnectionClaim(request); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if err := d.requireOpen(); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: disconnect publisher connection: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "disconnect publisher connection", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	route, session, err := lockRouteSessionForPublisherConnection(ctx, queries, request, now)
	if err != nil {
		return ClaimedPublisherConnection{}, err
	}
	before, err := queries.GetPublisherConnectionForClaim(ctx, request.PublisherConnectionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrPublisherConnectionUnavailable
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: disconnect publisher connection: lock assignment: %w", err)
	}
	beforeState := PublisherConnectionState(before.State)
	if !storedConnectionAssignmentMatches(before, request.ConnectionAssignmentIdentity) ||
		!publisherConnectionClaimMatches(before, request) ||
		beforeState != PublisherConnectionConnected && beforeState != PublisherConnectionReady && beforeState != PublisherConnectionDraining {
		return ClaimedPublisherConnection{}, ErrConnectionAssignmentStale
	}
	row, err := queries.DisconnectPublisherConnection(ctx, disconnectPublisherConnectionParams(request, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrConnectionAssignmentStale
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: disconnect publisher connection: update assignment: %w", err)
	}
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if session.ReadyAt.Valid && beforeState == PublisherConnectionReady && unexpected {
		if err := openRouteRecoveryEpisode(ctx, queries, route.ID, session.RouteVersion, now); err != nil {
			return ClaimedPublisherConnection{}, err
		}
	}
	if beforeState == PublisherConnectionReady {
		if err := pendingEvents.addPublisherConnectionChanges(ctx, queries, route, session, connections, now); err != nil {
			return ClaimedPublisherConnection{}, err
		}
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: disconnect publisher connection: commit: %w", err)
	}
	return claimedPublisherConnection(row)
}

func lockRouteSessionForPublisherConnection(
	ctx context.Context,
	queries *controlstatedb.Queries,
	request PublisherConnectionClaimRequest,
	now time.Time,
) (controlstatedb.ControlRoute, controlstatedb.ControlRouteSession, error) {
	route, err := queries.LockRouteForSession(ctx, request.RouteID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlRoute{}, controlstatedb.ControlRouteSession{}, ErrConnectionAssignmentStale
	}
	if err != nil {
		return controlstatedb.ControlRoute{}, controlstatedb.ControlRouteSession{}, fmt.Errorf("controlstate: lock publisher connection route: %w", err)
	}
	session, err := queries.LockRouteSession(ctx, request.RouteSessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlRoute{}, controlstatedb.ControlRouteSession{}, ErrConnectionAssignmentStale
	}
	if err != nil {
		return controlstatedb.ControlRoute{}, controlstatedb.ControlRouteSession{}, fmt.Errorf("controlstate: lock publisher connection route session: %w", err)
	}
	if RouteLifecycleState(route.LifecycleState) != RouteLifecycleEnabled || session.RouteID != request.RouteID ||
		!matchesPositiveInt64(session.RouteVersion, request.RouteVersion) || session.ClosedAt.Valid ||
		!session.PublisherExpiresAt.Valid || !session.PublisherExpiresAt.Time.After(now) {
		return controlstatedb.ControlRoute{}, controlstatedb.ControlRouteSession{}, ErrConnectionAssignmentStale
	}
	return route, session, nil
}

func lockAuthenticatedRouteSession(
	ctx context.Context,
	queries *controlstatedb.Queries,
	authentication RouteSessionAuthentication,
	now time.Time,
) (controlstatedb.ControlRoute, controlstatedb.ControlRouteSession, error) {
	route, err := queries.LockRouteForSession(ctx, authentication.RouteID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlRoute{}, controlstatedb.ControlRouteSession{}, ErrRouteSessionStale
	}
	if err != nil {
		return controlstatedb.ControlRoute{}, controlstatedb.ControlRouteSession{}, fmt.Errorf("controlstate: lock authenticated route: %w", err)
	}
	session, err := queries.LockRouteSession(ctx, authentication.RouteSessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlRoute{}, controlstatedb.ControlRouteSession{}, ErrRouteSessionStale
	}
	if err != nil {
		return controlstatedb.ControlRoute{}, controlstatedb.ControlRouteSession{}, fmt.Errorf("controlstate: lock authenticated route session: %w", err)
	}
	if RouteLifecycleState(route.LifecycleState) != RouteLifecycleEnabled || session.RouteID != authentication.RouteID ||
		!matchesPositiveInt64(session.RouteVersion, authentication.RouteVersion) || session.ClosedAt.Valid ||
		!session.PublisherExpiresAt.Valid || !session.PublisherExpiresAt.Time.After(now) {
		return controlstatedb.ControlRoute{}, controlstatedb.ControlRouteSession{}, ErrRouteSessionStale
	}
	tokenID, tokenHash, err := credentials.ParseRouteSessionToken(authentication.RouteSessionToken)
	if err != nil || tokenID.String() != session.SessionTokenID ||
		!credentials.SecretHashMatches(session.SessionTokenDigest, tokenHash) {
		return controlstatedb.ControlRoute{}, controlstatedb.ControlRouteSession{}, ErrRouteSessionCredential
	}
	return route, session, nil
}

func validReadyPublisherConnections(
	ctx context.Context,
	queries *controlstatedb.Queries,
	routeSessionID string,
	now time.Time,
) ([]controlstatedb.ListValidReadyPublisherConnectionsRow, error) {
	connections, err := queries.ListValidReadyPublisherConnections(
		ctx, controlstatedb.ListValidReadyPublisherConnectionsParams{
			RouteSessionID: routeSessionID, Now: timestamptz(now),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("controlstate: list ready publisher connections: %w", err)
	}
	return connections, nil
}

func activeRouteSessionChallengeExpiry(
	ctx context.Context,
	queries *controlstatedb.Queries,
	routeSessionID string,
	now time.Time,
) (time.Time, bool, error) {
	expiresAt, err := queries.GetActiveRouteSessionChallengeExpiry(ctx, controlstatedb.GetActiveRouteSessionChallengeExpiryParams{
		RouteSessionID: routeSessionID, Now: timestamptz(now),
	})
	if err != nil {
		return time.Time{}, false, fmt.Errorf("controlstate: read active route-session challenge: %w", err)
	}
	if !expiresAt.Valid {
		return time.Time{}, false, nil
	}
	return expiresAt.Time, true, nil
}

func (pending *pendingIngressRoutingTableEvents) addPublisherConnectionChanges(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlRoute,
	session controlstatedb.ControlRouteSession,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	now time.Time,
) error {
	if session.ReadyAt.Valid {
		if _, err := pending.addRouteEvent(
			ctx, queries, route, session, connections,
			routeRoutingTableEventKind(len(connections) > 0), now,
		); err != nil {
			return err
		}
	}
	return pending.addCurrentChallengeEvent(ctx, queries, route, session, connections, now)
}

func (pending *pendingIngressRoutingTableEvents) addCurrentChallengeEvent(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlRoute,
	session controlstatedb.ControlRouteSession,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	now time.Time,
) error {
	challengeExpiresAt, challengeActive, err := activeRouteSessionChallengeExpiry(ctx, queries, session.ID, now)
	if err != nil || !challengeActive {
		return err
	}
	_, err = pending.addChallengeEvent(
		ctx, queries, route, session, connections,
		challengeRoutingTableEventKind(len(connections) > 0), challengeExpiresAt, now,
	)
	return err
}

func routeRoutingTableEventKind(available bool) IngressRoutingTableEventKind {
	if available {
		return IngressRouteUpsert
	}
	return IngressRouteTombstone
}

func challengeRoutingTableEventKind(available bool) IngressRoutingTableEventKind {
	if available {
		return IngressChallengeUpsert
	}
	return IngressChallengeTombstone
}

func (pending *pendingIngressRoutingTableEvents) addRouteEvent(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlRoute,
	session controlstatedb.ControlRouteSession,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	eventKind IngressRoutingTableEventKind,
	now time.Time,
) (*publishedIngressRoutingTableEvent, error) {
	return pending.addEvent(ctx, queries, route, session, connections, eventKind, session.PublisherExpiresAt.Time, now)
}

func (pending *pendingIngressRoutingTableEvents) addChallengeEvent(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlRoute,
	session controlstatedb.ControlRouteSession,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	eventKind IngressRoutingTableEventKind,
	expiresAt time.Time,
	now time.Time,
) (*publishedIngressRoutingTableEvent, error) {
	if session.PublisherExpiresAt.Time.Before(expiresAt) {
		expiresAt = session.PublisherExpiresAt.Time
	}
	return pending.addEvent(ctx, queries, route, session, connections, eventKind, expiresAt, now)
}

type publishedIngressRoutingTableEvent struct {
	routingTableRevision int64
	entryRevision        int64
}

type pendingIngressRoutingTableEvent struct {
	eventKind           IngressRoutingTableEventKind
	routeID             string
	routeVersion        int64
	canonicalHostname   string
	projection          []byte
	projectionExpiresAt time.Time
	createdAt           time.Time
	published           *publishedIngressRoutingTableEvent
}

type pendingIngressRoutingTableEvents struct {
	events []pendingIngressRoutingTableEvent
}

func (pending *pendingIngressRoutingTableEvents) addEvent(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlRoute,
	session controlstatedb.ControlRouteSession,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	eventKind IngressRoutingTableEventKind,
	projectionExpiresAt time.Time,
	now time.Time,
) (*publishedIngressRoutingTableEvent, error) {
	projection := IngressRoutingTableProjection{
		RouteSessionID: session.ID, RouteID: route.ID, RouteVersion: uint64(session.RouteVersion),
		CanonicalHostname: route.CanonicalHostname, PolicyRevision: uint64(route.PolicyRevision),
		IPPolicy: route.IpPolicy, AllowedIPPrefixes: append([]netip.Prefix(nil), route.AllowedIpPrefixes...),
		RouteExpiresAt:       projectionExpiresAt,
		PublisherConnections: make([]IngressRoutingTablePublisherConnection, 0, len(connections)),
	}
	if projection.AllowedIPPrefixes == nil {
		projection.AllowedIPPrefixes = []netip.Prefix{}
	}
	if eventKind == "route_upsert" {
		episode, err := queries.GetOpenRouteRecoveryEpisode(ctx, controlstatedb.GetOpenRouteRecoveryEpisodeParams{
			RouteID: route.ID, RouteVersion: session.RouteVersion,
		})
		if err == nil {
			value := uint64(episode.RecoveryEpisodeID)
			projection.RecoveryEpisodeID = &value
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("controlstate: read route recovery episode: %w", err)
		}
	}
	for _, connection := range connections {
		if !connection.ConnectedRelayID.Valid || !connection.ConnectedRelayRunID.Valid ||
			!connection.ConnectedRelayLeaseRevision.Valid || connection.ConnectedRelayLeaseRevision.Int64 <= 0 ||
			connection.ConnectionAssignmentRevision <= 0 || !connection.LeaseExpiresAt.Valid {
			return nil, errors.New("controlstate: invalid ingress routing-table publisher connection row")
		}
		projection.PublisherConnections = append(projection.PublisherConnections, IngressRoutingTablePublisherConnection{
			ConnectionSlot: int(connection.ConnectionSlot), PublisherConnectionID: connection.PublisherConnectionID,
			ConnectionAssignmentRevision: uint64(connection.ConnectionAssignmentRevision),
			RelayServiceID:               connection.RelayServiceID, RelayID: connection.ConnectedRelayID.String,
			RelayRunID:           connection.ConnectedRelayRunID.String,
			RelayLeaseRevision:   uint64(connection.ConnectedRelayLeaseRevision.Int64),
			InternalRelayAddress: connection.InternalRelayAddress, TLSServerName: connection.TlsServerName,
			LeaseExpiresAt: connection.LeaseExpiresAt.Time,
		})
	}
	payload, err := json.Marshal(projection)
	if err != nil {
		return nil, fmt.Errorf("controlstate: encode ingress routing-table projection: %w", err)
	}
	published := &publishedIngressRoutingTableEvent{}
	pending.events = append(pending.events, pendingIngressRoutingTableEvent{
		eventKind: eventKind, routeID: route.ID, routeVersion: session.RouteVersion,
		canonicalHostname: route.CanonicalHostname, projection: payload,
		projectionExpiresAt: projectionExpiresAt, createdAt: now, published: published,
	})
	return published, nil
}

func (pending *pendingIngressRoutingTableEvents) publish(ctx context.Context, queries *controlstatedb.Queries) error {
	if len(pending.events) == 0 {
		return nil
	}
	// Callers hold each event's route row through commit, so same-route
	// publishers cannot change these entry revisions concurrently.
	type routeVersion struct {
		routeID      string
		routeVersion int64
	}
	entryRevisionsByRoute := make(map[routeVersion]int64)
	entryRevisions := make([]int64, len(pending.events))
	for index := range pending.events {
		event := &pending.events[index]
		key := routeVersion{routeID: event.routeID, routeVersion: event.routeVersion}
		entryRevision, found := entryRevisionsByRoute[key]
		if !found {
			var err error
			entryRevision, err = queries.LatestIngressRoutingEntryRevision(ctx, controlstatedb.LatestIngressRoutingEntryRevisionParams{
				RouteID: event.routeID, RouteVersion: event.routeVersion,
			})
			if err != nil {
				return fmt.Errorf("controlstate: read ingress routing-table entry revision: %w", err)
			}
		}
		if entryRevision == math.MaxInt64 {
			return errors.New("controlstate: ingress routing-table entry revision is exhausted")
		}
		entryRevision++
		entryRevisionsByRoute[key] = entryRevision
		entryRevisions[index] = entryRevision
	}
	// This is the transaction's final phase. The clock remains held through
	// commit, and callers must not perform further database work after it.
	if _, err := queries.LockIngressRoutingTableClock(ctx); err != nil {
		return fmt.Errorf("controlstate: lock ingress routing-table clock: %w", err)
	}
	for index := range pending.events {
		event := &pending.events[index]
		routeExpiresAt := pgtype.Timestamptz{}
		if event.eventKind == IngressRouteUpsert || event.eventKind == IngressChallengeUpsert {
			routeExpiresAt = timestamptz(event.projectionExpiresAt)
		}
		var routingTableRevision int64
		var err error
		if index == len(pending.events)-1 {
			routingTableRevision, err = queries.InsertFinalIngressRoutingTableEvent(ctx, controlstatedb.InsertFinalIngressRoutingTableEventParams{
				EventKind: string(event.eventKind), RouteID: event.routeID, RouteVersion: event.routeVersion,
				CanonicalHostname: event.canonicalHostname, EntryRevision: entryRevisions[index],
				Projection: event.projection, RouteExpiresAt: routeExpiresAt, CreatedAt: timestamptz(event.createdAt),
				UpdatedAt: timestamptz(event.createdAt),
			})
		} else {
			routingTableRevision, err = queries.InsertIngressRoutingTableEvent(ctx, controlstatedb.InsertIngressRoutingTableEventParams{
				EventKind: string(event.eventKind), RouteID: event.routeID, RouteVersion: event.routeVersion,
				CanonicalHostname: event.canonicalHostname, EntryRevision: entryRevisions[index],
				Projection: event.projection, RouteExpiresAt: routeExpiresAt, CreatedAt: timestamptz(event.createdAt),
			})
		}
		if err != nil {
			return fmt.Errorf("controlstate: insert ingress routing-table event: %w", err)
		}
		event.published.routingTableRevision = routingTableRevision
		event.published.entryRevision = entryRevisions[index]
	}
	return nil
}

func openRouteRecoveryEpisode(
	ctx context.Context,
	queries *controlstatedb.Queries,
	routeID string,
	routeVersion int64,
	now time.Time,
) error {
	if err := queries.OpenRouteRecoveryEpisode(ctx, controlstatedb.OpenRouteRecoveryEpisodeParams{
		RouteID: routeID, RouteVersion: routeVersion, OpenedAt: timestamptz(now),
	}); err != nil {
		return fmt.Errorf("controlstate: open route recovery episode: %w", err)
	}
	return nil
}

func routeSessionLifecycle(
	session controlstatedb.ControlRouteSession,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	routingTableRevision int64,
	entryRevision int64,
) RouteSessionLifecycle {
	result := RouteSessionLifecycle{
		RouteSessionID: session.ID, RouteID: session.RouteID, TeamID: session.TeamID,
		MembershipID: session.MembershipID.String, RouteVersion: uint64(session.RouteVersion),
		PolicyRevision: uint64(session.PolicyRevision), State: RouteSessionState(session.State), CreatedAt: session.CreatedAt.Time,
		ExpiresAt: session.PublisherExpiresAt.Time, ReadyPublisherConnectionCount: len(connections),
		Routable:             session.ReadyAt.Valid && len(connections) > 0,
		RoutingTableRevision: uint64(routingTableRevision), RouteEntryRevision: uint64(entryRevision),
	}
	if session.ReadyAt.Valid {
		value := session.ReadyAt.Time
		result.ReadyAt = &value
	}
	if session.CertificateInstalledAt.Valid {
		value := session.CertificateInstalledAt.Time
		result.CertificateAt = &value
	}
	if session.ClosedAt.Valid {
		value := session.ClosedAt.Time
		result.ClosedAt = &value
	}
	return result
}

func validateRouteSessionAuthentication(authentication RouteSessionAuthentication) error {
	if !validStateText(authentication.RouteSessionID) || !validStateText(authentication.RouteID) {
		return errors.New("controlstate: route-session authentication is invalid")
	}
	if _, ok := positiveInt64(authentication.RouteVersion); !ok {
		return errors.New("controlstate: route-session authentication has an invalid route version")
	}
	if _, _, err := credentials.ParseRouteSessionToken(authentication.RouteSessionToken); err != nil {
		return ErrRouteSessionCredential
	}
	return nil
}

func publisherConnectionClaimParams(
	request PublisherConnectionClaimRequest,
	now time.Time,
) controlstatedb.MarkPublisherConnectionReadyParams {
	return controlstatedb.MarkPublisherConnectionReadyParams{
		ReadyAt: timestamptz(now), PublisherConnectionID: request.PublisherConnectionID,
		RouteSessionID: request.RouteSessionID, RouteID: request.RouteID, RouteVersion: positive(request.RouteVersion),
		ConnectionSlot:               int16(request.ConnectionSlot),
		ConnectionAssignmentRevision: positive(request.ConnectionAssignmentRevision),
		RelayServiceID:               request.ConnectionAssignmentIdentity.RelayServiceID,
		RelayID:                      text(request.RelayID), RelayRunID: text(request.RelayRunID),
		RelayLeaseRevision: int8(request.RelayLeaseRevision), ClaimID: text(request.ClaimID),
	}
}

func disconnectPublisherConnectionParams(
	request PublisherConnectionClaimRequest,
	now time.Time,
) controlstatedb.DisconnectPublisherConnectionParams {
	return controlstatedb.DisconnectPublisherConnectionParams{
		DisconnectedAt: timestamptz(now), PublisherConnectionID: request.PublisherConnectionID,
		RouteSessionID: request.RouteSessionID, RouteID: request.RouteID, RouteVersion: positive(request.RouteVersion),
		ConnectionSlot:               int16(request.ConnectionSlot),
		ConnectionAssignmentRevision: positive(request.ConnectionAssignmentRevision),
		RelayServiceID:               request.ConnectionAssignmentIdentity.RelayServiceID,
		RelayID:                      text(request.RelayID), RelayRunID: text(request.RelayRunID),
		RelayLeaseRevision: int8(request.RelayLeaseRevision), ClaimID: text(request.ClaimID),
	}
}

func rollback(ctx context.Context, tx pgx.Tx, operation string, retErr *error) func() {
	return func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			*retErr = errors.Join(*retErr, fmt.Errorf("controlstate: %s: rollback: %w", operation, err))
		}
	}
}
