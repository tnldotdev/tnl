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
	ErrPublishRunCredential = errors.New("controlstate: publish-run credential is invalid")
	ErrPublishRunStale      = errors.New("controlstate: publish run identity or version is stale")
	ErrPublishRunNotReady   = errors.New("controlstate: publish run is not ready")
	ErrPublicURLCertificate = errors.New("controlstate: public URL certificate acknowledgement is invalid")
)

const transactionRollbackTimeout = 5 * time.Second

// PublishRunNotReadyError reports the prerequisites checked under the public URL
// and publish run locks. it does not contain credentials or certificate material.
type PublishRunNotReadyError struct {
	CertificateInstalled          bool
	ReadyPublisherConnectionCount int
	CreatedAt                     time.Time
}

func (e *PublishRunNotReadyError) Error() string { return ErrPublishRunNotReady.Error() }
func (e *PublishRunNotReadyError) Unwrap() error { return ErrPublishRunNotReady }

func (e *PublishRunNotReadyError) Reason() string {
	switch {
	case !e.CertificateInstalled && e.ReadyPublisherConnectionCount != publishRunConnectionCount:
		return "certificate_and_connections_missing"
	case !e.CertificateInstalled:
		return "certificate_missing"
	default:
		return "connections_missing"
	}
}

// PublishRunAuthentication binds a publish run credential to one exact publish run number.
type PublishRunAuthentication struct {
	PublishRunID     string
	PublicURLID      string
	PublishRunNumber uint64
	PublishRunToken  credentials.PublishRunToken
}

// PublishRunLifecycle reports saved readiness and current publisher connection availability.
type PublishRunLifecycle struct {
	PublishRunID                  string
	PublicURLID                   string
	TeamID                        string
	MembershipID                  string
	PublishRunNumber              uint64
	PolicyRevision                uint64
	State                         PublishRunState
	CreatedAt                     time.Time
	ExpiresAt                     time.Time
	ReadyAt                       *time.Time
	CertificateAt                 *time.Time
	ClosedAt                      *time.Time
	ReadyPublisherConnectionCount int
	Routable                      bool
	RoutingTableRevision          uint64
	PublicURLEntryRevision        uint64
}

func (d *Database) PublishRunAuthentication(
	ctx context.Context,
	publishRunID string,
	publishRunNumber uint64,
	token credentials.PublishRunToken,
) (PublishRunAuthentication, error) {
	if err := d.requireOpen(); err != nil {
		return PublishRunAuthentication{}, err
	}
	if !validStateText(publishRunID) {
		return PublishRunAuthentication{}, ErrPublishRunCredential
	}
	if _, ok := positiveInt64(publishRunNumber); !ok {
		return PublishRunAuthentication{}, ErrPublishRunCredential
	}
	tokenID, tokenHash, err := credentials.ParsePublishRunToken(token)
	if err != nil {
		return PublishRunAuthentication{}, ErrPublishRunCredential
	}
	session, err := controlstatedb.New(d.pool).GetPublishRun(ctx, publishRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return PublishRunAuthentication{}, ErrPublishRunCredential
	}
	if err != nil {
		return PublishRunAuthentication{}, fmt.Errorf("controlstate: read publish run authentication: %w", err)
	}
	if !matchesPositiveInt64(session.PublishRunNumber, publishRunNumber) || tokenID.String() != session.PublishRunTokenID ||
		!credentials.SecretHashMatches(session.PublishRunTokenDigest, tokenHash) {
		return PublishRunAuthentication{}, ErrPublishRunCredential
	}
	return PublishRunAuthentication{
		PublishRunID: publishRunID, PublicURLID: session.PublicURLID, PublishRunNumber: publishRunNumber, PublishRunToken: token,
	}, nil
}

func (d *Database) MarkPublishRunReady(
	ctx context.Context,
	authentication PublishRunAuthentication,
	now time.Time,
) (result PublishRunLifecycle, retErr error) {
	if err := validatePublishRunAuthentication(authentication); err != nil {
		return PublishRunLifecycle{}, err
	}
	if err := d.requireOpen(); err != nil {
		return PublishRunLifecycle{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: mark publish run ready: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "mark publish run ready", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	route, session, err := lockAuthenticatedPublishRun(ctx, queries, authentication, now)
	if err != nil {
		return PublishRunLifecycle{}, err
	}
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return PublishRunLifecycle{}, err
	}
	var publishedEvent *publishedIngressRoutingTableEvent
	if !session.ReadyAt.Valid {
		if !session.CertificateInstalledAt.Valid || len(connections) != publishRunConnectionCount {
			return PublishRunLifecycle{}, &PublishRunNotReadyError{
				CertificateInstalled:          session.CertificateInstalledAt.Valid,
				ReadyPublisherConnectionCount: len(connections), CreatedAt: session.CreatedAt.Time,
			}
		}
		session, err = queries.MarkPublishRunReady(ctx, controlstatedb.MarkPublishRunReadyParams{
			ReadyAt: timestamptz(now), PublishRunID: session.ID,
			PublicURLID: route.ID, PublishRunNumber: session.PublishRunNumber,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return PublishRunLifecycle{}, ErrPublishRunStale
		}
		if err != nil {
			return PublishRunLifecycle{}, fmt.Errorf("controlstate: mark publish run ready: update session: %w", err)
		}
		publishedEvent, err = pendingEvents.addRouteEvent(
			ctx, queries, route, session, connections, "public_url_upsert", now,
		)
		if err != nil {
			return PublishRunLifecycle{}, err
		}
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return PublishRunLifecycle{}, err
	}
	var routingTableRevision, publicURLEntryRevision int64
	if publishedEvent != nil {
		routingTableRevision = publishedEvent.routingTableRevision
		publicURLEntryRevision = publishedEvent.entryRevision
	}
	if err := tx.Commit(ctx); err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: mark publish run ready: commit: %w", err)
	}
	return publishRunLifecycle(session, connections, routingTableRevision, publicURLEntryRevision), nil
}

// IngressRoutingTableProjection is the stored public URL view used by ingress.
type IngressRoutingTableProjection struct {
	PublishRunID         string                                   `json:"publish_run_id"`
	PublicURLID          string                                   `json:"public_url_id"`
	PublishRunNumber     uint64                                   `json:"publish_run_number"`
	CanonicalHostname    string                                   `json:"canonical_hostname"`
	PolicyRevision       uint64                                   `json:"policy_revision"`
	IPPolicy             IPPolicy                                 `json:"ip_policy"`
	AllowedIPPrefixes    []netip.Prefix                           `json:"allowed_ip_prefixes"`
	PublicUrlExpiresAt   time.Time                                `json:"public_url_expires_at"`
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

// MarkPublicURLCertificateInstalled records publisher acknowledgement of the
// installed public URL certificate. first routability still requires both connections.
func (d *Database) MarkPublicURLCertificateInstalled(
	ctx context.Context,
	authentication PublishRunAuthentication,
	issuanceID string,
	notAfter time.Time,
	now time.Time,
) (result PublishRunLifecycle, retErr error) {
	if err := validatePublishRunAuthentication(authentication); err != nil {
		return PublishRunLifecycle{}, err
	}
	if !validStateText(issuanceID) || !notAfter.After(now) {
		return PublishRunLifecycle{}, ErrPublicURLCertificate
	}
	if err := d.requireOpen(); err != nil {
		return PublishRunLifecycle{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: install public URL certificate: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "install public URL certificate", &retErr)()
	queries := controlstatedb.New(tx)
	route, session, err := lockAuthenticatedPublishRun(ctx, queries, authentication, now)
	if err != nil {
		return PublishRunLifecycle{}, err
	}
	alreadyInstalled := session.CertificateInstalledAt.Valid
	order, err := queries.LockACMEOrderForInstall(ctx, controlstatedb.LockACMEOrderForInstallParams{
		IssuanceID: issuanceID, TeamID: session.TeamID, CertificateCacheKey: session.CertificateCacheKey,
		CertificateScope: session.CertificateScope, CertificateIdentifiers: session.CertificateIdentifiers,
		ChallengeMethod: session.CertificateChallenge,
		NotAfter:        timestamptz(notAfter), InstalledAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublishRunLifecycle{}, ErrPublicURLCertificate
	} else if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: install public URL certificate: lock issuance: %w", err)
	}
	if !validInstalledCertificate(order, route.CanonicalHostname, now) {
		return PublishRunLifecycle{}, ErrPublicURLCertificate
	}
	if _, err := queries.MarkACMEOrderInstalled(ctx, controlstatedb.MarkACMEOrderInstalledParams{
		InstalledAt: timestamptz(now), IssuanceID: issuanceID,
	}); errors.Is(err, pgx.ErrNoRows) {
		return PublishRunLifecycle{}, ErrPublicURLCertificate
	} else if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: install public URL certificate: update issuance: %w", err)
	}
	session, err = queries.MarkPublishRunCertificateInstalled(ctx, controlstatedb.MarkPublishRunCertificateInstalledParams{
		InstalledAt: timestamptz(now), IssuanceID: text(issuanceID), NotAfter: timestamptz(notAfter),
		PublishRunID: session.ID, PublicURLID: session.PublicURLID, PublishRunNumber: session.PublishRunNumber,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublishRunLifecycle{}, ErrPublicURLCertificate
	}
	if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: install public URL certificate: update session: %w", err)
	}
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return PublishRunLifecycle{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: install public URL certificate: commit: %w", err)
	}
	if !alreadyInstalled {
		d.activity.metrics.Load().ObserveCertificateTransition("public_url", "installed")
	}
	return publishRunLifecycle(session, connections, 0, 0), nil
}

// HeartbeatPublishRun extends one publish run and returns current or
// replacement publisher connection assignments.
func (d *Database) HeartbeatPublishRun(
	ctx context.Context,
	authentication PublishRunAuthentication,
	now time.Time,
	leaseDuration time.Duration,
	connectionCredentialDuration time.Duration,
) (result PublishRunSetup, retErr error) {
	defer d.observeOperation("HeartbeatPublishRun", &retErr)()
	if err := validatePublishRunAuthentication(authentication); err != nil {
		return PublishRunSetup{}, err
	}
	if leaseDuration <= 0 || connectionCredentialDuration <= 0 {
		return PublishRunSetup{}, errors.New("controlstate: publish-run heartbeat durations must be positive")
	}
	if err := d.requireOpen(); err != nil {
		return PublishRunSetup{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: heartbeat publish run: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "heartbeat publish run", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	route, session, err := lockAuthenticatedPublishRun(ctx, queries, authentication, now)
	if err != nil {
		return PublishRunSetup{}, err
	}
	if route.Ephemeral {
		if _, err := queries.RenewEphemeralPublicURLExpiry(ctx, controlstatedb.RenewEphemeralPublicURLExpiryParams{
			ExpiresAt: timestamptz(now.Add(ephemeralPublicURLGracePeriod)), PublicURLID: route.ID,
		}); err != nil {
			return PublishRunSetup{}, fmt.Errorf("controlstate: heartbeat publish run: renew ephemeral public_url: %w", err)
		}
	}
	previousExpiresAt := session.PublisherExpiresAt.Time
	session, err = queries.HeartbeatPublishRun(ctx, controlstatedb.HeartbeatPublishRunParams{
		HeartbeatAt: timestamptz(now), ExpiresAt: timestamptz(now.Add(leaseDuration)),
		PublishRunID: session.ID, PublicURLID: route.ID, PublishRunNumber: session.PublishRunNumber,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublishRunSetup{}, ErrPublishRunStale
	}
	if err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: heartbeat publish run: update lease: %w", err)
	}
	leaseExtended := session.PublisherExpiresAt.Time.After(previousExpiresAt)
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return PublishRunSetup{}, err
	}
	removedReadyConnection := false
	var replenishment replenishmentResult
	if len(connections) != publishRunConnectionCount {
		replenishment, err = replenishPublishRunConnections(
			ctx, queries, session, authentication.PublishRunToken, connections, now, connectionCredentialDuration,
		)
		if err != nil {
			return PublishRunSetup{}, err
		}
		removedReadyConnection = replenishment.removedReady
		connections, err = validReadyPublisherConnections(ctx, queries, session.ID, now)
		if err != nil {
			return PublishRunSetup{}, err
		}
	}
	if session.PolicyDenials < 0 {
		return PublishRunSetup{}, errors.New("controlstate: heartbeat publish run: invalid policy denial count")
	}
	if session.ReadyAt.Valid && removedReadyConnection {
		if err := openPublicURLRecoveryEpisode(ctx, queries, route.ID, session.PublishRunNumber, now); err != nil {
			return PublishRunSetup{}, err
		}
	}
	if session.ReadyAt.Valid && (leaseExtended && len(connections) > 0 || removedReadyConnection) {
		eventKind := publicURLRoutingTableEventKind(len(connections) > 0)
		if _, err := pendingEvents.addRouteEvent(ctx, queries, route, session, connections, eventKind, now); err != nil {
			return PublishRunSetup{}, err
		}
	}
	if leaseExtended && len(connections) > 0 || removedReadyConnection {
		if err := pendingEvents.addCurrentChallengeEvent(ctx, queries, route, session, connections, now); err != nil {
			return PublishRunSetup{}, err
		}
	}
	setup, err := loadPublishRunSetupWithToken(ctx, queries, authentication.PublishRunToken, session)
	if err != nil {
		return PublishRunSetup{}, err
	}
	setup.PolicyDenials = uint64(session.PolicyDenials)
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return PublishRunSetup{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublishRunSetup{}, fmt.Errorf("controlstate: heartbeat publish run: commit: %w", err)
	}
	metrics := d.activity.metrics.Load()
	for reason, count := range replenishment.replacements {
		metrics.AddAssignmentReplacements(reason, count)
	}
	if replenishment.attempted {
		outcome := "placed"
		if replenishment.unavailable {
			outcome = "unavailable"
		}
		metrics.ObservePlacement("replenish", outcome)
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
	route, session, err := lockPublishRunForPublisherConnection(ctx, queries, request, now)
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
	lease, err := queries.GetRelayLeaseForReady(ctx, request.RelayID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrRelayLeaseStale
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: mark publisher connection ready: lock relay lease: %w", err)
	}
	if err := validateClaimRelayLease(controlstatedb.GetRelayLeaseForClaimRow(lease), request.RelayLeaseIdentity, before.RelayServiceID, now); err != nil {
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
	route, session, err := lockPublishRunForPublisherConnection(ctx, queries, request, now)
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
		if err := openPublicURLRecoveryEpisode(ctx, queries, route.ID, session.PublishRunNumber, now); err != nil {
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

func lockPublishRunForPublisherConnection(
	ctx context.Context,
	queries *controlstatedb.Queries,
	request PublisherConnectionClaimRequest,
	now time.Time,
) (controlstatedb.ControlPublicUrl, controlstatedb.ControlPublishRun, error) {
	route, err := queries.LockPublicURLForRun(ctx, request.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrConnectionAssignmentStale
	}
	if err != nil {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, fmt.Errorf("controlstate: lock publisher connection public_url: %w", err)
	}
	session, err := queries.LockPublishRun(ctx, request.PublishRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrConnectionAssignmentStale
	}
	if err != nil {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, fmt.Errorf("controlstate: lock publisher connection publish run: %w", err)
	}
	if PublicURLLifecycleState(route.LifecycleState) != PublicURLLifecycleEnabled || session.PublicURLID != request.PublicURLID ||
		!matchesPositiveInt64(session.PublishRunNumber, request.PublishRunNumber) || session.ClosedAt.Valid ||
		!session.PublisherExpiresAt.Valid || !session.PublisherExpiresAt.Time.After(now) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrConnectionAssignmentStale
	}
	return route, session, nil
}

func lockAuthenticatedPublishRun(
	ctx context.Context,
	queries *controlstatedb.Queries,
	authentication PublishRunAuthentication,
	now time.Time,
) (controlstatedb.ControlPublicUrl, controlstatedb.ControlPublishRun, error) {
	route, err := queries.LockPublicURLForRun(ctx, authentication.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrPublishRunStale
	}
	if err != nil {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, fmt.Errorf("controlstate: lock authenticated public_url: %w", err)
	}
	session, err := queries.LockPublishRun(ctx, authentication.PublishRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrPublishRunStale
	}
	if err != nil {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, fmt.Errorf("controlstate: lock authenticated publish run: %w", err)
	}
	if PublicURLLifecycleState(route.LifecycleState) != PublicURLLifecycleEnabled || session.PublicURLID != authentication.PublicURLID ||
		!matchesPositiveInt64(session.PublishRunNumber, authentication.PublishRunNumber) || session.ClosedAt.Valid ||
		!session.PublisherExpiresAt.Valid || !session.PublisherExpiresAt.Time.After(now) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrPublishRunStale
	}
	tokenID, tokenHash, err := credentials.ParsePublishRunToken(authentication.PublishRunToken)
	if err != nil || tokenID.String() != session.PublishRunTokenID ||
		!credentials.SecretHashMatches(session.PublishRunTokenDigest, tokenHash) {
		return controlstatedb.ControlPublicUrl{}, controlstatedb.ControlPublishRun{}, ErrPublishRunCredential
	}
	return route, session, nil
}

func validReadyPublisherConnections(
	ctx context.Context,
	queries *controlstatedb.Queries,
	publishRunID string,
	now time.Time,
) ([]controlstatedb.ListValidReadyPublisherConnectionsRow, error) {
	connections, err := queries.ListValidReadyPublisherConnections(
		ctx, controlstatedb.ListValidReadyPublisherConnectionsParams{
			PublishRunID: publishRunID, Now: timestamptz(now),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("controlstate: list ready publisher connections: %w", err)
	}
	return connections, nil
}

func activePublishRunChallengeExpiry(
	ctx context.Context,
	queries *controlstatedb.Queries,
	publishRunID string,
	now time.Time,
) (time.Time, bool, error) {
	expiresAt, err := queries.GetActivePublishRunChallengeExpiry(ctx, controlstatedb.GetActivePublishRunChallengeExpiryParams{
		PublishRunID: publishRunID, Now: timestamptz(now),
	})
	if err != nil {
		return time.Time{}, false, fmt.Errorf("controlstate: read active publish-run challenge: %w", err)
	}
	if !expiresAt.Valid {
		return time.Time{}, false, nil
	}
	return expiresAt.Time, true, nil
}

func (pending *pendingIngressRoutingTableEvents) addPublisherConnectionChanges(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlPublicUrl,
	session controlstatedb.ControlPublishRun,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	now time.Time,
) error {
	if session.ReadyAt.Valid {
		if _, err := pending.addRouteEvent(
			ctx, queries, route, session, connections,
			publicURLRoutingTableEventKind(len(connections) > 0), now,
		); err != nil {
			return err
		}
	}
	return pending.addCurrentChallengeEvent(ctx, queries, route, session, connections, now)
}

func (pending *pendingIngressRoutingTableEvents) addCurrentChallengeEvent(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlPublicUrl,
	session controlstatedb.ControlPublishRun,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	now time.Time,
) error {
	challengeExpiresAt, challengeActive, err := activePublishRunChallengeExpiry(ctx, queries, session.ID, now)
	if err != nil || !challengeActive {
		return err
	}
	_, err = pending.addChallengeEvent(
		ctx, queries, route, session, connections,
		challengeRoutingTableEventKind(len(connections) > 0), challengeExpiresAt, now,
	)
	return err
}

func publicURLRoutingTableEventKind(available bool) IngressRoutingTableEventKind {
	if available {
		return IngressPublicURLUpsert
	}
	return IngressPublicURLTombstone
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
	route controlstatedb.ControlPublicUrl,
	session controlstatedb.ControlPublishRun,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	eventKind IngressRoutingTableEventKind,
	now time.Time,
) (*publishedIngressRoutingTableEvent, error) {
	return pending.addEvent(ctx, queries, route, session, connections, eventKind, session.PublisherExpiresAt.Time, now)
}

func (pending *pendingIngressRoutingTableEvents) addChallengeEvent(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlPublicUrl,
	session controlstatedb.ControlPublishRun,
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
	publicURLID         string
	publishRunNumber    int64
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
	route controlstatedb.ControlPublicUrl,
	session controlstatedb.ControlPublishRun,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	eventKind IngressRoutingTableEventKind,
	projectionExpiresAt time.Time,
	now time.Time,
) (*publishedIngressRoutingTableEvent, error) {
	policy := IPPolicy(route.IpPolicy)
	projection := IngressRoutingTableProjection{
		PublishRunID: session.ID, PublicURLID: route.ID, PublishRunNumber: uint64(session.PublishRunNumber),
		CanonicalHostname: route.CanonicalHostname, PolicyRevision: uint64(route.PolicyRevision),
		IPPolicy: policy, AllowedIPPrefixes: append([]netip.Prefix(nil), route.AllowedIpPrefixes...),
		PublicUrlExpiresAt:   projectionExpiresAt,
		PublisherConnections: make([]IngressRoutingTablePublisherConnection, 0, len(connections)),
	}
	if projection.AllowedIPPrefixes == nil {
		projection.AllowedIPPrefixes = []netip.Prefix{}
	}
	if eventKind == "public_url_upsert" {
		episode, err := queries.GetOpenPublicURLRecoveryEpisode(ctx, controlstatedb.GetOpenPublicURLRecoveryEpisodeParams{
			PublicURLID: route.ID, PublishRunNumber: session.PublishRunNumber,
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
		eventKind: eventKind, publicURLID: route.ID, publishRunNumber: session.PublishRunNumber,
		canonicalHostname: route.CanonicalHostname, projection: payload,
		projectionExpiresAt: projectionExpiresAt, createdAt: now, published: published,
	})
	return published, nil
}

func (pending *pendingIngressRoutingTableEvents) publish(ctx context.Context, queries *controlstatedb.Queries) error {
	if len(pending.events) == 0 {
		return nil
	}
	// callers hold each public URL row through commit, so another transaction
	// cannot allocate an entry revision for that public URL concurrently.
	type publishRunNumber struct {
		publicURLID      string
		publishRunNumber int64
	}
	entryRevisionsByPublicURL := make(map[publishRunNumber]int64)
	entryRevisions := make([]int64, len(pending.events))
	for index := range pending.events {
		event := &pending.events[index]
		key := publishRunNumber{publicURLID: event.publicURLID, publishRunNumber: event.publishRunNumber}
		entryRevision, found := entryRevisionsByPublicURL[key]
		if !found {
			var err error
			entryRevision, err = queries.LatestIngressRoutingEntryRevision(ctx, controlstatedb.LatestIngressRoutingEntryRevisionParams{
				PublicURLID: event.publicURLID, PublishRunNumber: event.publishRunNumber,
			})
			if err != nil {
				return fmt.Errorf("controlstate: read ingress routing-table entry revision: %w", err)
			}
		}
		if entryRevision == math.MaxInt64 {
			return errors.New("controlstate: ingress routing-table entry revision is exhausted")
		}
		entryRevision++
		entryRevisionsByPublicURL[key] = entryRevision
		entryRevisions[index] = entryRevision
	}
	// publish only after connection and challenge projections are complete.
	// hold the routing clock through commit so revision order matches commit order;
	// callers must not perform further database work. the final insert acquires
	// the clock itself when there is only one event.
	if len(pending.events) > 1 {
		if _, err := queries.LockIngressRoutingTableClock(ctx); err != nil {
			return fmt.Errorf("controlstate: lock ingress routing-table clock: %w", err)
		}
	}
	for index := range pending.events {
		event := &pending.events[index]
		publicURLExpiresAt := pgtype.Timestamptz{}
		if event.eventKind == IngressPublicURLUpsert || event.eventKind == IngressChallengeUpsert {
			publicURLExpiresAt = timestamptz(event.projectionExpiresAt)
		}
		var routingTableRevision int64
		var err error
		if index == len(pending.events)-1 {
			routingTableRevision, err = queries.InsertFinalIngressRoutingTableEvent(ctx, controlstatedb.InsertFinalIngressRoutingTableEventParams{
				EventKind: string(event.eventKind), PublicURLID: event.publicURLID, PublishRunNumber: event.publishRunNumber,
				CanonicalHostname: event.canonicalHostname, EntryRevision: entryRevisions[index],
				Projection: event.projection, PublicUrlExpiresAt: publicURLExpiresAt, CreatedAt: timestamptz(event.createdAt),
				UpdatedAt: timestamptz(event.createdAt),
			})
		} else {
			routingTableRevision, err = queries.InsertIngressRoutingTableEvent(ctx, controlstatedb.InsertIngressRoutingTableEventParams{
				EventKind: string(event.eventKind), PublicURLID: event.publicURLID, PublishRunNumber: event.publishRunNumber,
				CanonicalHostname: event.canonicalHostname, EntryRevision: entryRevisions[index],
				Projection: event.projection, PublicUrlExpiresAt: publicURLExpiresAt, CreatedAt: timestamptz(event.createdAt),
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

func openPublicURLRecoveryEpisode(
	ctx context.Context,
	queries *controlstatedb.Queries,
	publicURLID string,
	publishRunNumber int64,
	now time.Time,
) error {
	if err := queries.OpenPublicURLRecoveryEpisode(ctx, controlstatedb.OpenPublicURLRecoveryEpisodeParams{
		PublicURLID: publicURLID, PublishRunNumber: publishRunNumber, OpenedAt: timestamptz(now),
	}); err != nil {
		return fmt.Errorf("controlstate: open route recovery episode: %w", err)
	}
	return nil
}

func publishRunLifecycle(
	session controlstatedb.ControlPublishRun,
	connections []controlstatedb.ListValidReadyPublisherConnectionsRow,
	routingTableRevision int64,
	entryRevision int64,
) PublishRunLifecycle {
	result := PublishRunLifecycle{
		PublishRunID: session.ID, PublicURLID: session.PublicURLID, TeamID: session.TeamID,
		MembershipID: session.MembershipID.String, PublishRunNumber: uint64(session.PublishRunNumber),
		PolicyRevision: uint64(session.PolicyRevision), State: PublishRunState(session.State), CreatedAt: session.CreatedAt.Time,
		ExpiresAt: session.PublisherExpiresAt.Time, ReadyPublisherConnectionCount: len(connections),
		Routable:             session.ReadyAt.Valid && len(connections) > 0,
		RoutingTableRevision: uint64(routingTableRevision), PublicURLEntryRevision: uint64(entryRevision),
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

func validatePublishRunAuthentication(authentication PublishRunAuthentication) error {
	if !validStateText(authentication.PublishRunID) || !validStateText(authentication.PublicURLID) {
		return errors.New("controlstate: publish-run authentication is invalid")
	}
	if _, ok := positiveInt64(authentication.PublishRunNumber); !ok {
		return errors.New("controlstate: publish-run authentication has an invalid publish run number")
	}
	if _, _, err := credentials.ParsePublishRunToken(authentication.PublishRunToken); err != nil {
		return ErrPublishRunCredential
	}
	return nil
}

func publisherConnectionClaimParams(
	request PublisherConnectionClaimRequest,
	now time.Time,
) controlstatedb.MarkPublisherConnectionReadyParams {
	return controlstatedb.MarkPublisherConnectionReadyParams{
		ReadyAt: timestamptz(now), PublisherConnectionID: request.PublisherConnectionID,
		PublishRunID: request.PublishRunID, PublicURLID: request.PublicURLID, PublishRunNumber: positive(request.PublishRunNumber),
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
		PublishRunID: request.PublishRunID, PublicURLID: request.PublicURLID, PublishRunNumber: positive(request.PublishRunNumber),
		ConnectionSlot:               int16(request.ConnectionSlot),
		ConnectionAssignmentRevision: positive(request.ConnectionAssignmentRevision),
		RelayServiceID:               request.ConnectionAssignmentIdentity.RelayServiceID,
		RelayID:                      text(request.RelayID), RelayRunID: text(request.RelayRunID),
		RelayLeaseRevision: int8(request.RelayLeaseRevision), ClaimID: text(request.ClaimID),
	}
}

func rollback(ctx context.Context, tx pgx.Tx, operation string, retErr *error) func() {
	return func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), transactionRollbackTimeout)
		defer cancel()
		if err := tx.Rollback(rollbackCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			*retErr = errors.Join(*retErr, fmt.Errorf("controlstate: %s: rollback: %w", operation, err))
		}
	}
}
