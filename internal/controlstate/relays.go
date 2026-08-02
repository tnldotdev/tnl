package controlstate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

var (
	ErrRelayRegistrationConflict         = errors.New("controlstate: relay identity or service configuration conflicts with live state")
	ErrRelayLeaseStale                   = errors.New("controlstate: relay lease identity or revision is stale")
	ErrRelayDraining                     = errors.New("controlstate: relay is draining")
	ErrRelayConnectionCapacity           = errors.New("controlstate: relay connection capacity is exhausted")
	ErrPublisherConnectionUnavailable    = errors.New("controlstate: publisher connection is unavailable")
	ErrPublisherConnectionCredential     = errors.New("controlstate: publisher connection credential is invalid")
	ErrConnectionAssignmentStale         = errors.New("controlstate: connection assignment identity or revision is stale")
	ErrPublisherConnectionAlreadyClaimed = errors.New("controlstate: publisher connection is already claimed")
	ErrPublisherConnectionRelayService   = errors.New("controlstate: publisher connection is assigned to another relay service")
)

// RelayRegistration describes one relay process and its relay service.
type RelayRegistration struct {
	RelayServiceID       string
	RelayID              string
	RelayRunID           string
	ProtocolVersion      uint64
	RelayAddress         string
	TLSServerName        string
	InternalRelayAddress string
	InternalNetworks     []netip.Prefix
	ConnectionCapacity   uint64
	StreamCapacity       uint64
}

// RelayLeaseIdentity identifies one exact relay process lease.
type RelayLeaseIdentity struct {
	RelayServiceID     string
	RelayID            string
	RelayRunID         string
	RelayLeaseRevision uint64
}

// RelayRenewal reports the relay process's current load.
type RelayRenewal struct {
	RelayLeaseIdentity
	ReportedConnections uint64
	ReportedStreams     uint64
}

// RelayLease is the control-issued lease for one relay process.
type RelayLease struct {
	RelayLeaseIdentity
	ProtocolVersion      uint64
	RelayAddress         string
	TLSServerName        string
	InternalRelayAddress string
	ObservedAddress      *netip.Addr
	InternalNetworks     []netip.Prefix
	ConnectionCapacity   uint64
	StreamCapacity       uint64
	ReportedConnections  uint64
	ReportedStreams      uint64
	Draining             bool
	DrainDeadline        *time.Time
	RegisteredAt         time.Time
	RenewedAt            time.Time
	LeaseExpiresAt       time.Time
}

// ConnectionAssignmentIdentity identifies one exact publisher connection assignment.
type ConnectionAssignmentIdentity struct {
	RouteSessionID               string
	RouteID                      string
	RouteVersion                 uint64
	ConnectionSlot               int
	PublisherConnectionID        string
	ConnectionAssignmentRevision uint64
	RelayServiceID               string
}

// PublisherConnectionClaimRequest contains the assignment, relay lease, and
// credential hash needed to claim one publisher connection in a transaction.
type PublisherConnectionClaimRequest struct {
	ConnectionAssignmentIdentity
	RelayLeaseIdentity
	ClaimID          string
	CredentialDigest [32]byte
}

// ClaimedPublisherConnection is the stored state of one claimed assignment.
type ClaimedPublisherConnection struct {
	ConnectionAssignmentIdentity
	RelayLeaseIdentity
	ClaimID                                string
	RelayAddress                           string
	TLSServerName                          string
	State                                  PublisherConnectionState
	PublisherConnectionCredentialExpiresAt time.Time
	ConnectedAt                            time.Time
	ReadyAt                                *time.Time
}

// RegisterRelay creates or renews one relay process lease. A different process
// run cannot replace an unexpired lease for the same relay identity.
func (d *Database) RegisterRelay(
	ctx context.Context,
	registration RelayRegistration,
	now time.Time,
	leaseDuration time.Duration,
) (RelayLease, error) {
	if err := validateRelayRegistration(registration, leaseDuration); err != nil {
		return RelayLease{}, err
	}
	if err := d.requireOpen(); err != nil {
		return RelayLease{}, err
	}
	protocolVersion, _ := positiveInt64(registration.ProtocolVersion)
	connectionCapacity, _ := positiveInt64(registration.ConnectionCapacity)
	streamCapacity, _ := positiveInt64(registration.StreamCapacity)
	internalNetworks := registration.InternalNetworks
	if internalNetworks == nil {
		internalNetworks = []netip.Prefix{}
	}
	row, err := controlstatedb.New(d.pool).RegisterRelay(ctx, controlstatedb.RegisterRelayParams{
		RelayID: registration.RelayID, RelayRunID: registration.RelayRunID,
		ProtocolVersion: protocolVersion, InternalRelayAddress: registration.InternalRelayAddress,
		InternalNetworks: internalNetworks, ConnectionCapacity: connectionCapacity,
		StreamCapacity: streamCapacity, RegisteredAt: timestamptz(now), RenewedAt: timestamptz(now),
		LeaseExpiresAt: timestamptz(now.Add(leaseDuration)), RelayServiceID: registration.RelayServiceID,
		RelayAddress: registration.RelayAddress, TlsServerName: registration.TLSServerName,
	})
	if errors.Is(err, pgx.ErrNoRows) || isUniqueViolation(err) {
		return RelayLease{}, ErrRelayRegistrationConflict
	}
	if err != nil {
		return RelayLease{}, fmt.Errorf("controlstate: register relay: %w", err)
	}
	return relayLeaseFromRegister(row)
}

// RenewRelay extends one exact, unexpired relay lease.
func (d *Database) RenewRelay(
	ctx context.Context,
	renewal RelayRenewal,
	now time.Time,
	leaseDuration time.Duration,
) (RelayLease, error) {
	if err := validateRelayLeaseIdentity(renewal.RelayLeaseIdentity); err != nil {
		return RelayLease{}, err
	}
	if leaseDuration <= 0 {
		return RelayLease{}, errors.New("controlstate: relay lease duration must be positive")
	}
	if err := d.requireOpen(); err != nil {
		return RelayLease{}, err
	}
	reportedConnections, ok := nonnegativeInt64(renewal.ReportedConnections)
	if !ok {
		return RelayLease{}, errors.New("controlstate: reported connection count is too large")
	}
	reportedStreams, ok := nonnegativeInt64(renewal.ReportedStreams)
	if !ok {
		return RelayLease{}, errors.New("controlstate: reported stream count is too large")
	}
	revision, _ := positiveInt64(renewal.RelayLeaseRevision)
	row, err := controlstatedb.New(d.pool).RenewRelay(ctx, controlstatedb.RenewRelayParams{
		ReportedConnections: reportedConnections, ReportedStreams: reportedStreams,
		RenewedAt: timestamptz(now), LeaseExpiresAt: timestamptz(now.Add(leaseDuration)),
		RelayServiceID: renewal.RelayServiceID, RelayID: renewal.RelayID,
		RelayRunID: renewal.RelayRunID, RelayLeaseRevision: revision,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayLease{}, ErrRelayLeaseStale
	}
	if err != nil {
		return RelayLease{}, fmt.Errorf("controlstate: renew relay: %w", err)
	}
	return relayLeaseFromRenewal(row)
}

// BeginRelayDrain removes one exact relay process from placement and keeps its
// lease current through the deadline while established streams drain.
func (d *Database) BeginRelayDrain(
	ctx context.Context,
	identity RelayLeaseIdentity,
	now time.Time,
	deadline time.Time,
) (RelayLease, error) {
	if err := validateRelayLeaseIdentity(identity); err != nil {
		return RelayLease{}, err
	}
	if !deadline.After(now) {
		return RelayLease{}, errors.New("controlstate: relay drain deadline must be in the future")
	}
	if err := d.requireOpen(); err != nil {
		return RelayLease{}, err
	}
	revision, _ := positiveInt64(identity.RelayLeaseRevision)
	row, err := controlstatedb.New(d.pool).BeginRelayDrain(ctx, controlstatedb.BeginRelayDrainParams{
		DrainDeadline: timestamptz(deadline), RenewedAt: timestamptz(now),
		RelayServiceID: identity.RelayServiceID, RelayID: identity.RelayID,
		RelayRunID: identity.RelayRunID, RelayLeaseRevision: revision,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayLease{}, ErrRelayLeaseStale
	}
	if err != nil {
		return RelayLease{}, fmt.Errorf("controlstate: begin relay drain: %w", err)
	}
	return relayLeaseFromDrain(row)
}

// ClaimPublisherConnection authenticates and claims one assignment in a
// transaction. The winning relay can repeat its claim; all other relays are
// rejected.
func (d *Database) ClaimPublisherConnection(
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
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: claim publisher connection: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "claim publisher connection", &retErr)()
	queries := controlstatedb.New(tx)
	if _, _, err := lockRouteSessionForPublisherConnection(ctx, queries, request, now); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	connection, err := queries.GetPublisherConnectionForClaim(ctx, request.PublisherConnectionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrPublisherConnectionUnavailable
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: claim publisher connection: read assignment: %w", err)
	}
	if !storedConnectionAssignmentMatches(connection, request.ConnectionAssignmentIdentity) {
		return ClaimedPublisherConnection{}, ErrConnectionAssignmentStale
	}
	if !connection.PublisherConnectionCredentialExpiresAt.Valid ||
		!connection.PublisherConnectionCredentialExpiresAt.Time.After(now) ||
		len(connection.PublisherConnectionCredentialDigest) != len(request.CredentialDigest) ||
		subtle.ConstantTimeCompare(connection.PublisherConnectionCredentialDigest, request.CredentialDigest[:]) != 1 {
		return ClaimedPublisherConnection{}, ErrPublisherConnectionCredential
	}
	lease, err := queries.GetRelayLeaseForClaim(ctx, request.RelayID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrRelayLeaseStale
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: claim publisher connection: read relay lease: %w", err)
	}
	if err := validateClaimRelayLease(lease, request.RelayLeaseIdentity, connection.RelayServiceID, now); err != nil {
		return ClaimedPublisherConnection{}, err
	}
	sameClaim := publisherConnectionClaimMatches(connection, request)
	state := PublisherConnectionState(connection.State)
	if state != PublisherConnectionAssigned && !sameClaim {
		if state == PublisherConnectionConnected || state == PublisherConnectionReady || state == PublisherConnectionDraining {
			return ClaimedPublisherConnection{}, ErrPublisherConnectionAlreadyClaimed
		}
		return ClaimedPublisherConnection{}, ErrPublisherConnectionUnavailable
	}
	if !sameClaim {
		revision, _ := positiveInt64(request.RelayLeaseRevision)
		activeConnections, err := queries.CountRelayActiveConnections(ctx, controlstatedb.CountRelayActiveConnectionsParams{
			RelayID: text(request.RelayID), RelayRunID: text(request.RelayRunID),
			RelayLeaseRevision: pgtype.Int8{Int64: revision, Valid: true},
		})
		if err != nil {
			return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: claim publisher connection: check capacity: %w", err)
		}
		if activeConnections >= lease.ConnectionCapacity {
			return ClaimedPublisherConnection{}, ErrRelayConnectionCapacity
		}
	}
	relayRevision, _ := positiveInt64(request.RelayLeaseRevision)
	assignmentRevision, _ := positiveInt64(request.ConnectionAssignmentRevision)
	claimed, err := queries.ClaimPublisherConnection(ctx, controlstatedb.ClaimPublisherConnectionParams{
		RelayID: text(request.RelayID), RelayRunID: text(request.RelayRunID),
		RelayLeaseRevision: pgtype.Int8{Int64: relayRevision, Valid: true}, ClaimID: text(request.ClaimID),
		ConnectedAt: timestamptz(now), PublisherConnectionID: request.PublisherConnectionID,
		RouteSessionID: request.RouteSessionID, RouteID: request.RouteID, RouteVersion: positive(request.RouteVersion),
		ConnectionSlot: int16(request.ConnectionSlot), ConnectionAssignmentRevision: assignmentRevision,
		RelayServiceID: request.ConnectionAssignmentIdentity.RelayServiceID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimedPublisherConnection{}, ErrConnectionAssignmentStale
	}
	if err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: claim publisher connection: update assignment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ClaimedPublisherConnection{}, fmt.Errorf("controlstate: claim publisher connection: commit: %w", err)
	}
	return claimedPublisherConnection(claimed)
}

// MarkPublisherConnectionReady records that a claimed publisher connection can
// carry visitor streams.
func (d *Database) MarkPublisherConnectionReady(
	ctx context.Context,
	request PublisherConnectionClaimRequest,
	now time.Time,
) (ClaimedPublisherConnection, error) {
	return d.markPublisherConnectionReady(ctx, request, now)
}

// DisconnectPublisherConnection closes only the exact claimed connection.
func (d *Database) DisconnectPublisherConnection(
	ctx context.Context,
	request PublisherConnectionClaimRequest,
	now time.Time,
	unexpected bool,
) (ClaimedPublisherConnection, error) {
	return d.disconnectPublisherConnection(ctx, request, now, unexpected)
}

func validateRelayRegistration(registration RelayRegistration, leaseDuration time.Duration) error {
	for field, value := range map[string]string{
		"relay service ID": registration.RelayServiceID, "relay ID": registration.RelayID,
		"relay process run ID": registration.RelayRunID, "relay address": registration.RelayAddress,
		"TLS server name": registration.TLSServerName, "internal relay address": registration.InternalRelayAddress,
	} {
		if !validStateText(value) {
			return fmt.Errorf("controlstate: %s is invalid", field)
		}
	}
	if _, ok := positiveInt64(registration.ProtocolVersion); !ok {
		return errors.New("controlstate: relay protocol version must be positive")
	}
	if _, ok := positiveInt64(registration.ConnectionCapacity); !ok {
		return errors.New("controlstate: relay connection capacity must be positive")
	}
	if _, ok := positiveInt64(registration.StreamCapacity); !ok {
		return errors.New("controlstate: relay stream capacity must be positive")
	}
	if leaseDuration <= 0 {
		return errors.New("controlstate: relay lease duration must be positive")
	}
	for _, prefix := range registration.InternalNetworks {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return errors.New("controlstate: relay internal network is invalid")
		}
	}
	return nil
}

func validateRelayLeaseIdentity(identity RelayLeaseIdentity) error {
	for _, value := range []string{identity.RelayServiceID, identity.RelayID, identity.RelayRunID} {
		if !validStateText(value) {
			return errors.New("controlstate: relay lease identity is invalid")
		}
	}
	if _, ok := positiveInt64(identity.RelayLeaseRevision); !ok {
		return errors.New("controlstate: relay lease revision must be positive")
	}
	return nil
}

func validatePublisherConnectionClaim(request PublisherConnectionClaimRequest) error {
	if err := validateRelayLeaseIdentity(request.RelayLeaseIdentity); err != nil {
		return err
	}
	for _, value := range []string{
		request.RouteSessionID, request.RouteID, request.PublisherConnectionID,
		request.ConnectionAssignmentIdentity.RelayServiceID, request.ClaimID,
	} {
		if !validStateText(value) {
			return errors.New("controlstate: publisher connection claim is invalid")
		}
	}
	if request.ConnectionAssignmentIdentity.RelayServiceID != request.RelayLeaseIdentity.RelayServiceID {
		return ErrPublisherConnectionRelayService
	}
	if request.ConnectionSlot < 0 || request.ConnectionSlot >= routeSessionConnectionCount {
		return errors.New("controlstate: connection slot is invalid")
	}
	if _, ok := positiveInt64(request.RouteVersion); !ok {
		return errors.New("controlstate: route version must be positive")
	}
	if _, ok := positiveInt64(request.ConnectionAssignmentRevision); !ok {
		return errors.New("controlstate: connection assignment revision must be positive")
	}
	return nil
}

func claimedPublisherConnection(row controlstatedb.ControlRouteSessionConnection) (ClaimedPublisherConnection, error) {
	if row.RouteVersion <= 0 || row.ConnectionAssignmentRevision <= 0 || row.ConnectionSlot < 0 ||
		row.ConnectionSlot >= routeSessionConnectionCount || !row.ConnectedRelayID.Valid ||
		!row.ConnectedRelayRunID.Valid || !row.ConnectedRelayLeaseRevision.Valid ||
		row.ConnectedRelayLeaseRevision.Int64 <= 0 || !row.ClaimID.Valid ||
		!row.PublisherConnectionCredentialExpiresAt.Valid || !row.ConnectedAt.Valid {
		return ClaimedPublisherConnection{}, errors.New("controlstate: invalid claimed publisher connection row")
	}
	var readyAt *time.Time
	if row.ReadyAt.Valid {
		value := row.ReadyAt.Time
		readyAt = &value
	}
	return ClaimedPublisherConnection{
		ConnectionAssignmentIdentity: ConnectionAssignmentIdentity{
			RouteSessionID: row.RouteSessionID, RouteID: row.RouteID, RouteVersion: uint64(row.RouteVersion),
			ConnectionSlot: int(row.ConnectionSlot), PublisherConnectionID: row.PublisherConnectionID,
			ConnectionAssignmentRevision: uint64(row.ConnectionAssignmentRevision), RelayServiceID: row.RelayServiceID,
		},
		RelayLeaseIdentity: RelayLeaseIdentity{
			RelayServiceID: row.RelayServiceID, RelayID: row.ConnectedRelayID.String,
			RelayRunID: row.ConnectedRelayRunID.String, RelayLeaseRevision: uint64(row.ConnectedRelayLeaseRevision.Int64),
		},
		ClaimID: row.ClaimID.String, RelayAddress: row.RelayAddress, TLSServerName: row.TlsServerName,
		State: PublisherConnectionState(row.State), PublisherConnectionCredentialExpiresAt: row.PublisherConnectionCredentialExpiresAt.Time,
		ConnectedAt: row.ConnectedAt.Time, ReadyAt: readyAt,
	}, nil
}

func publisherConnectionClaimMatches(
	connection controlstatedb.ControlRouteSessionConnection,
	request PublisherConnectionClaimRequest,
) bool {
	return connection.ConnectedRelayID.Valid && connection.ConnectedRelayID.String == request.RelayID &&
		connection.ConnectedRelayRunID.Valid && connection.ConnectedRelayRunID.String == request.RelayRunID &&
		connection.ConnectedRelayLeaseRevision.Valid &&
		matchesPositiveInt64(connection.ConnectedRelayLeaseRevision.Int64, request.RelayLeaseRevision) &&
		connection.ClaimID.Valid && connection.ClaimID.String == request.ClaimID
}

func storedConnectionAssignmentMatches(
	connection controlstatedb.ControlRouteSessionConnection,
	identity ConnectionAssignmentIdentity,
) bool {
	return connection.RouteSessionID == identity.RouteSessionID && connection.RouteID == identity.RouteID &&
		matchesPositiveInt64(connection.RouteVersion, identity.RouteVersion) &&
		int(connection.ConnectionSlot) == identity.ConnectionSlot &&
		connection.PublisherConnectionID == identity.PublisherConnectionID &&
		matchesPositiveInt64(connection.ConnectionAssignmentRevision, identity.ConnectionAssignmentRevision) &&
		connection.RelayServiceID == identity.RelayServiceID
}

func validateClaimRelayLease(
	lease controlstatedb.GetRelayLeaseForClaimRow,
	identity RelayLeaseIdentity,
	assignedRelayServiceID string,
	now time.Time,
) error {
	if lease.RelayServiceID != identity.RelayServiceID || lease.RelayID != identity.RelayID ||
		lease.RelayRunID != identity.RelayRunID ||
		!matchesPositiveInt64(lease.RelayLeaseRevision, identity.RelayLeaseRevision) ||
		!lease.LeaseExpiresAt.Valid || !lease.LeaseExpiresAt.Time.After(now) {
		return ErrRelayLeaseStale
	}
	if lease.RelayServiceID != assignedRelayServiceID {
		return ErrPublisherConnectionRelayService
	}
	if lease.Draining {
		return ErrRelayDraining
	}
	return nil
}

func relayLeaseFromRegister(row controlstatedb.RegisterRelayRow) (RelayLease, error) {
	return relayLease(relayLeaseValues{
		relayID: row.RelayID, relayServiceID: row.RelayServiceID, relayRunID: row.RelayRunID,
		relayLeaseRevision: row.RelayLeaseRevision, protocolVersion: row.ProtocolVersion,
		internalRelayAddress: row.InternalRelayAddress, observedAddress: row.ObservedAddress,
		internalNetworks: row.InternalNetworks, connectionCapacity: row.ConnectionCapacity,
		streamCapacity: row.StreamCapacity, reportedConnections: row.ReportedConnections,
		reportedStreams: row.ReportedStreams, draining: row.Draining, drainDeadline: row.DrainDeadline,
		registeredAt: row.RegisteredAt, renewedAt: row.RenewedAt, leaseExpiresAt: row.LeaseExpiresAt,
		relayAddress: row.RelayAddress, tlsServerName: row.TlsServerName,
	})
}

func relayLeaseFromRenewal(row controlstatedb.RenewRelayRow) (RelayLease, error) {
	return relayLease(relayLeaseValues{
		relayID: row.RelayID, relayServiceID: row.RelayServiceID, relayRunID: row.RelayRunID,
		relayLeaseRevision: row.RelayLeaseRevision, protocolVersion: row.ProtocolVersion,
		internalRelayAddress: row.InternalRelayAddress, observedAddress: row.ObservedAddress,
		internalNetworks: row.InternalNetworks, connectionCapacity: row.ConnectionCapacity,
		streamCapacity: row.StreamCapacity, reportedConnections: row.ReportedConnections,
		reportedStreams: row.ReportedStreams, draining: row.Draining, drainDeadline: row.DrainDeadline,
		registeredAt: row.RegisteredAt, renewedAt: row.RenewedAt, leaseExpiresAt: row.LeaseExpiresAt,
		relayAddress: row.RelayAddress, tlsServerName: row.TlsServerName,
	})
}

func relayLeaseFromDrain(row controlstatedb.BeginRelayDrainRow) (RelayLease, error) {
	return relayLease(relayLeaseValues{
		relayID: row.RelayID, relayServiceID: row.RelayServiceID, relayRunID: row.RelayRunID,
		relayLeaseRevision: row.RelayLeaseRevision, protocolVersion: row.ProtocolVersion,
		internalRelayAddress: row.InternalRelayAddress, observedAddress: row.ObservedAddress,
		internalNetworks: row.InternalNetworks, connectionCapacity: row.ConnectionCapacity,
		streamCapacity: row.StreamCapacity, reportedConnections: row.ReportedConnections,
		reportedStreams: row.ReportedStreams, draining: row.Draining, drainDeadline: row.DrainDeadline,
		registeredAt: row.RegisteredAt, renewedAt: row.RenewedAt, leaseExpiresAt: row.LeaseExpiresAt,
		relayAddress: row.RelayAddress, tlsServerName: row.TlsServerName,
	})
}

type relayLeaseValues struct {
	relayID, relayServiceID, relayRunID, internalRelayAddress, relayAddress, tlsServerName string
	relayLeaseRevision, protocolVersion, connectionCapacity, streamCapacity                int64
	reportedConnections, reportedStreams                                                   int64
	observedAddress                                                                        *netip.Addr
	internalNetworks                                                                       []netip.Prefix
	draining                                                                               bool
	drainDeadline, registeredAt, renewedAt, leaseExpiresAt                                 pgtype.Timestamptz
}

func relayLease(row relayLeaseValues) (RelayLease, error) {
	if row.relayLeaseRevision <= 0 || row.protocolVersion <= 0 || row.connectionCapacity < 0 ||
		row.streamCapacity < 0 || row.reportedConnections < 0 || row.reportedStreams < 0 ||
		!row.registeredAt.Valid || !row.renewedAt.Valid || !row.leaseExpiresAt.Valid {
		return RelayLease{}, errors.New("controlstate: invalid relay lease row")
	}
	var drainDeadline *time.Time
	if row.drainDeadline.Valid {
		value := row.drainDeadline.Time
		drainDeadline = &value
	}
	return RelayLease{
		RelayLeaseIdentity: RelayLeaseIdentity{
			RelayServiceID: row.relayServiceID, RelayID: row.relayID, RelayRunID: row.relayRunID,
			RelayLeaseRevision: uint64(row.relayLeaseRevision),
		},
		ProtocolVersion: uint64(row.protocolVersion), RelayAddress: row.relayAddress,
		TLSServerName: row.tlsServerName, InternalRelayAddress: row.internalRelayAddress,
		ObservedAddress: row.observedAddress, InternalNetworks: append([]netip.Prefix(nil), row.internalNetworks...),
		ConnectionCapacity: uint64(row.connectionCapacity), StreamCapacity: uint64(row.streamCapacity),
		ReportedConnections: uint64(row.reportedConnections), ReportedStreams: uint64(row.reportedStreams),
		Draining: row.draining, DrainDeadline: drainDeadline, RegisteredAt: row.registeredAt.Time,
		RenewedAt: row.renewedAt.Time, LeaseExpiresAt: row.leaseExpiresAt.Time,
	}, nil
}

func (d *Database) requireOpen() error {
	if d == nil || d.pool == nil {
		return errors.New("controlstate: database is not open")
	}
	return nil
}

func validStateText(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value
}

func positiveInt64(value uint64) (int64, bool) {
	if value == 0 || value > math.MaxInt64 {
		return 0, false
	}
	return int64(value), true
}

func nonnegativeInt64(value uint64) (int64, bool) {
	if value > math.MaxInt64 {
		return 0, false
	}
	return int64(value), true
}

func positive(value uint64) int64 {
	result, _ := positiveInt64(value)
	return result
}

func matchesPositiveInt64(stored int64, value uint64) bool {
	expected, ok := positiveInt64(value)
	return ok && stored == expected
}

func timestamptz(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: true}
}

func text(value string) pgtype.Text { return pgtype.Text{String: value, Valid: true} }

func int8(value uint64) pgtype.Int8 { return pgtype.Int8{Int64: positive(value), Valid: true} }

func isUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}
