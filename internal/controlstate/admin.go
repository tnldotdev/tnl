package controlstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

const adminRelayPageSize = 100

type MaintenanceControlName string

const (
	MaintenanceControlRouteCreation        MaintenanceControlName = "route_creation"
	MaintenanceControlRouteSessionCreation MaintenanceControlName = "route_session_creation"
	MaintenanceControlCertificateIssuance  MaintenanceControlName = "certificate_issuance"
)

var (
	ErrAdminInvalid               = errors.New("controlstate: invalid administration request")
	ErrMaintenanceControlNotFound = errors.New("controlstate: maintenance control not found")
)

// AdminRuntimeCounts contains current stored state counts for server status.
type AdminRuntimeCounts struct {
	EnabledRoutes         int64
	SuspendedRoutes       int64
	StartingRouteSessions int64
	ReadyRouteSessions    int64
	IngressLeases         int64
	RelayLeases           int64
}

// AdminRelayPage is one stable relay-ID-ordered page of unexpired leases.
type AdminRelayPage struct {
	Relays     []RelayLease
	NextCursor string
}

// MaintenanceControl is one stored gate for starting new work.
type MaintenanceControl struct {
	Name      MaintenanceControlName
	Allowed   bool
	Revision  uint64
	UpdatedAt time.Time
	UpdatedBy string
}

// AdminRuntimeCounts returns counts evaluated against one captured timestamp.
func (d *Database) AdminRuntimeCounts(ctx context.Context, now time.Time) (AdminRuntimeCounts, error) {
	if err := d.requireOpen(); err != nil {
		return AdminRuntimeCounts{}, err
	}
	row, err := controlstatedb.New(d.pool).GetAdminRuntimeCounts(ctx, timestamptz(now))
	if err != nil {
		return AdminRuntimeCounts{}, fmt.Errorf("controlstate: read admin server status: %w", err)
	}
	values := []int64{
		row.EnabledRoutes, row.SuspendedRoutes, row.StartingRouteSessions,
		row.ReadyRouteSessions, row.IngressLeases, row.RelayLeases,
	}
	for _, value := range values {
		if value < 0 {
			return AdminRuntimeCounts{}, errors.New("controlstate: invalid admin server status count")
		}
	}
	return AdminRuntimeCounts{
		EnabledRoutes: row.EnabledRoutes, SuspendedRoutes: row.SuspendedRoutes,
		StartingRouteSessions: row.StartingRouteSessions, ReadyRouteSessions: row.ReadyRouteSessions,
		IngressLeases: row.IngressLeases, RelayLeases: row.RelayLeases,
	}, nil
}

// ListAdminRelayLeases returns one page of current relay process leases.
func (d *Database) ListAdminRelayLeases(ctx context.Context, cursor string, now time.Time) (AdminRelayPage, error) {
	if cursor != "" && !validStateText(cursor) {
		return AdminRelayPage{}, ErrAdminInvalid
	}
	if err := d.requireOpen(); err != nil {
		return AdminRelayPage{}, err
	}
	rows, err := controlstatedb.New(d.pool).ListAdminRelayLeases(ctx, controlstatedb.ListAdminRelayLeasesParams{
		Now: timestamptz(now), Cursor: nullableText(cursor), PageLimit: adminRelayPageSize + 1,
	})
	if err != nil {
		return AdminRelayPage{}, fmt.Errorf("controlstate: list admin relay leases: %w", err)
	}
	page := AdminRelayPage{Relays: make([]RelayLease, min(len(rows), adminRelayPageSize))}
	for index, row := range rows[:len(page.Relays)] {
		page.Relays[index], err = relayLease(relayLeaseValues{
			relayID: row.RelayID, relayServiceID: row.RelayServiceID, relayRunID: row.RelayRunID,
			relayLeaseRevision: row.RelayLeaseRevision, protocolVersion: row.ProtocolVersion,
			internalRelayAddress: row.InternalRelayAddress, observedAddress: row.ObservedAddress,
			internalNetworks: row.InternalNetworks, connectionCapacity: row.ConnectionCapacity,
			streamCapacity: row.StreamCapacity, reportedConnections: row.ReportedConnections,
			reportedStreams: row.ReportedStreams, draining: row.Draining, drainDeadline: row.DrainDeadline,
			registeredAt: row.RegisteredAt, renewedAt: row.RenewedAt, leaseExpiresAt: row.LeaseExpiresAt,
			relayAddress: row.RelayAddress, tlsServerName: row.TlsServerName,
		})
		if err != nil {
			return AdminRelayPage{}, err
		}
	}
	if len(rows) > adminRelayPageSize {
		page.NextCursor = rows[adminRelayPageSize-1].RelayID
	}
	return page, nil
}

// BeginAdminRelayDrain drains one matching lease and records the administrator
// action in the same transaction.
func (d *Database) BeginAdminRelayDrain(
	ctx context.Context,
	identity RelayLeaseIdentity,
	actorIdentityID, requestID string,
	now, deadline time.Time,
) (result RelayLease, retErr error) {
	if !validStateText(identity.RelayID) || !validStateText(identity.RelayRunID) ||
		identity.RelayLeaseRevision == 0 || identity.RelayLeaseRevision > math.MaxInt64 ||
		!validStateText(actorIdentityID) || !validStateText(requestID) || !deadline.After(now) {
		return RelayLease{}, ErrAdminInvalid
	}
	if err := d.requireOpen(); err != nil {
		return RelayLease{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return RelayLease{}, fmt.Errorf("controlstate: begin admin relay drain: %w", err)
	}
	defer rollback(ctx, tx, "admin relay drain", &retErr)()
	queries := controlstatedb.New(tx)
	revision, _ := positiveInt64(identity.RelayLeaseRevision)
	row, err := queries.BeginAdminRelayDrain(ctx, controlstatedb.BeginAdminRelayDrainParams{
		DrainDeadline: timestamptz(deadline), DrainedAt: timestamptz(now), RelayID: identity.RelayID,
		RelayRunID: identity.RelayRunID, RelayLeaseRevision: revision,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayLease{}, ErrRelayLeaseStale
	}
	if err != nil {
		return RelayLease{}, fmt.Errorf("controlstate: drain admin relay: %w", err)
	}
	details, err := json.Marshal(map[string]any{
		"deadline": deadline.UTC(), "relay_run_id": identity.RelayRunID,
		"relay_lease_revision": identity.RelayLeaseRevision,
	})
	if err != nil {
		return RelayLease{}, fmt.Errorf("controlstate: encode relay drain audit details: %w", err)
	}
	if err := insertAdminAuditEvent(ctx, queries, actorIdentityID, requestID, "relay.drain", "relay", identity.RelayID, details, now); err != nil {
		return RelayLease{}, err
	}
	result, err = relayLease(relayLeaseValues{
		relayID: row.RelayID, relayServiceID: row.RelayServiceID, relayRunID: row.RelayRunID,
		relayLeaseRevision: row.RelayLeaseRevision, protocolVersion: row.ProtocolVersion,
		internalRelayAddress: row.InternalRelayAddress, observedAddress: row.ObservedAddress,
		internalNetworks: row.InternalNetworks, connectionCapacity: row.ConnectionCapacity,
		streamCapacity: row.StreamCapacity, reportedConnections: row.ReportedConnections,
		reportedStreams: row.ReportedStreams, draining: row.Draining, drainDeadline: row.DrainDeadline,
		registeredAt: row.RegisteredAt, renewedAt: row.RenewedAt, leaseExpiresAt: row.LeaseExpiresAt,
		relayAddress: row.RelayAddress, tlsServerName: row.TlsServerName,
	})
	if err != nil {
		return RelayLease{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RelayLease{}, fmt.Errorf("controlstate: commit admin relay drain: %w", err)
	}
	return result, nil
}

// ListMaintenanceControls returns all maintenance controls in name order.
func (d *Database) ListMaintenanceControls(ctx context.Context) ([]MaintenanceControl, error) {
	if err := d.requireOpen(); err != nil {
		return nil, err
	}
	rows, err := controlstatedb.New(d.pool).ListMaintenanceControls(ctx)
	if err != nil {
		return nil, fmt.Errorf("controlstate: list maintenance controls: %w", err)
	}
	result := make([]MaintenanceControl, len(rows))
	for index, row := range rows {
		result[index], err = maintenanceControl(row)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// SetMaintenanceControl updates one gate and records the administrator action
// in the same transaction.
func (d *Database) SetMaintenanceControl(
	ctx context.Context,
	name MaintenanceControlName,
	allowed bool,
	actorIdentityID, requestID string,
	now time.Time,
) (result MaintenanceControl, retErr error) {
	if !validMaintenanceControlName(name) || !validStateText(actorIdentityID) || !validStateText(requestID) {
		return MaintenanceControl{}, ErrAdminInvalid
	}
	if err := d.requireOpen(); err != nil {
		return MaintenanceControl{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return MaintenanceControl{}, fmt.Errorf("controlstate: begin maintenance control update: %w", err)
	}
	defer rollback(ctx, tx, "maintenance control update", &retErr)()
	queries := controlstatedb.New(tx)
	row, err := queries.SetMaintenanceControl(ctx, controlstatedb.SetMaintenanceControlParams{
		Allowed: allowed, UpdatedAt: timestamptz(now), UpdatedBy: actorIdentityID, ControlName: string(name),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return MaintenanceControl{}, ErrMaintenanceControlNotFound
	}
	if err != nil {
		return MaintenanceControl{}, fmt.Errorf("controlstate: set maintenance control: %w", err)
	}
	details, err := json.Marshal(map[string]any{"allowed": allowed, "revision": row.Revision})
	if err != nil {
		return MaintenanceControl{}, fmt.Errorf("controlstate: encode maintenance audit details: %w", err)
	}
	if err := insertAdminAuditEvent(ctx, queries, actorIdentityID, requestID, "maintenance_control.set", "maintenance_control", string(name), details, now); err != nil {
		return MaintenanceControl{}, err
	}
	result, err = maintenanceControl(row)
	if err != nil {
		return MaintenanceControl{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return MaintenanceControl{}, fmt.Errorf("controlstate: commit maintenance control update: %w", err)
	}
	return result, nil
}

func insertAdminAuditEvent(
	ctx context.Context,
	queries *controlstatedb.Queries,
	actorIdentityID, requestID, operation, targetKind, targetID string,
	details []byte,
	now time.Time,
) error {
	if err := queries.InsertAdminAuditEvent(ctx, controlstatedb.InsertAdminAuditEventParams{
		ActorIdentityID: nullableText(actorIdentityID), Actor: actorIdentityID, RequestID: requestID,
		Operation: operation, TargetKind: targetKind, TargetID: targetID, Details: details,
		OccurredAt: timestamptz(now),
	}); err != nil {
		return fmt.Errorf("controlstate: record admin audit event: %w", err)
	}
	return nil
}

func maintenanceControl(row controlstatedb.ControlMaintenanceControl) (MaintenanceControl, error) {
	name := MaintenanceControlName(row.ControlName)
	if !validMaintenanceControlName(name) || row.Revision <= 0 || !row.UpdatedAt.Valid || !validStateText(row.UpdatedBy) {
		return MaintenanceControl{}, errors.New("controlstate: invalid maintenance control row")
	}
	return MaintenanceControl{
		Name: name, Allowed: row.Allowed, Revision: uint64(row.Revision),
		UpdatedAt: row.UpdatedAt.Time, UpdatedBy: row.UpdatedBy,
	}, nil
}

func validMaintenanceControlName(name MaintenanceControlName) bool {
	return name == MaintenanceControlRouteCreation || name == MaintenanceControlRouteSessionCreation ||
		name == MaintenanceControlCertificateIssuance
}
