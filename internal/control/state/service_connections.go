package state

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type ServicePublisherConnection struct {
	ServiceID, RunID, ConnectionID, RelayServiceID string
	RunNumber, Revision                            int64
}

func servicePublisherConnection(row controlstatedb.ControlServiceConnectionSlot) ServicePublisherConnection {
	return ServicePublisherConnection{ServiceID: row.ServiceID, RunID: row.ServiceRunID,
		ConnectionID: row.PublisherConnectionID, RelayServiceID: row.RelayServiceID,
		RunNumber: row.RunNumber, Revision: row.ConnectionAssignmentRevision}
}

// countReadyServiceConnections uses the caller's transaction so uncommitted slot
// transitions and the readiness decision share one state boundary.
func countReadyServiceConnections(ctx context.Context, tx pgx.Tx, runID string, now time.Time) (int, error) {
	var count int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM control.service_connection_slots slot
		JOIN control.relay_leases lease ON lease.relay_id=slot.relay_id AND lease.relay_run_id=slot.relay_run_id
			AND lease.relay_lease_revision=slot.relay_lease_revision AND lease.relay_service_id=slot.relay_service_id
		WHERE slot.service_run_id=$1 AND slot.state='ready' AND slot.session_open
			AND lease.lease_expires_at > $2 AND NOT lease.draining`, runID, now).Scan(&count)
	return count, err
}

func lockServiceConnectionRun(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries,
	connectionID, serviceID, runID string, runNumber, revision int64, now time.Time) (controlstatedb.ControlServiceRun, error) {
	binding, err := checkedPrivateAssignmentBinding(serviceID, runID, connectionID, runNumber, revision)
	if err != nil {
		return controlstatedb.ControlServiceRun{}, ErrServiceAccess
	}
	if err := lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return controlstatedb.ControlServiceRun{}, err
	}
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: runID, ServiceID: serviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return run, ErrServiceAccess
	}
	if err != nil {
		return run, err
	}
	if !binding.serviceRunBinding.matches(run) || !activeServiceRun(run, now) {
		return run, ErrServiceAccess
	}
	_, err = q.GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{
		ID: runID, ServiceID: serviceID, RunNumber: runNumber,
		PublisherIdentityID: run.PublisherIdentityID, PublisherGrantID: run.PublisherGrantID,
		PublisherKeyID: run.PublisherKeyID, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return run, ErrServiceAccess
	}
	return run, err
}

func serviceConnectionScope(ctx context.Context, tx pgx.Tx, connectionID string) (serviceID, runID string, err error) {
	err = tx.QueryRow(ctx, `SELECT service_id, service_run_id FROM control.service_connection_slots WHERE publisher_connection_id=$1`, connectionID).Scan(&serviceID, &runID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrServiceAccess
	}
	return
}

func resolvePrivateRelay(ctx context.Context, tx pgx.Tx, lease RelayLeaseIdentity) (RelayLeaseIdentity, error) {
	if !validStateText(lease.RelayID) || !validStateText(lease.RelayRunID) || lease.RelayLeaseRevision == 0 || lease.RelayLeaseRevision > uint64(^uint64(0)>>1) {
		return lease, ErrServiceAccess
	}
	err := tx.QueryRow(ctx, `SELECT relay_service_id FROM control.relay_leases WHERE relay_id=$1 AND relay_run_id=$2 AND relay_lease_revision=$3`,
		lease.RelayID, lease.RelayRunID, int64(lease.RelayLeaseRevision)).Scan(&lease.RelayServiceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return lease, ErrServiceAccess
	}
	return lease, err
}

func (d *Database) ClaimServicePublisherConnection(ctx context.Context, connectionID, serviceID, runID string, runNumber, revision int64, credential string, lease RelayLeaseIdentity, now time.Time) (result ServicePublisherConnection, retErr error) {
	digest, err := credentials.ParsePublisherConnectionCredential(credentials.PublisherConnectionCredential(credential))
	if err != nil {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "claim private publisher connection", &retErr)()
	lease, err = resolvePrivateRelay(ctx, tx, lease)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	if _, err = lockServiceConnectionRun(ctx, tx, q, connectionID, serviceID, runID, runNumber, revision, now); err != nil {
		return result, err
	}
	slots, err := q.ListServiceConnectionSlots(ctx, runID)
	if err != nil {
		return result, err
	}
	var connection controlstatedb.ControlServiceConnectionSlot
	for _, slot := range slots {
		if slot.PublisherConnectionID == connectionID {
			connection = slot
			break
		}
	}
	binding, err := checkedPrivateAssignmentBinding(serviceID, runID, connectionID, runNumber, revision)
	if err != nil || !binding.matches(connection) ||
		!connection.CredentialExpiresAt.Time.After(now) || subtle.ConstantTimeCompare(connection.CredentialDigest, digest[:]) != 1 {
		return result, ErrServiceAccess
	}
	current, err := q.GetRelayLeaseForClaim(ctx, lease.RelayID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if err = validateClaimRelayLease(current, lease, connection.RelayServiceID, now); err != nil {
		return result, ErrServiceAccess
	}
	// only the exact connected claim can recover a lost response. ready slots
	// remain owned by their existing tunnel; local admission fences duplicates
	// before control so a losing handshake cannot disconnect the winner.
	state, err := privateAssignmentState(connection.State)
	if err != nil {
		return result, err
	}
	sameClaim := state == PublisherConnectionConnected && connection.RelayID.String == lease.RelayID &&
		connection.RelayRunID.String == lease.RelayRunID && connection.RelayLeaseRevision.Valid &&
		connection.RelayLeaseRevision.Int64 == int64(lease.RelayLeaseRevision)
	if state != PublisherConnectionAssigned && !sameClaim {
		return result, ErrServiceAccess
	}
	if !sameClaim {
		// the selected process lease serializes both public and private claims.
		active, err := q.CountRelayActiveConnections(ctx, controlstatedb.CountRelayActiveConnectionsParams{
			RelayID: text(lease.RelayID), RelayRunID: text(lease.RelayRunID),
			RelayLeaseRevision: pgtype.Int8{Int64: int64(lease.RelayLeaseRevision), Valid: true},
		})
		if err != nil {
			return result, err
		}
		if active >= current.ConnectionCapacity {
			return result, ErrRelayConnectionCapacity
		}
	}
	row, err := q.ClaimServiceConnectionSlot(ctx, controlstatedb.ClaimServiceConnectionSlotParams{
		PublisherConnectionID: connectionID, CredentialDigest: digest[:], ConnectionAssignmentRevision: revision,
		RelayID: text(lease.RelayID), RelayRunID: text(lease.RelayRunID),
		RelayLeaseRevision: pgtype.Int8{Int64: int64(lease.RelayLeaseRevision), Valid: true}, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if row.ServiceID != serviceID || row.ServiceRunID != runID || row.RunNumber != runNumber || row.RelayServiceID != lease.RelayServiceID {
		return result, ErrServiceAccess
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return servicePublisherConnection(row), nil
}

func (d *Database) ReadyServicePublisherConnection(ctx context.Context, connectionID, runID string, runNumber, revision int64, lease RelayLeaseIdentity, now time.Time) (result ServicePublisherConnection, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "ready private publisher connection", &retErr)()
	lease, err = resolvePrivateRelay(ctx, tx, lease)
	if err != nil {
		return result, err
	}
	serviceID, storedRunID, err := serviceConnectionScope(ctx, tx, connectionID)
	if err != nil {
		return result, err
	}
	if storedRunID != runID {
		return result, ErrServiceAccess
	}
	q := controlstatedb.New(tx)
	run, err := lockServiceConnectionRun(ctx, tx, q, connectionID, serviceID, runID, runNumber, revision, now)
	if err != nil {
		return result, err
	}
	if _, err = q.GetRelayLeaseForReady(ctx, lease.RelayID); err != nil {
		return result, err
	}
	row, err := q.ReadyServiceConnectionSlot(ctx, controlstatedb.ReadyServiceConnectionSlotParams{
		PublisherConnectionID: connectionID, ConnectionAssignmentRevision: revision, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if row.RelayServiceID != lease.RelayServiceID || row.RelayID.String != lease.RelayID || row.RelayRunID.String != lease.RelayRunID || row.RelayLeaseRevision.Int64 != int64(lease.RelayLeaseRevision) || row.ServiceRunID != runID || row.RunNumber != runNumber {
		return result, ErrServiceAccess
	}
	count, err := countReadyServiceConnections(ctx, tx, runID, now)
	if err != nil {
		return result, err
	}
	certificateReady := run.CertificateExpiresAt.Valid && run.CertificateExpiresAt.Time.After(now)
	if run.Healthy && certificateReady && (count == 2 || run.ReadyAt.Valid && count >= 1) {
		if serviceRunLifecycleState(run.State) == serviceRunStarting {
			run, err = q.ReadyServiceRun(ctx, controlstatedb.ReadyServiceRunParams{ID: runID, ServiceID: serviceID, RunNumber: runNumber, Now: timestamptz(now)})
			if err != nil {
				return result, err
			}
		}
		if err = serviceRoutingUpsert(ctx, tx, q, run, now); err != nil {
			return result, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return servicePublisherConnection(row), nil
}

func (d *Database) DisconnectServicePublisherConnection(ctx context.Context, connectionID, runID string, runNumber, revision int64, lease RelayLeaseIdentity, now time.Time) (result ServicePublisherConnection, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "disconnect private publisher connection", &retErr)()
	serviceID, storedRunID, err := serviceConnectionScope(ctx, tx, connectionID)
	if err != nil {
		return result, err
	}
	if storedRunID != runID {
		return result, ErrServiceAccess
	}
	if _, err = checkedPrivateAssignmentBinding(serviceID, runID, connectionID, runNumber, revision); err != nil {
		return result, err
	}
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: runID, ServiceID: serviceID})
	if err != nil {
		return result, err
	}
	if !validStateText(lease.RelayID) || !validStateText(lease.RelayRunID) || lease.RelayLeaseRevision == 0 || lease.RelayLeaseRevision > uint64(^uint64(0)>>1) {
		return result, ErrServiceAccess
	}
	if err = tx.QueryRow(ctx, `SELECT relay_service_id FROM control.service_connection_slots WHERE publisher_connection_id=$1 AND relay_id=$2 AND relay_run_id=$3 AND relay_lease_revision=$4`,
		connectionID, lease.RelayID, lease.RelayRunID, int64(lease.RelayLeaseRevision)).Scan(&lease.RelayServiceID); errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	} else if err != nil {
		return result, err
	}
	row, err := q.DisconnectServiceConnectionSlot(ctx, controlstatedb.DisconnectServiceConnectionSlotParams{
		PublisherConnectionID: connectionID, ServiceRunID: runID, RunNumber: runNumber,
		ConnectionAssignmentRevision: revision, RelayID: text(lease.RelayID), RelayRunID: text(lease.RelayRunID),
		RelayLeaseRevision: pgtype.Int8{Int64: int64(lease.RelayLeaseRevision), Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if row.RelayServiceID != lease.RelayServiceID || row.ServiceID != serviceID {
		return result, ErrServiceAccess
	}
	if serviceRunLifecycleState(run.State) == serviceRunReady && !run.ClosedAt.Valid {
		ready, err := countReadyServiceConnections(ctx, tx, runID, now)
		if err != nil {
			return result, err
		}
		if ready > 0 {
			if err = serviceRoutingUpsert(ctx, tx, q, run, now); err != nil {
				return result, err
			}
		} else {
			if _, err = q.DemoteServiceRun(ctx, controlstatedb.DemoteServiceRunParams{ID: runID, ServiceID: serviceID, RunNumber: runNumber}); err != nil {
				return result, err
			}
			if err = serviceRunRoutingTombstone(ctx, q, serviceID, run.ID, run.RunNumber, now); err != nil {
				return result, err
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return servicePublisherConnection(row), nil
}
