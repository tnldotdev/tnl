package controlstate

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

type PrivatePublisherConnection struct {
	ServiceID, RunID, ConnectionID, RelayServiceID string
	RunNumber, Revision                            int64
}

func privatePublisherConnection(row controlstatedb.ControlPrivateServiceConnectionSlot) PrivatePublisherConnection {
	return PrivatePublisherConnection{ServiceID: row.PrivateServiceID, RunID: row.PrivateRunID,
		ConnectionID: row.PublisherConnectionID, RelayServiceID: row.RelayServiceID,
		RunNumber: row.RunNumber, Revision: row.ConnectionAssignmentRevision}
}

// countReadyPrivateConnections uses the caller's transaction so uncommitted slot
// transitions and the readiness decision share one state boundary.
func countReadyPrivateConnections(ctx context.Context, tx pgx.Tx, runID string, now time.Time) (int, error) {
	var count int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM control.private_service_connection_slots slot
		JOIN control.relay_leases lease ON lease.relay_id=slot.relay_id AND lease.relay_run_id=slot.relay_run_id
			AND lease.relay_lease_revision=slot.relay_lease_revision AND lease.relay_service_id=slot.relay_service_id
		WHERE slot.private_run_id=$1 AND slot.state='ready' AND slot.session_open
			AND lease.lease_expires_at > $2 AND NOT lease.draining`, runID, now).Scan(&count)
	return count, err
}

func lockPrivateConnectionRun(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries,
	connectionID, serviceID, runID string, runNumber, revision int64, now time.Time) (controlstatedb.ControlPrivateServiceRun, error) {
	binding, err := checkedPrivateAssignmentBinding(serviceID, runID, connectionID, runNumber, revision)
	if err != nil {
		return controlstatedb.ControlPrivateServiceRun{}, ErrPrivateServiceAccess
	}
	if err := lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		return controlstatedb.ControlPrivateServiceRun{}, err
	}
	run, err := q.LockPrivateServiceRun(ctx, controlstatedb.LockPrivateServiceRunParams{ID: runID, PrivateServiceID: serviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return run, ErrPrivateServiceAccess
	}
	if err != nil {
		return run, err
	}
	if !binding.privateRunBinding.matches(run) || !activePrivateRun(run, now) {
		return run, ErrPrivateServiceAccess
	}
	_, err = q.GetPrivateRunPublisherIdentity(ctx, controlstatedb.GetPrivateRunPublisherIdentityParams{
		ID: runID, PrivateServiceID: serviceID, RunNumber: runNumber,
		PublisherIdentityID: run.PublisherIdentityID, PublisherGrantID: run.PublisherGrantID,
		PublisherKeyID: run.PublisherKeyID, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return run, ErrPrivateServiceAccess
	}
	return run, err
}

func privateConnectionScope(ctx context.Context, tx pgx.Tx, connectionID string) (serviceID, runID string, err error) {
	err = tx.QueryRow(ctx, `SELECT private_service_id, private_run_id FROM control.private_service_connection_slots WHERE publisher_connection_id=$1`, connectionID).Scan(&serviceID, &runID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrPrivateServiceAccess
	}
	return
}

func resolvePrivateRelay(ctx context.Context, tx pgx.Tx, lease RelayLeaseIdentity) (RelayLeaseIdentity, error) {
	if !validStateText(lease.RelayID) || !validStateText(lease.RelayRunID) || lease.RelayLeaseRevision == 0 || lease.RelayLeaseRevision > uint64(^uint64(0)>>1) {
		return lease, ErrPrivateServiceAccess
	}
	err := tx.QueryRow(ctx, `SELECT relay_service_id FROM control.relay_leases WHERE relay_id=$1 AND relay_run_id=$2 AND relay_lease_revision=$3`,
		lease.RelayID, lease.RelayRunID, int64(lease.RelayLeaseRevision)).Scan(&lease.RelayServiceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return lease, ErrPrivateServiceAccess
	}
	return lease, err
}

func (d *Database) ClaimPrivatePublisherConnection(ctx context.Context, connectionID, serviceID, runID string, runNumber, revision int64, credential string, lease RelayLeaseIdentity, now time.Time) (result PrivatePublisherConnection, retErr error) {
	digest, err := credentials.ParsePublisherConnectionCredential(credentials.PublisherConnectionCredential(credential))
	if err != nil {
		return result, ErrPrivateServiceAccess
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
	if _, err = lockPrivateConnectionRun(ctx, tx, q, connectionID, serviceID, runID, runNumber, revision, now); err != nil {
		return result, err
	}
	slots, err := q.ListPrivateServiceConnectionSlots(ctx, runID)
	if err != nil {
		return result, err
	}
	var connection controlstatedb.ControlPrivateServiceConnectionSlot
	for _, slot := range slots {
		if slot.PublisherConnectionID == connectionID {
			connection = slot
			break
		}
	}
	binding, err := checkedPrivateAssignmentBinding(serviceID, runID, connectionID, runNumber, revision)
	if err != nil || !binding.matches(connection) ||
		!connection.CredentialExpiresAt.Time.After(now) || subtle.ConstantTimeCompare(connection.CredentialDigest, digest[:]) != 1 {
		return result, ErrPrivateServiceAccess
	}
	current, err := q.GetRelayLeaseForClaim(ctx, lease.RelayID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	if err = validateClaimRelayLease(current, lease, connection.RelayServiceID, now); err != nil {
		return result, ErrPrivateServiceAccess
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
		return result, ErrPrivateServiceAccess
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
	row, err := q.ClaimPrivateServiceConnectionSlot(ctx, controlstatedb.ClaimPrivateServiceConnectionSlotParams{
		PublisherConnectionID: connectionID, CredentialDigest: digest[:], ConnectionAssignmentRevision: revision,
		RelayID: text(lease.RelayID), RelayRunID: text(lease.RelayRunID),
		RelayLeaseRevision: pgtype.Int8{Int64: int64(lease.RelayLeaseRevision), Valid: true}, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	if row.PrivateServiceID != serviceID || row.PrivateRunID != runID || row.RunNumber != runNumber || row.RelayServiceID != lease.RelayServiceID {
		return result, ErrPrivateServiceAccess
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return privatePublisherConnection(row), nil
}

func (d *Database) ReadyPrivatePublisherConnection(ctx context.Context, connectionID, runID string, runNumber, revision int64, lease RelayLeaseIdentity, now time.Time) (result PrivatePublisherConnection, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "ready private publisher connection", &retErr)()
	lease, err = resolvePrivateRelay(ctx, tx, lease)
	if err != nil {
		return result, err
	}
	serviceID, storedRunID, err := privateConnectionScope(ctx, tx, connectionID)
	if err != nil {
		return result, err
	}
	if storedRunID != runID {
		return result, ErrPrivateServiceAccess
	}
	q := controlstatedb.New(tx)
	run, err := lockPrivateConnectionRun(ctx, tx, q, connectionID, serviceID, runID, runNumber, revision, now)
	if err != nil {
		return result, err
	}
	if _, err = q.GetRelayLeaseForReady(ctx, lease.RelayID); err != nil {
		return result, err
	}
	row, err := q.ReadyPrivateServiceConnectionSlot(ctx, controlstatedb.ReadyPrivateServiceConnectionSlotParams{
		PublisherConnectionID: connectionID, ConnectionAssignmentRevision: revision, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	if row.RelayServiceID != lease.RelayServiceID || row.RelayID.String != lease.RelayID || row.RelayRunID.String != lease.RelayRunID || row.RelayLeaseRevision.Int64 != int64(lease.RelayLeaseRevision) || row.PrivateRunID != runID || row.RunNumber != runNumber {
		return result, ErrPrivateServiceAccess
	}
	count, err := countReadyPrivateConnections(ctx, tx, runID, now)
	if err != nil {
		return result, err
	}
	certificateReady := run.CertificateExpiresAt.Valid && run.CertificateExpiresAt.Time.After(now)
	if run.Healthy && certificateReady && (count == 2 || run.ReadyAt.Valid && count >= 1) {
		if privateRunLifecycleState(run.State) == privateRunStarting {
			run, err = q.ReadyPrivateServiceRun(ctx, controlstatedb.ReadyPrivateServiceRunParams{ID: runID, PrivateServiceID: serviceID, RunNumber: runNumber, Now: timestamptz(now)})
			if err != nil {
				return result, err
			}
		}
		if err = privateRoutingUpsert(ctx, tx, q, run, now); err != nil {
			return result, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return privatePublisherConnection(row), nil
}

func (d *Database) DisconnectPrivatePublisherConnection(ctx context.Context, connectionID, runID string, runNumber, revision int64, lease RelayLeaseIdentity, now time.Time) (result PrivatePublisherConnection, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "disconnect private publisher connection", &retErr)()
	serviceID, storedRunID, err := privateConnectionScope(ctx, tx, connectionID)
	if err != nil {
		return result, err
	}
	if storedRunID != runID {
		return result, ErrPrivateServiceAccess
	}
	if _, err = checkedPrivateAssignmentBinding(serviceID, runID, connectionID, runNumber, revision); err != nil {
		return result, err
	}
	if err = lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := q.LockPrivateServiceRun(ctx, controlstatedb.LockPrivateServiceRunParams{ID: runID, PrivateServiceID: serviceID})
	if err != nil {
		return result, err
	}
	if !validStateText(lease.RelayID) || !validStateText(lease.RelayRunID) || lease.RelayLeaseRevision == 0 || lease.RelayLeaseRevision > uint64(^uint64(0)>>1) {
		return result, ErrPrivateServiceAccess
	}
	if err = tx.QueryRow(ctx, `SELECT relay_service_id FROM control.private_service_connection_slots WHERE publisher_connection_id=$1 AND relay_id=$2 AND relay_run_id=$3 AND relay_lease_revision=$4`,
		connectionID, lease.RelayID, lease.RelayRunID, int64(lease.RelayLeaseRevision)).Scan(&lease.RelayServiceID); errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	} else if err != nil {
		return result, err
	}
	row, err := q.DisconnectPrivateServiceConnectionSlot(ctx, controlstatedb.DisconnectPrivateServiceConnectionSlotParams{
		PublisherConnectionID: connectionID, PrivateRunID: runID, RunNumber: runNumber,
		ConnectionAssignmentRevision: revision, RelayID: text(lease.RelayID), RelayRunID: text(lease.RelayRunID),
		RelayLeaseRevision: pgtype.Int8{Int64: int64(lease.RelayLeaseRevision), Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	if row.RelayServiceID != lease.RelayServiceID || row.PrivateServiceID != serviceID {
		return result, ErrPrivateServiceAccess
	}
	if privateRunLifecycleState(run.State) == privateRunReady && !run.ClosedAt.Valid {
		ready, err := countReadyPrivateConnections(ctx, tx, runID, now)
		if err != nil {
			return result, err
		}
		if ready > 0 {
			if err = privateRoutingUpsert(ctx, tx, q, run, now); err != nil {
				return result, err
			}
		} else {
			if _, err = q.DemotePrivateServiceRun(ctx, controlstatedb.DemotePrivateServiceRunParams{ID: runID, PrivateServiceID: serviceID, RunNumber: runNumber}); err != nil {
				return result, err
			}
			if err = privateRunRoutingTombstone(ctx, q, serviceID, run.ID, run.RunNumber, now); err != nil {
				return result, err
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return privatePublisherConnection(row), nil
}
