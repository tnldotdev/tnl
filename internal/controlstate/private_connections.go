package controlstate

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
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

func lockPrivateConnectionRun(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries,
	connectionID, serviceID, runID string, runNumber, revision int64, now time.Time) (controlstatedb.ControlPrivateServiceRun, error) {
	if !opaqueid.Valid(connectionID, opaqueid.PublisherConnectionPrefix) || !opaqueid.Valid(runID, opaqueid.PrivateRunPrefix) ||
		!opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) || runNumber <= 0 || revision <= 0 {
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
	if run.RunNumber != runNumber || run.ClosedAt.Valid || !run.PublisherExpiresAt.Time.After(now) || (run.State != "starting" && run.State != "ready") {
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
	if _, err = q.GetRelayLeaseForClaim(ctx, lease.RelayID); err != nil {
		return result, err
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
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.private_service_connection_slots slot
		JOIN control.relay_leases lease ON lease.relay_id=slot.relay_id AND lease.relay_run_id=slot.relay_run_id
			AND lease.relay_lease_revision=slot.relay_lease_revision AND lease.relay_service_id=slot.relay_service_id
		WHERE slot.private_run_id=$1 AND slot.state='ready' AND slot.session_open
			AND lease.lease_expires_at > $2 AND NOT lease.draining`, runID, now).Scan(&count); err != nil {
		return result, err
	}
	certificateReady := run.CertificateExpiresAt.Valid && run.CertificateExpiresAt.Time.After(now)
	if run.Healthy && certificateReady && (count == 2 || run.ReadyAt.Valid && count >= 1) {
		if run.State == "starting" {
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
	if run.State == "ready" && !run.ClosedAt.Valid {
		var ready int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.private_service_connection_slots slot
			JOIN control.relay_leases lease ON lease.relay_id=slot.relay_id AND lease.relay_run_id=slot.relay_run_id
				AND lease.relay_lease_revision=slot.relay_lease_revision AND lease.relay_service_id=slot.relay_service_id
			WHERE slot.private_run_id=$1 AND slot.state='ready' AND slot.session_open
				AND lease.lease_expires_at > $2 AND NOT lease.draining`, runID, now).Scan(&ready); err != nil {
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
