package controlstate

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func lockEnabledPrivateService(ctx context.Context, tx pgx.Tx, id string) error {
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM control.private_services WHERE id = $1 AND enabled AND deleted_at IS NULL FOR UPDATE`, id).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	}
	return err
}

// take the team lock before the saved service lock, matching grant and
// membership mutations; no claim can commit against a revoked grant snapshot.
func lockPrivateAdmission(ctx context.Context, tx pgx.Tx, id string) error {
	var teamID string
	err := tx.QueryRow(ctx, `SELECT team_id FROM control.private_services WHERE id=$1`, id).Scan(&teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	}
	if err != nil {
		return err
	}
	var locked string
	err = tx.QueryRow(ctx, `SELECT id FROM control.teams WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, teamID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	}
	if err != nil {
		return err
	}
	return lockEnabledPrivateService(ctx, tx, id)
}

func privateVisitorRecheckParams(lease IngressLeaseIdentity, serviceID, runID, sessionID, identityID, visitorID string,
	runNumber int64, source netip.Addr, now time.Time) controlstatedb.RecheckPrivateServiceVisitorParams {
	return controlstatedb.RecheckPrivateServiceVisitorParams{
		PrivateServiceID: serviceID, PrivateRunID: runID, ConnectorSessionID: sessionID,
		IdentityID: text(identityID), VisitorConnectionID: visitorID, RunNumber: runNumber,
		ObservedSourceIp: source.Unmap(), Now: timestamptz(now),
		IngressID: text(lease.IngressID), IngressRunID: text(lease.IngressRunID),
		IngressLeaseRevision: pgtype.Int8{Int64: int64(lease.IngressLeaseRevision), Valid: true},
	}
}

// RecheckPrivateServiceVisitor verifies the exact admitted visitor connection.
// it does not extend publisher or ingress leases or grant
// new permission; a revoked grant, stopped run, or lost ingress lease denies.
func (d *Database) RecheckPrivateServiceVisitor(ctx context.Context, lease IngressLeaseIdentity, serviceID, runID, sessionID, identityID, visitorID string, runNumber int64, source netip.Addr, now time.Time) (result PrivateVisitorValidity, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) ||
		!opaqueid.Valid(runID, opaqueid.PrivateRunPrefix) ||
		!opaqueid.Valid(sessionID, opaqueid.PrivateConnectorSessionPrefix) ||
		!opaqueid.Valid(identityID, opaqueid.IdentityPrefix) ||
		!opaqueid.Valid(visitorID, opaqueid.VisitorConnectionPrefix) ||
		runNumber < 1 || !source.IsValid() || source.Zone() != "" {
		return result, ErrPrivateServiceAccess
	}
	if err := validateIngressLeaseIdentity(lease); err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "recheck private visitor", &retErr)()
	if err := lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		if errors.Is(err, ErrPrivateServiceAccess) {
			return PrivateVisitorValidity{ValidUntil: now}, nil
		}
		return result, err
	}
	q := controlstatedb.New(tx)
	if _, err := lockCurrentIngressLease(ctx, q, lease, now); err != nil {
		if errors.Is(err, ErrIngressLeaseStale) {
			return PrivateVisitorValidity{ValidUntil: now}, nil
		}
		return result, err
	}
	row, err := q.RecheckPrivateServiceVisitor(ctx, privateVisitorRecheckParams(lease, serviceID, runID, sessionID, identityID, visitorID, runNumber, source, now))
	if err != nil {
		return result, err
	}
	if row.Allowed && (!row.ValidUntil.Valid || !row.ValidUntil.Time.After(now)) {
		return result, ErrPrivateServiceAccess
	}
	if row.Allowed {
		if _, err = tx.Exec(ctx, `UPDATE control.private_visitor_streams SET valid_until=$2 WHERE visitor_connection_id=$1 AND closed_at IS NULL`, visitorID, row.ValidUntil.Time); err != nil {
			return result, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return PrivateVisitorValidity{Allowed: row.Allowed, ValidUntil: row.ValidUntil.Time}, nil
}
