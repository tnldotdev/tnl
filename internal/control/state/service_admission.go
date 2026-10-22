package state

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

func lockEnabledService(ctx context.Context, tx pgx.Tx, id string) error {
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM control.services WHERE id = $1 AND enabled AND deleted_at IS NULL FOR UPDATE`, id).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	return err
}

// take the team lock before the saved service lock, matching grant and
// membership mutations; no claim can commit against a revoked grant snapshot.
func lockServiceAdmission(ctx context.Context, tx pgx.Tx, id string) error {
	var teamID string
	err := tx.QueryRow(ctx, `SELECT team_id FROM control.services WHERE id=$1`, id).Scan(&teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	if err != nil {
		return err
	}
	var locked string
	err = tx.QueryRow(ctx, `SELECT id FROM control.teams WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, teamID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	if err != nil {
		return err
	}
	return lockEnabledService(ctx, tx, id)
}

func privateVisitorRecheckParams(lease IngressLeaseIdentity, serviceID, runID, sessionID, identityID, visitorID string,
	runNumber int64, source netip.Addr, now time.Time) controlstatedb.RecheckServiceVisitorParams {
	return controlstatedb.RecheckServiceVisitorParams{
		ServiceID: serviceID, ServiceRunID: runID, ConnectorSessionID: sessionID,
		IdentityID: text(identityID), VisitorConnectionID: visitorID, RunNumber: runNumber,
		ObservedSourceIp: source.Unmap(), Now: timestamptz(now),
		IngressID: text(lease.IngressID), IngressRunID: text(lease.IngressRunID),
		IngressLeaseRevision: pgtype.Int8{Int64: int64(lease.IngressLeaseRevision), Valid: true},
	}
}

// RecheckServiceVisitor verifies the exact admitted visitor connection.
// it does not extend publisher or ingress leases or grant
// new permission; a revoked grant, stopped run, or lost ingress lease denies.
func (d *Database) RecheckServiceVisitor(ctx context.Context, lease IngressLeaseIdentity, serviceID, runID, sessionID, identityID, visitorID string, runNumber int64, source netip.Addr, now time.Time) (result ServiceVisitorValidity, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(runID, opaqueid.ServiceRunPrefix) ||
		!opaqueid.Valid(sessionID, opaqueid.ConnectorSessionPrefix) ||
		!opaqueid.Valid(identityID, opaqueid.IdentityPrefix) ||
		!opaqueid.Valid(visitorID, opaqueid.VisitorConnectionPrefix) ||
		runNumber < 1 || !source.IsValid() || source.Zone() != "" {
		return result, ErrServiceAccess
	}
	if err := validateIngressLeaseIdentity(lease); err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "recheck private visitor", &retErr)()
	if err := lockServiceAdmission(ctx, tx, serviceID); err != nil {
		if errors.Is(err, ErrServiceAccess) {
			return ServiceVisitorValidity{ValidUntil: now}, nil
		}
		return result, err
	}
	q := controlstatedb.New(tx)
	if _, err := lockCurrentIngressLease(ctx, q, lease, now); err != nil {
		if errors.Is(err, ErrIngressLeaseStale) {
			return ServiceVisitorValidity{ValidUntil: now}, nil
		}
		return result, err
	}
	row, err := q.RecheckServiceVisitor(ctx, privateVisitorRecheckParams(lease, serviceID, runID, sessionID, identityID, visitorID, runNumber, source, now))
	if err != nil {
		return result, err
	}
	if row.Allowed && (!row.ValidUntil.Valid || !row.ValidUntil.Time.After(now)) {
		return result, ErrServiceAccess
	}
	if row.Allowed {
		if _, err = tx.Exec(ctx, `UPDATE control.connector_visitor_streams SET valid_until=$2 WHERE visitor_connection_id=$1 AND closed_at IS NULL`, visitorID, row.ValidUntil.Time); err != nil {
			return result, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return ServiceVisitorValidity{Allowed: row.Allowed, ValidUntil: row.ValidUntil.Time}, nil
}
