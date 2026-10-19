package controlstate

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

// ConnectorVisitor binds the publisher's trusted forwarding header to control's
// admitted stream. the visitor does not need a second application credential.
type ConnectorVisitor struct {
	SessionID, IdentityID, DeviceID, ConnectionID string
	Source                                        netip.Addr
}

func (v ConnectorVisitor) valid() bool {
	return opaqueid.Valid(v.SessionID, opaqueid.PrivateConnectorSessionPrefix) &&
		opaqueid.Valid(v.IdentityID, opaqueid.IdentityPrefix) &&
		opaqueid.Valid(v.DeviceID, opaqueid.VisitorDevicePrefix) &&
		opaqueid.Valid(v.ConnectionID, opaqueid.VisitorConnectionPrefix) &&
		v.Source.IsValid() && v.Source.Zone() == ""
}

func (d *Database) AuthorizeServiceConnector(ctx context.Context, service, runID, token string, number int64, visitor ConnectorVisitor, now time.Time) (result PrivateVisitorValidity, retErr error) {
	if !visitor.valid() || number < 1 {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize service connector", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	if err := d.managedHTTPSourceAllowed(ctx, q, service, visitor.Source); err != nil {
		return result, err
	}
	run, err := privateRunAuthorization(ctx, tx, q, service, runID, token, now)
	if err != nil || run.RunNumber != number {
		return result, errors.Join(ErrPrivateServiceAccess, err)
	}
	result, err = recheckServiceConnector(ctx, tx, service, runID, number, visitor, now)
	if err != nil {
		return result, err
	}
	result.Admitted = result.Allowed
	return result, tx.Commit(ctx)
}

func recheckServiceConnector(ctx context.Context, tx pgx.Tx, service, runID string, number int64, visitor ConnectorVisitor, now time.Time) (PrivateVisitorValidity, error) {
	params := controlstatedb.RecheckPrivateServiceVisitorParams{Now: timestamptz(now), PrivateServiceID: service, PrivateRunID: runID, RunNumber: number, IdentityID: visitor.IdentityID, VisitorConnectionID: visitor.ConnectionID, ObservedSourceIp: visitor.Source.Unmap()}
	err := tx.QueryRow(ctx, `SELECT session.id,session.ingress_id,session.ingress_run_id,session.ingress_lease_revision FROM control.private_visitor_streams stream JOIN control.private_connector_sessions session ON session.id=stream.connector_session_id WHERE stream.visitor_connection_id=$1 AND stream.private_service_id=$2 AND stream.private_run_id=$3 AND stream.identity_id=$4 AND stream.device_id=$5 AND stream.source_ip=$6 AND stream.connector_session_id=$7 AND stream.closed_at IS NULL`, visitor.ConnectionID, service, runID, visitor.IdentityID, visitor.DeviceID, visitor.Source.Unmap(), visitor.SessionID).Scan(&params.ConnectorSessionID, &params.IngressID, &params.IngressRunID, &params.IngressLeaseRevision)
	if err != nil {
		return PrivateVisitorValidity{}, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	decision, err := controlstatedb.New(tx).RecheckPrivateServiceVisitor(ctx, params)
	return PrivateVisitorValidity{Allowed: decision.Allowed, ValidUntil: decision.ValidUntil.Time}, err
}
