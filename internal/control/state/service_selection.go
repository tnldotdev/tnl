package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ServiceInventory struct {
	ServiceMetadata
	KubernetesAuth                 *controlv1.KubernetesAuth
	ID, TeamID, Name, ServiceRunID string
	RunNumber                      int64
	CreatedAt                      time.Time
}

type ServiceVisitorValidity struct {
	Allowed    bool
	Admitted   bool
	ValidUntil time.Time
}

type ServiceRelay struct {
	TLSServerName                string    `json:"tls_server_name"`
	PublisherConnectionID        string    `json:"publisher_connection_id"`
	ConnectionSlot               int16     `json:"connection_slot"`
	RelayServiceID               string    `json:"relay_service_id"`
	RelayID                      string    `json:"relay_id"`
	RelayRunID                   string    `json:"relay_run_id"`
	InternalRelayAddress         string    `json:"internal_relay_address"`
	RelayLeaseRevision           int64     `json:"relay_lease_revision"`
	ConnectionAssignmentRevision int64     `json:"connection_assignment_revision"`
	LeaseExpiresAt               time.Time `json:"lease_expires_at"`
}

type ServiceSelection struct {
	Subject VisitorSubject
	ServiceMetadata
	ServiceID, ServiceRunID, IdentityID, DeviceID string
	RunNumber                                     int64
	ExpiresAt                                     time.Time
	PairReady                                     *NativePeerPairReady
}

// NativePeerPairReady is a credential-free signing hint, never delivery authority.
type NativePeerPairReady struct {
	PublisherIdentityID string
	Relays              [2]NativePeerPairRelay
}

// access is evaluated inside the team/service admission lock. the deadline
// includes the last currently valid grant, rather than the first matching one.
func privateVisitorAccess(ctx context.Context, tx pgx.Tx, serviceID, identityID string, now time.Time) (time.Time, int64, error) {
	var until time.Time
	var revision int64
	err := tx.QueryRow(ctx, `SELECT LEAST($3::timestamptz+interval '2 minutes',permission.expires_at),s.visitor_revision+t.policy_revision
	    FROM control.services s JOIN control.teams t ON t.id=s.team_id
	    CROSS JOIN LATERAL control.visitor_identity_permission('service',s.id,$2,$4,'',$3) permission
	    WHERE s.id=$1`, serviceID, identityID, now, companySessionID(ctx, identityID)).Scan(&until, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return until, 0, ErrServiceAccess
	}
	return until, revision, err
}

func (d *Database) SelectServiceRun(ctx context.Context, serviceID, identityID, deviceID string, now time.Time) (ServiceSelection, error) {
	return d.SelectVisitorServiceRun(ctx, serviceID, VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: identityID, DeviceID: deviceID}, now)
}

func (d *Database) SelectVisitorServiceRun(ctx context.Context, serviceID string, subject VisitorSubject, now time.Time) (result ServiceSelection, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "select service run", &retErr)()
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	until, _, err := VisitorSubjectAccess(ctx, tx, serviceID, subject, now)
	if err != nil {
		return result, err
	}
	service, err := controlstatedb.New(tx).LockService(ctx, serviceID)
	if err != nil {
		return result, err
	}
	// count only admitted streams with a current hard deadline. no established
	// stream moves, and expired authority cannot retain capacity indefinitely.
	err = tx.QueryRow(ctx, `SELECT run.id,run.run_number,LEAST(run.publisher_expires_at,g.expires_at,run.certificate_expires_at)
	    FROM control.publisher_service_runs runtime JOIN control.service_runs run ON run.id=runtime.id
	    JOIN control.publisher_grants g ON g.id=runtime.publisher_grant_id
	    JOIN control.publisher_identities p ON p.id=run.publisher_identity_id
	    WHERE runtime.service_id=$1 AND runtime.state='ready' AND runtime.healthy AND runtime.closed_at IS NULL AND runtime.publisher_expires_at>$2
	    AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>$2) AND p.revoked_at IS NULL
	    AND run.certificate_expires_at>$2
	    AND EXISTS(SELECT 1 FROM control.publisher_service_connection_slots slot JOIN control.relay_leases lease ON lease.relay_id=slot.connected_relay_id
	        AND lease.relay_run_id=slot.connected_relay_run_id AND lease.relay_lease_revision=slot.connected_relay_lease_revision
	        AND lease.relay_service_id=slot.relay_service_id
	        WHERE slot.run_id=run.id AND slot.state='ready' AND slot.session_open AND lease.lease_expires_at>$2 AND NOT lease.draining AND lease.reported_streams<lease.stream_capacity)
	    AND GREATEST(runtime.reported_streams,(SELECT count(*) FROM control.service_visitor_capacity stream WHERE stream.service_run_id=run.id AND stream.closed_at IS NULL AND stream.valid_until>$2))<runtime.stream_capacity
	    ORDER BY GREATEST(runtime.reported_streams,(SELECT count(*) FROM control.service_visitor_capacity stream WHERE stream.service_run_id=run.id AND stream.closed_at IS NULL AND stream.valid_until>$2))::numeric/runtime.stream_capacity,run.run_number LIMIT 1`, serviceID, now).
		Scan(&result.ServiceRunID, &result.RunNumber, &result.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	result.ServiceID, result.IdentityID, result.DeviceID = serviceID, subject.IdentityID, subject.DeviceID
	result.Subject = subject
	result.ExpiresAt = minTime(result.ExpiresAt, until)
	result.ServiceMetadata, err = checkedServiceMetadata(service)
	if err != nil {
		return result, err
	}
	result.PairReady, err = nativePairReadySelection(ctx, tx, result.ServiceRunID, serviceID, result.RunNumber, now)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}
