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
	KubernetesAuth                                          *controlv1.KubernetesAuth
	ID, TeamID, TeamName, Name, ServiceRunID, VisitorAccess string
	RunNumber                                               int64
	CreatedAt                                               time.Time
	RequirePostQuantum                                      bool
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
	RelayLeaseRevision           int64     `json:"relay_lease_revision,string"`
	ConnectionAssignmentRevision int64     `json:"connection_assignment_revision,string"`
	LeaseExpiresAt               time.Time `json:"lease_expires_at"`
	ServingUntil                 time.Time `json:"serving_until"`
}

type ServiceSelection struct {
	Subject        VisitorSubject
	KubernetesAuth *controlv1.KubernetesAuth
	ServiceMetadata
	ServiceID, ServiceRunID, IdentityID, DeviceID string
	RunNumber                                     int64
	ExpiresAt                                     time.Time
	PairReady                                     *ConnectorPeerPairReady
}

// ServiceRunCursor bounds native continuation to one circular pass. references
// describe traversal, not authority; every admission still checks current state.
type ServiceRunCursor struct {
	Start, After ServiceRunReference
}

func (c ServiceRunCursor) Valid() bool {
	for _, ref := range []ServiceRunReference{c.Start, c.After} {
		if _, err := checkedServiceRunBinding(ref.ServiceID, ref.RunID, ref.RunNumber); err != nil {
			return false
		}
	}
	return c.Start.ServiceID == c.After.ServiceID &&
		(c.Start.RunID == c.After.RunID) == (c.Start.RunNumber == c.After.RunNumber)
}

func (c ServiceRunCursor) allows(number int64) bool {
	if c.After.RunNumber >= c.Start.RunNumber {
		return number > c.After.RunNumber || number < c.Start.RunNumber
	}
	return number > c.After.RunNumber && number < c.Start.RunNumber
}

// ConnectorPeerPairReady is a credential-free signing hint, never delivery authority.
type ConnectorPeerPairReady struct {
	PublisherIdentityID string
	Relays              [2]ConnectorPeerPairRelay
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

// both access paths select only runs with a current relay that can accept work.
// callers hold service admission while selecting; existing streams never reselect.
func selectRoutableServiceRun(ctx context.Context, tx pgx.Tx, serviceID, endpointHostname string, now time.Time, continuation ...ServiceRunCursor) (id string, number int64, until time.Time, err error) {
	var start, after int64
	if len(continuation) > 1 {
		return "", 0, time.Time{}, ErrServiceAccess
	}
	if len(continuation) == 1 {
		cursor := continuation[0]
		if !cursor.Valid() || cursor.Start.ServiceID != serviceID {
			return "", 0, time.Time{}, ErrServiceAccess
		}
		start, after = cursor.Start.RunNumber, cursor.After.RunNumber
	}
	err = tx.QueryRow(ctx, `SELECT run.id,run.run_number,LEAST(run.publisher_expires_at,permission.expires_at,run.certificate_expires_at)
	    FROM control.service_runs run
	    JOIN control.publisher_grants g ON g.id=run.publisher_grant_id
	    JOIN LATERAL control.publisher_service_permission(run.publisher_identity_id,run.publisher_grant_id,run.service_id,$2) permission ON true
	    JOIN control.publisher_identity_keys signing ON signing.id=run.publisher_key_id AND signing.publisher_identity_id=run.publisher_identity_id
	    WHERE run.service_id=$1 AND run.state='ready' AND run.healthy AND run.closed_at IS NULL AND run.publisher_expires_at>$2
	    AND (g.kind='service' OR signing.retired_at IS NULL)
	    AND run.certificate_expires_at>$2
	    AND ($5='' OR run.certificate_hostname=$5)
	    AND ($3::bigint=0 OR ($4::bigint>=$3 AND (run.run_number>$4 OR run.run_number<$3))
	        OR ($4<$3 AND run.run_number>$4 AND run.run_number<$3))
	    AND EXISTS(SELECT 1 FROM control.service_connection_slots slot JOIN control.relay_leases lease ON lease.relay_id=slot.relay_id
	        AND lease.relay_run_id=slot.relay_run_id AND lease.relay_lease_revision=slot.relay_lease_revision
	        AND lease.relay_service_id=slot.relay_service_id
	        WHERE slot.service_run_id=run.id AND slot.state='ready' AND slot.session_open AND lease.lease_expires_at>$2 AND NOT lease.draining AND lease.reported_streams<lease.stream_capacity)
	    AND GREATEST(run.reported_streams,(SELECT count(*) FROM control.service_visitor_capacity stream WHERE stream.service_run_id=run.id AND stream.closed_at IS NULL AND stream.valid_until>$2))<run.stream_capacity
	    ORDER BY CASE WHEN $3::bigint=0 THEN GREATEST(run.reported_streams,(SELECT count(*) FROM control.service_visitor_capacity stream WHERE stream.service_run_id=run.id AND stream.closed_at IS NULL AND stream.valid_until>$2))::numeric/run.stream_capacity ELSE 0 END,
	        CASE WHEN $3::bigint>0 AND run.run_number<=$3 THEN 1 ELSE 0 END,run.run_number LIMIT 1`, serviceID, now, start, after, endpointHostname).
		Scan(&id, &number, &until)
	return
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
	result.ServiceRunID, result.RunNumber, result.ExpiresAt, err = selectRoutableServiceRun(ctx, tx, serviceID, "", now)
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
	if result.Endpoint == nil {
		return result, ErrServiceMetadata
	}
	if err = tx.QueryRow(ctx, `SELECT certificate_hostname FROM control.service_runs WHERE id=$1`, result.ServiceRunID).Scan(&result.Endpoint.Hostname); err != nil {
		return result, err
	}
	if result.Protocol == "kubernetes" {
		result.KubernetesAuth, err = d.visitorKubernetesAuth(ctx, controlstatedb.New(tx), serviceID)
		if err != nil {
			return result, err
		}
	}
	result.PairReady, err = connectorPairReadySelection(ctx, tx, result.ServiceRunID, serviceID, result.RunNumber, now)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}
