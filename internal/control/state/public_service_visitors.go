package state

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

type PublicServiceVisitorAdmission struct {
	ServiceID, RunID, ConnectionID string
	RunNumber                      int64
	ExpiresAt                      time.Time
	Relays                         []ServiceRelay
	Traffic                        trafficlimits.Limits
	RecoveryEpisodeID              *int64
}

// AdmitPublicServiceVisitor reserves bounded native pre-authentication capacity
// by trusted destination port, without inspecting protocol negotiation.
func (d *Database) AdmitPublicServiceVisitor(ctx context.Context, lease IngressLeaseIdentity, pool, visitor string, port int, source netip.Addr, now time.Time, excluded ...ServiceRunReference) (result PublicServiceVisitorAdmission, retErr error) {
	clock := newAuthorizationClock(now)
	if validateIngressLeaseIdentity(lease) != nil || !opaqueid.Valid(visitor, opaqueid.VisitorConnectionPrefix) || !tcpport.ValidNetwork(port) || port < 1024 || !source.IsValid() || source.Zone() != "" || len(excluded) > 7 {
		return result, ErrServiceAccess
	}
	seenIDs, seenNumbers := make(map[string]bool, len(excluded)), make(map[int64]bool, len(excluded))
	for _, run := range excluded {
		if _, err := checkedServiceRunBinding(run.ServiceID, run.RunID, run.RunNumber); err != nil || seenIDs[run.RunID] || seenNumbers[run.RunNumber] {
			return result, ErrServiceAccess
		}
		seenIDs[run.RunID], seenNumbers[run.RunNumber] = true, true
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "admit public service visitor", &retErr)()
	// select the service before the admission lock, then revalidate everything
	// under that lock. an old DNS answer cannot authorize a private endpoint.
	err = tx.QueryRow(ctx, `SELECT id FROM control.services WHERE ingress_pool_id=$1 AND service_port=$2
	    AND protocol<>'http' AND public AND enabled AND deleted_at IS NULL`, pool, port).Scan(&result.ServiceID)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	for _, run := range excluded {
		if run.ServiceID != result.ServiceID {
			return PublicServiceVisitorAdmission{}, ErrServiceAccess
		}
	}
	if err = lockPublicServiceVisitorCapacity(ctx, tx, result.ServiceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	service, err := q.GetService(ctx, result.ServiceID)
	if err != nil || !service.Public || service.IngressPoolID != pool || int(service.ServicePort.Int32) != port ||
		service.Protocol == "http" {
		return result, errors.Join(ErrServiceAccess, err)
	}
	current, err := lockCurrentIngressLease(ctx, q, lease, clock.current())
	if err != nil || current.Draining {
		return result, errors.Join(ErrServiceAccess, err)
	}
	var supported bool
	if err = tx.QueryRow(ctx, `SELECT ingress_pool_id=$2 AND $3=ANY(service_ports)
	    FROM control.ingress_leases WHERE ingress_id=$1`, lease.IngressID, pool, port).Scan(&supported); err != nil || !supported {
		return result, errors.Join(ErrServiceAccess, err)
	}
	var existing bool
	err = tx.QueryRow(ctx, `SELECT service_run_id,run_number,valid_until FROM control.public_service_visitors WHERE visitor_connection_id=$1 AND service_id=$2 AND ingress_id=$3 AND ingress_run_id=$4 AND ingress_lease_revision=$5 AND source_ip=$6 AND destination_port=$7 AND valid_until>$8 AND closed_at IS NULL`, visitor, result.ServiceID, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), source.Unmap(), port, clock.current()).Scan(&result.RunID, &result.RunNumber, &result.ExpiresAt)
	if err == nil {
		existing = true
		for _, run := range excluded {
			if run.RunID == result.RunID && run.RunNumber == result.RunNumber {
				return PublicServiceVisitorAdmission{}, ErrServiceAccess
			}
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		result.RunID, result.RunNumber, _, err = selectRoutableServiceRun(ctx, tx, result.ServiceID, service.CertificateHostname, clock.current(), excluded...)
	}
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	result.Relays, _, err = privateConnectedRelays(ctx, tx, result.RunID, clock.current())
	if err != nil || len(result.Relays) == 0 {
		return result, errors.Join(ErrServiceAccess, err)
	}
	if !existing {
		result.ExpiresAt = minTime(now.Add(10*time.Second), current.LeaseExpiresAt.Time)
	}
	// retries retain their original setup bound but still need the current run
	// and certificate. a saved pending row cannot revive expired serving state.
	var runUntil time.Time
	var traffic []byte
	err = tx.QueryRow(ctx, `SELECT LEAST(run.publisher_expires_at,run.certificate_expires_at,permission.expires_at),run.traffic_limits
	    FROM control.service_runs run
	    JOIN LATERAL control.publisher_service_permission(run.publisher_identity_id,run.publisher_grant_id,run.service_id,$4) permission ON true
	    JOIN control.publisher_grants g ON g.id=run.publisher_grant_id
	    JOIN control.publisher_identity_keys signing ON signing.id=run.publisher_key_id AND signing.publisher_identity_id=run.publisher_identity_id
	    WHERE run.id=$1 AND run.service_id=$2 AND run.run_number=$3 AND run.state='ready' AND run.healthy
	    AND run.closed_at IS NULL AND run.publisher_expires_at>$4 AND run.certificate_expires_at>$4
	    AND run.certificate_hostname=$5 AND run.certificate_domain_id=$6
	    AND (g.kind='service' OR signing.retired_at IS NULL)`, result.RunID, result.ServiceID, result.RunNumber, clock.current(), service.CertificateHostname, service.DomainID).Scan(&runUntil, &traffic)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	result.Traffic, err = decodeRunTraffic(traffic)
	if err != nil {
		return result, err
	}
	result.ExpiresAt = minTime(result.ExpiresAt, runUntil)
	if !existing {
		_, err = tx.Exec(ctx, `INSERT INTO control.public_service_visitors(visitor_connection_id,service_id,service_run_id,run_number,ingress_id,ingress_run_id,ingress_lease_revision,destination_port,source_ip,valid_until,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(visitor_connection_id) DO NOTHING`, visitor, result.ServiceID, result.RunID, result.RunNumber, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), port, source.Unmap(), result.ExpiresAt, now)
		if err != nil {
			return result, err
		}
		// verify the exact reserved identity even when the retry key collided.
		var same bool
		// return the stored deadline on the first response too. PostgreSQL stores
		// microseconds, so an in-memory nanosecond deadline would change on retry.
		if err = tx.QueryRow(ctx, `SELECT service_id=$2 AND service_run_id=$3 AND ingress_id=$4 AND ingress_run_id=$5 AND ingress_lease_revision=$6 AND source_ip=$7 AND destination_port=$8 AND valid_until>$9 AND closed_at IS NULL,valid_until FROM control.public_service_visitors WHERE visitor_connection_id=$1`, visitor, result.ServiceID, result.RunID, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), source.Unmap(), port, clock.current()).Scan(&same, &result.ExpiresAt); err != nil || !same {
			return result, errors.Join(ErrServiceAccess, err)
		}
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return PublicServiceVisitorAdmission{}, err
	}
	if !result.ExpiresAt.After(clock.current()) {
		return PublicServiceVisitorAdmission{}, ErrServiceAccess
	}
	result.ConnectionID = visitor
	episode, err := q.GetOpenServiceRecoveryEpisode(ctx, result.RunID)
	if err == nil {
		result.RecoveryEpisodeID = &episode.ID
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return PublicServiceVisitorAdmission{}, err
	}
	return result, tx.Commit(ctx)
}

// PublicServiceVisitorStatus distinguishes TLS setup from an authenticated application
// stream. pending never extends its original admission deadline.
type PublicServiceVisitorStatus struct {
	State      PublicServiceVisitorState
	ValidUntil time.Time
}

type PublicServiceVisitorState string

const (
	PublicServiceVisitorPending       PublicServiceVisitorState = "pending"
	PublicServiceVisitorAuthenticated PublicServiceVisitorState = "authenticated"
	PublicServiceVisitorAllowed       PublicServiceVisitorState = "allowed"
	PublicServiceVisitorDenied        PublicServiceVisitorState = "denied"
)

func (d *Database) PublicServiceVisitorStatus(ctx context.Context, lease IngressLeaseIdentity, visitor string, now time.Time) (result PublicServiceVisitorStatus, retErr error) {
	if validateIngressLeaseIdentity(lease) != nil || !opaqueid.Valid(visitor, opaqueid.VisitorConnectionPrefix) {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "check public service visitor", &retErr)()
	result.State = PublicServiceVisitorDenied
	var service, run string
	var source netip.Addr
	var number int64
	err = tx.QueryRow(ctx, `SELECT service_id,service_run_id,run_number,source_ip,valid_until FROM control.public_service_visitors WHERE visitor_connection_id=$1 AND ingress_id=$2 AND ingress_run_id=$3 AND ingress_lease_revision=$4 AND closed_at IS NULL AND valid_until>$5`, visitor, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), now).Scan(&service, &run, &number, &source, &result.ValidUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicServiceVisitorStatus{State: PublicServiceVisitorDenied, ValidUntil: now}, nil
	}
	if err != nil {
		return result, err
	}
	if err = lockPublicServiceVisitorCapacity(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	if _, err = lockCurrentIngressLease(ctx, q, lease, now); err != nil {
		return result, err
	}
	binding, err := q.ServicePublicEndpointBinding(ctx, visitor)
	if err != nil {
		return result, err
	}
	if binding.WorkloadSessionID.Valid {
		if _, err := d.serviceHTTPSourcePolicy(ctx, q, service, source); err != nil {
			return result, err
		}
		validity, err := recheckWorkloadPublicServiceVisitor(ctx, tx, service, run, number, visitor, binding.WorkloadSessionID.String, source, nil, now)
		if err != nil && !errors.Is(err, ErrServiceAccess) {
			return result, err
		}
		result.ValidUntil = validity.ValidUntil
		if validity.Allowed {
			result.State = PublicServiceVisitorAuthenticated
			if validity.Admitted {
				result.State = PublicServiceVisitorAllowed
			}
		}
	} else if !binding.IdentityID.Valid {
		var public bool
		if err = tx.QueryRow(ctx, `SELECT public FROM control.services WHERE id=$1`, service).Scan(&public); err != nil {
			return result, err
		}
		if public {
			result.State = PublicServiceVisitorPending
		}
	} else {
		if _, err := d.serviceHTTPSourcePolicy(ctx, q, service, source); err != nil {
			if errors.Is(err, ErrServiceAccess) {
				return PublicServiceVisitorStatus{State: PublicServiceVisitorDenied, ValidUntil: now}, nil
			}
			return result, err
		}
		validity, err := recheckPublicServiceVisitor(ctx, tx, service, run, number, visitor, binding.IdentityID.String, binding.DeviceID.String, source, nil, now)
		if err != nil && !errors.Is(err, ErrServiceAccess) {
			return result, err
		}
		result.ValidUntil = validity.ValidUntil
		if validity.Allowed {
			result.State = PublicServiceVisitorAuthenticated
			if validity.Admitted {
				result.State = PublicServiceVisitorAllowed
			}
		}
	}
	return result, tx.Commit(ctx)
}

func (d *Database) PromotePublicServiceVisitor(ctx context.Context, lease IngressLeaseIdentity, visitor string, now time.Time) error {
	if validateIngressLeaseIdentity(lease) != nil || !opaqueid.Valid(visitor, opaqueid.VisitorConnectionPrefix) {
		return ErrServiceAccess
	}
	var id string
	err := d.pool.QueryRow(ctx, `UPDATE control.public_service_visitors v SET promoted_at=COALESCE(v.promoted_at,$5)
	    FROM control.services service,control.ingress_leases ingress
	    WHERE v.visitor_connection_id=$1 AND v.ingress_id=$2 AND v.ingress_run_id=$3 AND v.ingress_lease_revision=$4 AND v.closed_at IS NULL AND v.valid_until>$5
	    AND service.protocol<>'http' AND (v.identity_id IS NOT NULL OR v.workload_session_id IS NOT NULL)
	    AND service.id=v.service_id AND service.public AND service.enabled AND service.deleted_at IS NULL
	    AND ingress.ingress_id=v.ingress_id AND ingress.ingress_run_id=v.ingress_run_id AND ingress.ingress_lease_revision=v.ingress_lease_revision AND ingress.lease_expires_at>$5
	    RETURNING v.visitor_connection_id`, visitor, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), now).Scan(&id)
	return publisherLookupError(err, ErrServiceAccess)
}

func (d *Database) ClosePublicServiceVisitor(ctx context.Context, lease IngressLeaseIdentity, visitor string, now time.Time) error {
	if validateIngressLeaseIdentity(lease) != nil || !opaqueid.Valid(visitor, opaqueid.VisitorConnectionPrefix) {
		return ErrServiceAccess
	}
	_, err := d.pool.Exec(ctx, `UPDATE control.public_service_visitors SET closed_at=COALESCE(closed_at,$5) WHERE visitor_connection_id=$1 AND ingress_id=$2 AND ingress_run_id=$3 AND ingress_lease_revision=$4`, visitor, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), now)
	return err
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
