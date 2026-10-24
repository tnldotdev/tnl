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
)

type DirectVisitorAdmission struct {
	ServiceID, RunID, ConnectionID string
	RunNumber                      int64
	ExpiresAt                      time.Time
	Relays                         []ServiceRelay
}

// AdmitDirectServiceVisitor reserves only bounded pre-authentication capacity.
// the destination comes from a trusted socket or outer PROXY header, never SNI.
func (d *Database) AdmitDirectServiceVisitor(ctx context.Context, lease IngressLeaseIdentity, pool, visitor string, port int, source netip.Addr, now time.Time) (result DirectVisitorAdmission, retErr error) {
	if validateIngressLeaseIdentity(lease) != nil || !opaqueid.Valid(visitor, opaqueid.VisitorConnectionPrefix) || !tcpport.ValidNetwork(port) || port < 1024 || !source.IsValid() || source.Zone() != "" {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "admit direct service visitor", &retErr)()
	// select the service before the admission lock, then revalidate everything
	// under that lock. an old DNS answer cannot authorize a private endpoint.
	err = tx.QueryRow(ctx, `SELECT id FROM control.services WHERE ingress_pool_id=$1 AND service_port=$2 AND public AND enabled AND deleted_at IS NULL`, pool, port).Scan(&result.ServiceID)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if err = lockServiceAdmission(ctx, tx, result.ServiceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	service, err := q.GetService(ctx, result.ServiceID)
	if err != nil || !service.Public || service.IngressPoolID != pool || int(service.ServicePort.Int32) != port {
		return result, errors.Join(ErrServiceAccess, err)
	}
	current, err := lockCurrentIngressLease(ctx, q, lease, now)
	if err != nil || current.Draining {
		return result, errors.Join(ErrServiceAccess, err)
	}
	var supported bool
	if err = tx.QueryRow(ctx, `SELECT ingress_pool_id=$2 AND $3=ANY(service_ports) FROM control.ingress_leases WHERE ingress_id=$1`, lease.IngressID, pool, port).Scan(&supported); err != nil || !supported {
		return result, errors.Join(ErrServiceAccess, err)
	}
	var existing bool
	err = tx.QueryRow(ctx, `SELECT service_run_id,run_number,valid_until FROM control.direct_service_visitors WHERE visitor_connection_id=$1 AND service_id=$2 AND ingress_id=$3 AND ingress_run_id=$4 AND ingress_lease_revision=$5 AND source_ip=$6 AND destination_port=$7 AND valid_until>$8 AND closed_at IS NULL`, visitor, result.ServiceID, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), source.Unmap(), port, now).Scan(&result.RunID, &result.RunNumber, &result.ExpiresAt)
	if err == nil {
		existing = true
	} else if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT run.id,run.run_number FROM control.service_runs run JOIN control.services service ON service.id=run.service_id
		    JOIN control.publisher_grants g ON g.id=run.publisher_grant_id JOIN control.publisher_identities p ON p.id=run.publisher_identity_id
		    WHERE service.id=$1 AND service.public AND service.enabled AND service.deleted_at IS NULL AND service.ingress_pool_id=$2 AND service.service_port=$3
		    AND run.state='ready' AND run.healthy AND run.closed_at IS NULL AND run.publisher_expires_at>$4 AND run.certificate_expires_at>$4
		    AND g.revoked_at IS NULL AND(g.expires_at IS NULL OR g.expires_at>$4) AND p.revoked_at IS NULL
		    AND GREATEST(run.reported_streams,(SELECT count(*) FROM control.direct_service_visitors v WHERE v.service_run_id=run.id AND v.closed_at IS NULL AND v.valid_until>$4))<run.stream_capacity
		    ORDER BY GREATEST(run.reported_streams,(SELECT count(*) FROM control.direct_service_visitors v WHERE v.service_run_id=run.id AND v.closed_at IS NULL AND v.valid_until>$4))::numeric/run.stream_capacity,run.run_number LIMIT 1`, result.ServiceID, pool, port, now).Scan(&result.RunID, &result.RunNumber)
	}
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	result.Relays, _, err = privateConnectedRelays(ctx, tx, result.RunID, now)
	if err != nil || len(result.Relays) == 0 {
		return result, errors.Join(ErrServiceAccess, err)
	}
	if !existing {
		result.ExpiresAt = minTime(now.Add(10*time.Second), current.LeaseExpiresAt.Time)
		_, err = tx.Exec(ctx, `INSERT INTO control.direct_service_visitors(visitor_connection_id,service_id,service_run_id,run_number,ingress_id,ingress_run_id,ingress_lease_revision,destination_port,source_ip,valid_until,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(visitor_connection_id) DO NOTHING`, visitor, result.ServiceID, result.RunID, result.RunNumber, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), port, source.Unmap(), result.ExpiresAt, now)
		if err != nil {
			return result, err
		}
		// verify the exact reserved identity even when the retry key collided.
		var same bool
		if err = tx.QueryRow(ctx, `SELECT service_id=$2 AND service_run_id=$3 AND ingress_id=$4 AND ingress_run_id=$5 AND ingress_lease_revision=$6 AND source_ip=$7 AND destination_port=$8 AND valid_until>$9 AND closed_at IS NULL FROM control.direct_service_visitors WHERE visitor_connection_id=$1`, visitor, result.ServiceID, result.RunID, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), source.Unmap(), port, now).Scan(&same); err != nil || !same {
			return result, errors.Join(ErrServiceAccess, err)
		}
	}
	result.ConnectionID = visitor
	return result, tx.Commit(ctx)
}

// DirectVisitorStatus distinguishes TLS setup from an authenticated application
// stream. pending never extends its original admission deadline.
type DirectVisitorStatus struct {
	State      DirectVisitorState
	ValidUntil time.Time
}

type DirectVisitorState string

const (
	DirectVisitorPending       DirectVisitorState = "pending"
	DirectVisitorAuthenticated DirectVisitorState = "authenticated"
	DirectVisitorAllowed       DirectVisitorState = "allowed"
	DirectVisitorDenied        DirectVisitorState = "denied"
)

func (d *Database) DirectServiceVisitorStatus(ctx context.Context, lease IngressLeaseIdentity, visitor string, now time.Time) (result DirectVisitorStatus, retErr error) {
	if validateIngressLeaseIdentity(lease) != nil || !opaqueid.Valid(visitor, opaqueid.VisitorConnectionPrefix) {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "check direct service visitor", &retErr)()
	result.State = DirectVisitorDenied
	var service, run string
	var source netip.Addr
	var number int64
	err = tx.QueryRow(ctx, `SELECT service_id,service_run_id,run_number,source_ip,valid_until FROM control.direct_service_visitors WHERE visitor_connection_id=$1 AND ingress_id=$2 AND ingress_run_id=$3 AND ingress_lease_revision=$4 AND closed_at IS NULL AND valid_until>$5`, visitor, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), now).Scan(&service, &run, &number, &source, &result.ValidUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return DirectVisitorStatus{State: DirectVisitorDenied, ValidUntil: now}, nil
	}
	if err != nil {
		return result, err
	}
	if err = lockServiceAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	if _, err = lockCurrentIngressLease(ctx, q, lease, now); err != nil {
		return result, err
	}
	httpCredential, err := q.ServiceHTTPDirectCredential(ctx, visitor)
	if err != nil {
		return result, err
	}
	if httpCredential.HttpCredentialKind.Valid {
		credential, err := storedServiceHTTPCredential(httpCredential.HttpCredentialKind.String, httpCredential.HttpCredentialDigest)
		if err != nil {
			return DirectVisitorStatus{State: DirectVisitorDenied, ValidUntil: now}, nil
		}
		validity, err := d.recheckServiceHTTPVisitor(ctx, tx, service, run, number, visitor, source, httpCredential.DestinationPort, credential, now)
		if err != nil && !errors.Is(err, ErrServiceAccess) && !errors.Is(err, ErrVisitorSignIn) {
			return result, err
		}
		result.ValidUntil = validity.ValidUntil
		if validity.Allowed {
			result.State = DirectVisitorAuthenticated
			if validity.Admitted {
				result.State = DirectVisitorAllowed
			}
		}
	} else if httpCredential.WorkloadSessionID.Valid {
		if err := d.serviceHTTPSourceAllowed(ctx, q, service, source); err != nil {
			return result, err
		}
		validity, err := recheckWorkloadDirectVisitor(ctx, tx, service, run, number, visitor, httpCredential.WorkloadSessionID.String, source, nil, now)
		if err != nil && !errors.Is(err, ErrServiceAccess) {
			return result, err
		}
		result.ValidUntil = validity.ValidUntil
		if validity.Allowed {
			result.State = DirectVisitorAuthenticated
			if validity.Admitted {
				result.State = DirectVisitorAllowed
			}
		}
	} else if !httpCredential.IdentityID.Valid {
		var public bool
		if err = tx.QueryRow(ctx, `SELECT public FROM control.services WHERE id=$1`, service).Scan(&public); err != nil {
			return result, err
		}
		if public {
			result.State = DirectVisitorPending
		}
	} else {
		if err := d.serviceHTTPSourceAllowed(ctx, q, service, source); err != nil {
			if errors.Is(err, ErrServiceAccess) {
				return DirectVisitorStatus{State: DirectVisitorDenied, ValidUntil: now}, nil
			}
			return result, err
		}
		validity, err := recheckDirectServiceVisitor(ctx, tx, service, run, number, visitor, httpCredential.IdentityID.String, httpCredential.DeviceID.String, source, nil, now)
		if err != nil && !errors.Is(err, ErrServiceAccess) {
			return result, err
		}
		result.ValidUntil = validity.ValidUntil
		if validity.Allowed {
			result.State = DirectVisitorAuthenticated
			if validity.Admitted {
				result.State = DirectVisitorAllowed
			}
		}
	}
	return result, tx.Commit(ctx)
}

func (d *Database) PromoteDirectServiceVisitor(ctx context.Context, lease IngressLeaseIdentity, visitor string, now time.Time) error {
	if validateIngressLeaseIdentity(lease) != nil || !opaqueid.Valid(visitor, opaqueid.VisitorConnectionPrefix) {
		return ErrServiceAccess
	}
	var id string
	err := d.pool.QueryRow(ctx, `UPDATE control.direct_service_visitors v SET promoted_at=COALESCE(v.promoted_at,$5)
	    FROM control.services service,control.ingress_leases ingress
	    WHERE v.visitor_connection_id=$1 AND v.ingress_id=$2 AND v.ingress_run_id=$3 AND v.ingress_lease_revision=$4 AND v.closed_at IS NULL AND v.valid_until>$5 AND (v.identity_id IS NOT NULL OR v.workload_session_id IS NOT NULL OR v.http_credential_kind IS NOT NULL)
	    AND service.id=v.service_id AND service.public AND service.enabled AND service.deleted_at IS NULL
	    AND ingress.ingress_id=v.ingress_id AND ingress.ingress_run_id=v.ingress_run_id AND ingress.ingress_lease_revision=v.ingress_lease_revision AND ingress.lease_expires_at>$5
	    RETURNING v.visitor_connection_id`, visitor, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), now).Scan(&id)
	return publisherLookupError(err, ErrServiceAccess)
}

func (d *Database) CloseDirectServiceVisitor(ctx context.Context, lease IngressLeaseIdentity, visitor string, now time.Time) error {
	if validateIngressLeaseIdentity(lease) != nil || !opaqueid.Valid(visitor, opaqueid.VisitorConnectionPrefix) {
		return ErrServiceAccess
	}
	_, err := d.pool.Exec(ctx, `UPDATE control.direct_service_visitors SET closed_at=COALESCE(closed_at,$5) WHERE visitor_connection_id=$1 AND ingress_id=$2 AND ingress_run_id=$3 AND ingress_lease_revision=$4`, visitor, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), now)
	return err
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
