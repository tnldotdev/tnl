package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type serviceEndpoint struct {
	ServiceID, GroupID, DomainID, Hostname, Namespace, PoolID string
	LocalSourceKey                                            string
	Public, Automation                                        bool
}

func reconcileServiceEndpoint(ctx context.Context, tx pgx.Tx, endpoint serviceEndpoint, now time.Time) error {
	if err := retireServiceEndpoints(ctx, tx, endpoint.ServiceID, endpoint.Hostname, now); err != nil {
		return err
	}
	state := PublicURLDNSUnmanaged
	var available *time.Time
	if endpoint.Automation {
		state, available = PublicURLDNSPending, &now
	}
	var hostname string
	err := tx.QueryRow(ctx, `INSERT INTO control.service_endpoints(hostname,service_id,group_id,domain_id,namespace,ingress_pool_id,public,dns_authority_reference,dns_state,dns_available_at,created_at,local_source_key)
	    SELECT $1,$2,$3,domain.id,$5,$6,$7,domain.dns_authority_reference,$8,$9,$10,$11 FROM control.domains domain WHERE domain.id=$4
	    ON CONFLICT(hostname) DO UPDATE SET service_id=EXCLUDED.service_id,group_id=EXCLUDED.group_id,domain_id=EXCLUDED.domain_id,namespace=EXCLUDED.namespace,ingress_pool_id=EXCLUDED.ingress_pool_id,public=EXCLUDED.public,
	      retired_at=NULL,reusable_after=NULL,dns_authority_reference=EXCLUDED.dns_authority_reference,
	      dns_state=CASE WHEN control.service_endpoints.service_id=EXCLUDED.service_id AND control.service_endpoints.public=EXCLUDED.public AND control.service_endpoints.retired_at IS NULL AND control.service_endpoints.dns_state NOT IN('unmanaged','removed','failed') THEN control.service_endpoints.dns_state ELSE EXCLUDED.dns_state END,
	      dns_available_at=CASE WHEN control.service_endpoints.service_id=EXCLUDED.service_id AND control.service_endpoints.public=EXCLUDED.public AND control.service_endpoints.retired_at IS NULL AND control.service_endpoints.dns_state NOT IN('unmanaged','removed','failed') THEN control.service_endpoints.dns_available_at ELSE EXCLUDED.dns_available_at END,
	      dns_revision=control.service_endpoints.dns_revision+1,dns_work_owner=NULL,dns_work_expires_at=NULL
	    WHERE control.service_endpoints.service_id=EXCLUDED.service_id
	      OR(control.service_endpoints.group_id=EXCLUDED.group_id AND EXCLUDED.group_id IS NOT NULL
	        AND EXISTS(SELECT 1 FROM control.services previous WHERE previous.id=control.service_endpoints.service_id AND previous.deleted_at IS NOT NULL))
	      OR(control.service_endpoints.local_source_key=EXCLUDED.local_source_key AND EXCLUDED.local_source_key<>''
	        AND EXISTS(SELECT 1 FROM control.services previous WHERE previous.id=control.service_endpoints.service_id AND previous.deleted_at IS NOT NULL))
	      OR(control.service_endpoints.retired_at IS NOT NULL AND control.service_endpoints.reusable_after<=$10 AND control.service_endpoints.dns_state='removed'
	        AND EXISTS(SELECT 1 FROM control.service_namespace_claims claim WHERE claim.namespace=control.service_endpoints.namespace AND claim.group_id=EXCLUDED.group_id AND claim.retired_at IS NULL))
	    RETURNING hostname`, endpoint.Hostname, endpoint.ServiceID, nullableText(endpoint.GroupID), endpoint.DomainID, endpoint.Namespace, endpoint.PoolID, endpoint.Public, string(state), available, now, endpoint.LocalSourceKey).Scan(&hostname)
	return projectConstraintError(publisherLookupError(err, ErrServiceConflict))
}

func retireServiceEndpoints(ctx context.Context, tx pgx.Tx, service, keep string, now time.Time) error {
	_, err := tx.Exec(ctx, `SELECT control.retire_service_endpoints($1,$2,$3)`, service, keep, now)
	return err
}

type ServiceEndpointDNSWork struct {
	Hostname, ServiceID, OwnerID, DomainID, PoolID, AuthorityReference string
	Public                                                             bool
	State                                                              PublicURLDNSState
	Revision, Epoch, Attempts                                          int64
	Worker                                                             string
	ExpiresAt, AvailableAt                                             time.Time
	LastError                                                          string
}

func managedDNSWork(row controlstatedb.ControlServiceEndpoint) ServiceEndpointDNSWork {
	owner := row.ServiceID
	if row.GroupID.Valid {
		owner = row.GroupID.String
	}
	return ServiceEndpointDNSWork{Hostname: row.Hostname, ServiceID: row.ServiceID, OwnerID: owner, DomainID: row.DomainID, PoolID: row.IngressPoolID, AuthorityReference: row.DnsAuthorityReference.String, Public: row.Public, State: PublicURLDNSState(row.DnsState), Revision: row.DnsRevision, Epoch: row.DnsWorkEpoch, Attempts: row.DnsAttempts, Worker: row.DnsWorkOwner.String, ExpiresAt: row.DnsWorkExpiresAt.Time, AvailableAt: row.DnsAvailableAt.Time, LastError: row.DnsLastError.String}
}

func (d *Database) ClaimServiceEndpointDNSWork(ctx context.Context, worker string, now time.Time, duration time.Duration) (ServiceEndpointDNSWork, bool, error) {
	if !validStateText(worker) || duration <= 0 || now.IsZero() {
		return ServiceEndpointDNSWork{}, false, ErrDNSPublicURLInvalid
	}
	row, err := controlstatedb.New(d.pool).ClaimServiceEndpointDNSWork(ctx, controlstatedb.ClaimServiceEndpointDNSWorkParams{Worker: text(worker), Now: timestamptz(now), ExpiresAt: timestamptz(now.Add(duration))})
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceEndpointDNSWork{}, false, nil
	}
	return managedDNSWork(row), err == nil, err
}

func (d *Database) SaveServiceEndpointDNSWork(ctx context.Context, work ServiceEndpointDNSWork, now time.Time) (ServiceEndpointDNSWork, error) {
	if !opaqueid.Valid(work.ServiceID, opaqueid.ServicePrefix) || work.Worker == "" || work.Revision < 1 || work.Epoch < 1 || !work.ExpiresAt.After(now) || work.State != PublicURLDNSPending && work.State != PublicURLDNSPublished && work.State != PublicURLDNSRemoving && work.State != PublicURLDNSRemoved && work.State != PublicURLDNSFailed {
		return ServiceEndpointDNSWork{}, ErrDNSPublicURLInvalid
	}
	var available *time.Time
	if !work.AvailableAt.IsZero() {
		available = &work.AvailableAt
	}
	row, err := controlstatedb.New(d.pool).SaveServiceEndpointDNSWork(ctx, controlstatedb.SaveServiceEndpointDNSWorkParams{Hostname: work.Hostname, ServiceID: work.ServiceID, State: string(work.State), Revision: work.Revision, Worker: text(work.Worker), Epoch: work.Epoch, AvailableAt: nullableTime(available), LastError: nullableText(work.LastError), Now: timestamptz(now)})
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceEndpointDNSWork{}, ErrDNSPublicURLWorkStale
	}
	return managedDNSWork(row), err
}

func (d *Database) ValidateServiceEndpointDNSWork(ctx context.Context, work ServiceEndpointDNSWork, now time.Time) error {
	var current bool
	err := d.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_endpoints WHERE hostname=$1 AND service_id=$2 AND dns_revision=$3 AND dns_work_owner=$4 AND dns_work_epoch=$5 AND dns_work_expires_at>$6)`, work.Hostname, work.ServiceID, work.Revision, work.Worker, work.Epoch, now).Scan(&current)
	if err != nil {
		return err
	}
	if !current {
		return ErrDNSPublicURLWorkStale
	}
	if work.Public && work.State != PublicURLDNSRemoving {
		if err := d.pool.QueryRow(ctx, `SELECT EXISTS(
		    SELECT 1 FROM control.services service JOIN control.service_runs run ON run.service_id=service.id
		    WHERE service.id=$1 AND service.public AND service.enabled AND service.deleted_at IS NULL
		      AND run.state='ready' AND run.healthy AND run.closed_at IS NULL AND run.publisher_expires_at>$2 AND run.certificate_expires_at>$2
		      AND EXISTS(SELECT 1 FROM control.service_connection_slots slot
		        JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id
		          AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id
		        WHERE slot.service_run_id=run.id AND slot.state='ready' AND slot.session_open AND NOT relay.draining AND relay.lease_expires_at>$2)
		      AND EXISTS(SELECT 1 FROM control.ingress_leases ingress WHERE ingress.ingress_pool_id=service.ingress_pool_id
		        AND service.service_port=ANY(ingress.service_ports) AND NOT ingress.draining AND ingress.lease_expires_at>$2)
		      AND NOT EXISTS(SELECT 1 FROM control.ingress_leases ingress WHERE ingress.ingress_pool_id=service.ingress_pool_id
		        AND NOT (service.service_port=ANY(ingress.service_ports)) AND NOT ingress.draining AND ingress.lease_expires_at>$2))`, work.ServiceID, now).Scan(&current); err != nil {
			return err
		}
		if !current {
			return ErrDNSPublicURLWorkStale
		}
	}
	return nil
}
