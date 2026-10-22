package controlstate

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type managedEndpoint struct {
	ServiceID, GroupID, DomainID, Hostname, Namespace, PoolID string
	LocalSourceKey                                            string
	Public, Automation                                        bool
}

func reconcileManagedEndpoint(ctx context.Context, tx pgx.Tx, endpoint managedEndpoint, now time.Time) error {
	if err := retireManagedEndpoints(ctx, tx, endpoint.ServiceID, endpoint.Hostname, now); err != nil {
		return err
	}
	state := PublicURLDNSUnmanaged
	var available *time.Time
	if endpoint.Automation {
		state, available = PublicURLDNSPending, &now
	}
	var hostname string
	err := tx.QueryRow(ctx, `INSERT INTO control.managed_service_endpoints(hostname,private_service_id,group_id,domain_id,namespace,ingress_pool_id,public,dns_authority_reference,dns_state,dns_available_at,created_at,local_source_key)
	    SELECT $1,$2,$3,domain.id,$5,$6,$7,domain.dns_authority_reference,$8,$9,$10,$11 FROM control.domains domain WHERE domain.id=$4
	    ON CONFLICT(hostname) DO UPDATE SET private_service_id=EXCLUDED.private_service_id,group_id=EXCLUDED.group_id,domain_id=EXCLUDED.domain_id,namespace=EXCLUDED.namespace,ingress_pool_id=EXCLUDED.ingress_pool_id,public=EXCLUDED.public,
	      retired_at=NULL,reusable_after=NULL,dns_authority_reference=EXCLUDED.dns_authority_reference,
	      dns_state=CASE WHEN control.managed_service_endpoints.private_service_id=EXCLUDED.private_service_id AND control.managed_service_endpoints.public=EXCLUDED.public AND control.managed_service_endpoints.retired_at IS NULL AND control.managed_service_endpoints.dns_state NOT IN('unmanaged','removed','failed') THEN control.managed_service_endpoints.dns_state ELSE EXCLUDED.dns_state END,
	      dns_available_at=CASE WHEN control.managed_service_endpoints.private_service_id=EXCLUDED.private_service_id AND control.managed_service_endpoints.public=EXCLUDED.public AND control.managed_service_endpoints.retired_at IS NULL AND control.managed_service_endpoints.dns_state NOT IN('unmanaged','removed','failed') THEN control.managed_service_endpoints.dns_available_at ELSE EXCLUDED.dns_available_at END,
	      dns_revision=control.managed_service_endpoints.dns_revision+1,dns_work_owner=NULL,dns_work_expires_at=NULL
	    WHERE control.managed_service_endpoints.private_service_id=EXCLUDED.private_service_id
	      OR(control.managed_service_endpoints.group_id=EXCLUDED.group_id AND EXCLUDED.group_id IS NOT NULL
	        AND EXISTS(SELECT 1 FROM control.private_services previous WHERE previous.id=control.managed_service_endpoints.private_service_id AND previous.deleted_at IS NOT NULL))
	      OR(control.managed_service_endpoints.local_source_key=EXCLUDED.local_source_key AND EXCLUDED.local_source_key<>''
	        AND EXISTS(SELECT 1 FROM control.private_services previous WHERE previous.id=control.managed_service_endpoints.private_service_id AND previous.deleted_at IS NOT NULL))
	      OR(control.managed_service_endpoints.retired_at IS NOT NULL AND control.managed_service_endpoints.reusable_after<=$10 AND control.managed_service_endpoints.dns_state='removed'
	        AND EXISTS(SELECT 1 FROM control.managed_namespace_claims claim WHERE claim.namespace=control.managed_service_endpoints.namespace AND claim.group_id=EXCLUDED.group_id AND claim.retired_at IS NULL))
	    RETURNING hostname`, endpoint.Hostname, endpoint.ServiceID, nullableText(endpoint.GroupID), endpoint.DomainID, endpoint.Namespace, endpoint.PoolID, endpoint.Public, string(state), available, now, endpoint.LocalSourceKey).Scan(&hostname)
	return projectConstraintError(publisherLookupError(err, ErrPrivateServiceConflict))
}

func retireManagedEndpoints(ctx context.Context, tx pgx.Tx, service, keep string, now time.Time) error {
	_, err := tx.Exec(ctx, `SELECT control.retire_managed_endpoints($1,$2,$3)`, service, keep, now)
	return err
}

type ManagedEndpointDNSWork struct {
	Hostname, ServiceID, OwnerID, DomainID, PoolID, AuthorityReference string
	Public                                                             bool
	State                                                              PublicURLDNSState
	Revision, Epoch, Attempts                                          int64
	Worker                                                             string
	ExpiresAt, AvailableAt                                             time.Time
	LastError                                                          string
}

func managedDNSWork(row controlstatedb.ControlManagedServiceEndpoint) ManagedEndpointDNSWork {
	owner := row.PrivateServiceID
	if row.GroupID.Valid {
		owner = row.GroupID.String
	}
	return ManagedEndpointDNSWork{Hostname: row.Hostname, ServiceID: row.PrivateServiceID, OwnerID: owner, DomainID: row.DomainID, PoolID: row.IngressPoolID, AuthorityReference: row.DnsAuthorityReference.String, Public: row.Public, State: PublicURLDNSState(row.DnsState), Revision: row.DnsRevision, Epoch: row.DnsWorkEpoch, Attempts: row.DnsAttempts, Worker: row.DnsWorkOwner.String, ExpiresAt: row.DnsWorkExpiresAt.Time, AvailableAt: row.DnsAvailableAt.Time, LastError: row.DnsLastError.String}
}

func (d *Database) ClaimManagedEndpointDNSWork(ctx context.Context, worker string, now time.Time, duration time.Duration) (ManagedEndpointDNSWork, bool, error) {
	if !validStateText(worker) || duration <= 0 || now.IsZero() {
		return ManagedEndpointDNSWork{}, false, ErrDNSPublicURLInvalid
	}
	row, err := controlstatedb.New(d.pool).ClaimManagedEndpointDNSWork(ctx, controlstatedb.ClaimManagedEndpointDNSWorkParams{Worker: text(worker), Now: timestamptz(now), ExpiresAt: timestamptz(now.Add(duration))})
	if errors.Is(err, pgx.ErrNoRows) {
		return ManagedEndpointDNSWork{}, false, nil
	}
	return managedDNSWork(row), err == nil, err
}

func (d *Database) SaveManagedEndpointDNSWork(ctx context.Context, work ManagedEndpointDNSWork, now time.Time) (ManagedEndpointDNSWork, error) {
	if !opaqueid.Valid(work.ServiceID, opaqueid.PrivateServicePrefix) || work.Worker == "" || work.Revision < 1 || work.Epoch < 1 || !work.ExpiresAt.After(now) || work.State != PublicURLDNSPending && work.State != PublicURLDNSPublished && work.State != PublicURLDNSRemoving && work.State != PublicURLDNSRemoved && work.State != PublicURLDNSFailed {
		return ManagedEndpointDNSWork{}, ErrDNSPublicURLInvalid
	}
	var available *time.Time
	if !work.AvailableAt.IsZero() {
		available = &work.AvailableAt
	}
	row, err := controlstatedb.New(d.pool).SaveManagedEndpointDNSWork(ctx, controlstatedb.SaveManagedEndpointDNSWorkParams{Hostname: work.Hostname, PrivateServiceID: work.ServiceID, State: string(work.State), Revision: work.Revision, Worker: text(work.Worker), Epoch: work.Epoch, AvailableAt: nullableTime(available), LastError: nullableText(work.LastError), Now: timestamptz(now)})
	if errors.Is(err, pgx.ErrNoRows) {
		return ManagedEndpointDNSWork{}, ErrDNSPublicURLWorkStale
	}
	return managedDNSWork(row), err
}

func (d *Database) ValidateManagedEndpointDNSWork(ctx context.Context, work ManagedEndpointDNSWork, now time.Time) error {
	var current bool
	err := d.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.managed_service_endpoints WHERE hostname=$1 AND private_service_id=$2 AND dns_revision=$3 AND dns_work_owner=$4 AND dns_work_epoch=$5 AND dns_work_expires_at>$6)`, work.Hostname, work.ServiceID, work.Revision, work.Worker, work.Epoch, now).Scan(&current)
	if err != nil {
		return err
	}
	if !current {
		return ErrDNSPublicURLWorkStale
	}
	if work.Public && work.State != PublicURLDNSRemoving {
		if err := d.pool.QueryRow(ctx, `SELECT EXISTS(
		    SELECT 1 FROM control.private_services service JOIN control.private_service_runs run ON run.private_service_id=service.id
		    WHERE service.id=$1 AND service.public AND service.enabled AND service.deleted_at IS NULL
		      AND run.state='ready' AND run.healthy AND run.closed_at IS NULL AND run.publisher_expires_at>$2 AND run.certificate_expires_at>$2
		      AND EXISTS(SELECT 1 FROM control.private_service_connection_slots slot
		        JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id
		          AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id
		        WHERE slot.private_run_id=run.id AND slot.state='ready' AND slot.session_open AND NOT relay.draining AND relay.lease_expires_at>$2)
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
