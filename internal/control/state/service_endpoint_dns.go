package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var (
	ErrServiceEndpointDNSInvalid   = errors.New("controlstate: invalid service endpoint DNS work")
	ErrServiceEndpointDNSWorkStale = errors.New("controlstate: service endpoint DNS work lease is stale")
)

type serviceEndpoint struct {
	ServiceID, DeploymentID, DomainID, Hostname, Namespace, PoolID string
	LocalSourceKey                                                 string
	Public, Automation                                             bool
}

func reconcileServiceEndpoint(ctx context.Context, tx pgx.Tx, endpoint serviceEndpoint, now time.Time) error {
	if err := retireServiceEndpoints(ctx, tx, endpoint.ServiceID, endpoint.Hostname, now); err != nil {
		return err
	}
	state := ServiceEndpointDNSUnmanaged
	var available *time.Time
	if endpoint.Automation && endpoint.Public {
		state, available = ServiceEndpointDNSPending, &now
	}
	// a replacement must not discard the predecessor's provider ownership
	// receipt. same-source handoff can skip quarantine, but not DNS removal.
	// a different owner needs the old namespace settled and its own current claim;
	// reusing one hostname does not transfer its old parent scope.
	var hostname string
	err := tx.QueryRow(ctx, `INSERT INTO control.service_endpoints(hostname,service_id,deployment_id,domain_id,namespace,ingress_pool_id,public,dns_automation,dns_authority_reference,dns_state,dns_available_at,created_at,local_source_key)
	    SELECT $1,$2,$3,domain.id,$5,$6,$7,$12,domain.dns_authority_reference,$8,$9,$10,$11 FROM control.domains domain WHERE domain.id=$4
	      AND NOT EXISTS (SELECT 1 FROM control.operator_nameserver_hostnames WHERE hostname=$1)
	    ON CONFLICT(hostname) DO UPDATE SET service_id=EXCLUDED.service_id,deployment_id=EXCLUDED.deployment_id,domain_id=EXCLUDED.domain_id,namespace=EXCLUDED.namespace,ingress_pool_id=EXCLUDED.ingress_pool_id,public=EXCLUDED.public,dns_automation=EXCLUDED.dns_automation,
	      retired_at=NULL,reusable_after=NULL,dns_authority_reference=EXCLUDED.dns_authority_reference,
	      dns_state=CASE
	        WHEN control.service_endpoints.dns_state NOT IN('unmanaged','removed')
	          AND (control.service_endpoints.public AND NOT EXCLUDED.public
	            OR control.service_endpoints.dns_automation AND NOT EXCLUDED.dns_automation) THEN 'removing'
	        WHEN control.service_endpoints.service_id=EXCLUDED.service_id AND control.service_endpoints.public=EXCLUDED.public
	          AND control.service_endpoints.dns_automation=EXCLUDED.dns_automation
	          AND control.service_endpoints.retired_at IS NULL AND control.service_endpoints.dns_state NOT IN('unmanaged','removed','failed') THEN control.service_endpoints.dns_state
	        ELSE EXCLUDED.dns_state END,
	      dns_available_at=CASE
	        WHEN control.service_endpoints.dns_state NOT IN('unmanaged','removed')
	          AND (control.service_endpoints.public AND NOT EXCLUDED.public
	            OR control.service_endpoints.dns_automation AND NOT EXCLUDED.dns_automation) THEN $10
	        WHEN control.service_endpoints.service_id=EXCLUDED.service_id AND control.service_endpoints.public=EXCLUDED.public
	          AND control.service_endpoints.dns_automation=EXCLUDED.dns_automation
	          AND control.service_endpoints.retired_at IS NULL AND control.service_endpoints.dns_state NOT IN('unmanaged','removed','failed') THEN
	          CASE WHEN control.service_endpoints.dns_available_at IS NOT NULL
	            AND (control.service_endpoints.deployment_id,control.service_endpoints.domain_id,
	                 control.service_endpoints.ingress_pool_id,control.service_endpoints.dns_authority_reference)
	              IS DISTINCT FROM (EXCLUDED.deployment_id,EXCLUDED.domain_id,EXCLUDED.ingress_pool_id,EXCLUDED.dns_authority_reference)
	            THEN $10 ELSE control.service_endpoints.dns_available_at END
	        ELSE EXCLUDED.dns_available_at END,
	      dns_revision=control.service_endpoints.dns_revision+1,dns_work_owner=NULL,dns_work_expires_at=NULL
	    WHERE control.service_endpoints.service_run_id IS NULL AND (control.service_endpoints.service_id=EXCLUDED.service_id
	      OR(control.service_endpoints.dns_state IN('unmanaged','removed')
	        AND control.service_endpoints.deployment_id=EXCLUDED.deployment_id AND EXCLUDED.deployment_id IS NOT NULL
	        AND EXISTS(SELECT 1 FROM control.services previous WHERE previous.id=control.service_endpoints.service_id AND previous.deleted_at IS NOT NULL))
	      OR(control.service_endpoints.dns_state IN('unmanaged','removed')
	        AND control.service_endpoints.local_source_key=EXCLUDED.local_source_key AND EXCLUDED.local_source_key<>''
	        AND EXISTS(SELECT 1 FROM control.services previous WHERE previous.id=control.service_endpoints.service_id AND previous.deleted_at IS NOT NULL))
	      OR(control.service_endpoints.retired_at IS NOT NULL AND control.service_endpoints.reusable_after<=$10 AND control.service_endpoints.dns_state='removed'
	        AND (control.service_endpoints.namespace=EXCLUDED.namespace OR control.service_namespace_reusable(control.service_endpoints.namespace,$10))
	        AND EXISTS(SELECT 1 FROM control.service_namespace_claims claim
	          WHERE claim.namespace=EXCLUDED.namespace AND claim.deployment_id=EXCLUDED.deployment_id
	            AND claim.domain_id=EXCLUDED.domain_id AND claim.retired_at IS NULL)))
	    RETURNING hostname`, endpoint.Hostname, endpoint.ServiceID, nullableText(endpoint.DeploymentID), endpoint.DomainID, endpoint.Namespace, endpoint.PoolID, endpoint.Public, string(state), available, now, endpoint.LocalSourceKey, endpoint.Automation).Scan(&hostname)
	return projectConstraintError(publisherLookupError(err, ErrServiceConflict))
}

func retireServiceEndpoints(ctx context.Context, tx pgx.Tx, service, keep string, now time.Time) error {
	_, err := tx.Exec(ctx, `SELECT control.retire_service_endpoints($1,$2,$3)`, service, keep, now)
	return err
}

type ServiceEndpointDNSWork struct {
	Hostname, ServiceID, OwnerID, DomainID, PoolID, AuthorityReference string
	Public                                                             bool
	State                                                              ServiceEndpointDNSState
	Revision, Epoch, Attempts, ConsecutiveErrors                       int64
	Worker                                                             string
	ExpiresAt, AvailableAt                                             time.Time
	LastError                                                          string
}

func managedDNSWork(row controlstatedb.ControlServiceEndpoint) ServiceEndpointDNSWork {
	owner := row.ServiceID
	if row.DeploymentID.Valid {
		owner = row.DeploymentID.String
	}
	return ServiceEndpointDNSWork{Hostname: row.Hostname, ServiceID: row.ServiceID, OwnerID: owner, DomainID: row.DomainID, PoolID: row.IngressPoolID, AuthorityReference: row.DnsAuthorityReference.String, Public: row.Public, State: ServiceEndpointDNSState(row.DnsState), Revision: row.DnsRevision, Epoch: row.DnsWorkEpoch, Attempts: row.DnsAttempts, ConsecutiveErrors: row.DnsConsecutiveErrors, Worker: row.DnsWorkOwner.String, ExpiresAt: row.DnsWorkExpiresAt.Time, AvailableAt: row.DnsAvailableAt.Time, LastError: row.DnsLastError.String}
}

func (d *Database) ClaimServiceEndpointDNSWork(ctx context.Context, worker string, now time.Time, duration time.Duration) (ServiceEndpointDNSWork, bool, error) {
	if !validStateText(worker) || duration <= 0 || now.IsZero() {
		return ServiceEndpointDNSWork{}, false, ErrServiceEndpointDNSInvalid
	}
	row, err := controlstatedb.New(d.pool).ClaimServiceEndpointDNSWork(ctx, controlstatedb.ClaimServiceEndpointDNSWorkParams{Worker: text(worker), Now: timestamptz(now), ExpiresAt: timestamptz(now.Add(duration))})
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceEndpointDNSWork{}, false, nil
	}
	return managedDNSWork(row), err == nil, err
}

func (d *Database) SaveServiceEndpointDNSWork(ctx context.Context, work ServiceEndpointDNSWork, now time.Time) (ServiceEndpointDNSWork, error) {
	if !opaqueid.Valid(work.ServiceID, opaqueid.ServicePrefix) || work.Worker == "" || work.Revision < 1 || work.Epoch < 1 || !work.ExpiresAt.After(now) || work.State != ServiceEndpointDNSPending && work.State != ServiceEndpointDNSPublished && work.State != ServiceEndpointDNSRemoving && work.State != ServiceEndpointDNSRemoved && work.State != ServiceEndpointDNSFailed {
		return ServiceEndpointDNSWork{}, ErrServiceEndpointDNSInvalid
	}
	var available *time.Time
	if !work.AvailableAt.IsZero() {
		available = &work.AvailableAt
	}
	row, err := controlstatedb.New(d.pool).SaveServiceEndpointDNSWork(ctx, controlstatedb.SaveServiceEndpointDNSWorkParams{Hostname: work.Hostname, ServiceID: work.ServiceID, State: string(work.State), Revision: work.Revision, Worker: text(work.Worker), Epoch: work.Epoch, AvailableAt: nullableTime(available), LastError: nullableText(work.LastError), Now: timestamptz(now)})
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceEndpointDNSWork{}, ErrServiceEndpointDNSWorkStale
	}
	return managedDNSWork(row), err
}

func (d *Database) ValidateServiceEndpointDNSWork(ctx context.Context, work ServiceEndpointDNSWork, now time.Time) error {
	current, err := controlstatedb.New(d.pool).ValidateServiceEndpointDNSWork(ctx, controlstatedb.ValidateServiceEndpointDNSWorkParams{
		Hostname: work.Hostname, ServiceID: work.ServiceID, Revision: work.Revision,
		Worker: work.Worker, Epoch: work.Epoch, Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	if !current {
		return ErrServiceEndpointDNSWorkStale
	}
	return nil
}
