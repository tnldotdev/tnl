package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// callers hold the service lock while deriving this endpoint observation.
// endpoint publication does not change the run's connector readiness or authority.
type serviceRunEndpoint struct {
	id, hostname, pool, protocol, aliasParent string
	domain                                    pgtype.Text
	revision                                  int64
	port                                      int32
	public                                    bool
}

func lockServiceRunEndpoint(ctx context.Context, tx pgx.Tx, serviceID string) (serviceRunEndpoint, error) {
	var endpoint serviceRunEndpoint
	err := tx.QueryRow(ctx, `SELECT id,endpoint_revision,certificate_hostname,domain_id,ingress_pool_id,protocol,service_port,public,run_alias_parent
	    FROM control.services WHERE id=$1 AND enabled AND deleted_at IS NULL FOR SHARE`, serviceID).Scan(
		&endpoint.id, &endpoint.revision, &endpoint.hostname, &endpoint.domain, &endpoint.pool, &endpoint.protocol, &endpoint.port, &endpoint.public, &endpoint.aliasParent)
	return endpoint, publisherLookupError(err, ErrServiceAccess)
}

func serviceRunAliasReady(ctx context.Context, tx pgx.Tx, endpoint serviceRunEndpoint, run controlstatedb.ControlServiceRun, canonicalReady bool, now time.Time) (bool, error) {
	if !canonicalReady || run.RunHostname == "" || run.RunAliasParent != endpoint.aliasParent {
		return false, nil
	}
	return controlstatedb.New(tx).ServiceRunPublicEndpointReady(ctx, controlstatedb.ServiceRunPublicEndpointReadyParams{
		ServiceID: endpoint.id, Hostname: run.RunHostname, DomainID: endpoint.domain.String,
		IngressPoolID: endpoint.pool, PrimaryIngressPoolID: PrimaryIngressPoolID,
		ServiceRunID: run.ID, Protocol: endpoint.protocol, ServicePort: endpoint.port, Now: timestamptz(now),
	})
}

func serviceRunPublicEndpointReady(ctx context.Context, tx pgx.Tx, endpoint serviceRunEndpoint, run controlstatedb.ControlServiceRun, now time.Time) (bool, error) {
	if serviceRunLifecycleState(run.State) != serviceRunReady {
		return false, nil
	}
	return serviceRunPublicEndpointPrerequisitesReady(ctx, tx, endpoint, run, now)
}

// the starting candidate is only for a guest's first readiness. the shared
// readiness operation also requires two current connections before committing.
// observations must use serviceRunPublicEndpointReady instead.
func serviceRunPublicEndpointPrerequisitesReady(ctx context.Context, tx pgx.Tx, endpoint serviceRunEndpoint, run controlstatedb.ControlServiceRun, now time.Time) (bool, error) {
	candidate := run.State == string(serviceRunReady) ||
		run.GuestID.Valid && run.State == string(serviceRunStarting) && !run.ReadyAt.Valid
	if !endpoint.public || endpoint.revision < 1 || !endpoint.domain.Valid ||
		run.ServiceID != endpoint.id || run.CertificateHostname != endpoint.hostname || run.CertificateDomainID != endpoint.domain ||
		!candidate || !run.Healthy || run.ClosedAt.Valid ||
		!run.PublisherExpiresAt.Time.After(now) || !run.CertificateExpiresAt.Valid || !run.CertificateExpiresAt.Time.After(now) {
		return false, nil
	}
	// use the DNS worker's current relay and ingress capability facts. an
	// automated endpoint cannot bypass publication by claiming unmanaged DNS.
	// the primary pool retains its externally addressed fallback semantics.
	return controlstatedb.New(tx).ServiceRunPublicEndpointReady(ctx, controlstatedb.ServiceRunPublicEndpointReadyParams{
		ServiceID: endpoint.id, Hostname: endpoint.hostname, DomainID: endpoint.domain.String,
		IngressPoolID: endpoint.pool, PrimaryIngressPoolID: PrimaryIngressPoolID,
		ServiceRunID: run.ID, Protocol: endpoint.protocol, ServicePort: endpoint.port, Now: timestamptz(now),
	})
}

func serviceRunFirstReadyGuestEndpointReady(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, run controlstatedb.ControlServiceRun, clock authorizationClock) (bool, error) {
	if !run.GuestID.Valid || run.ReadyAt.Valid || run.State != string(serviceRunStarting) {
		return false, ErrServiceAccess
	}
	// the owner and service are already locked before the run. retain the exact
	// endpoint too, so DNS cannot change between this decision and clock commit.
	endpoint, err := lockServiceRunEndpoint(ctx, tx, run.ServiceID)
	if err != nil {
		return false, err
	}
	_, err = q.LockServiceRunFirstReadyEndpoint(ctx, controlstatedb.LockServiceRunFirstReadyEndpointParams{
		ServiceID: endpoint.id, Hostname: endpoint.hostname, DomainID: endpoint.domain.String, IngressPoolID: endpoint.pool,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return serviceRunPublicEndpointPrerequisitesReady(ctx, tx, endpoint, run, clock.current())
}
