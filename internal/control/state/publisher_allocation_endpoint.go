package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// allocation provenance is the durable allocation plus its real namespace.
// HTTP shares 443 and never reserves a service port or invents a worktree.
func allocateServiceEndpoint(ctx context.Context, tx pgx.Tx, service, deployment, domain, namespace string, now time.Time) error {
	hostname, err := newEphemeralHostname(namespace)
	if err != nil {
		return err
	}
	var pool string
	if err = tx.QueryRow(ctx, `SELECT team.ingress_pool_id FROM control.services service
		JOIN control.teams team ON team.id=service.team_id WHERE service.id=$1`, service).Scan(&pool); err != nil {
		return err
	}
	var occupied bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.public_urls WHERE canonical_hostname=$1 AND lifecycle_state<>'deleted')`, hostname).Scan(&occupied); err != nil {
		return err
	}
	if occupied {
		return ErrServiceConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE control.services SET domain_id=$2,certificate_hostname=$3,certificate_scope=$3,
		service_port=443,ingress_pool_id=$4,public=true WHERE id=$1`, service, domain, hostname, pool); err != nil {
		return err
	}
	return reconcileServiceEndpoint(ctx, tx, serviceEndpoint{ServiceID: service, DeploymentID: deployment, DomainID: domain, Hostname: hostname, Namespace: namespace, PoolID: pool, Public: true, Automation: true}, now)
}
