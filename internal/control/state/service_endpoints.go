package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/naming"
)

// endpoint identity is durable across runs, publisher replicas and deployment-key
// renames. deployment moves never silently broaden certificate authority.
func (d *Database) ensureServiceEndpoint(ctx context.Context, tx pgx.Tx, service, deployment string, public, automation bool, now time.Time) error {
	var namespace, domain, pool, name, hostname string
	err := tx.QueryRow(ctx, `SELECT g.namespace,g.domain_id,t.ingress_pool_id,s.name,s.certificate_hostname FROM control.deployments g JOIN control.teams t ON t.id=g.team_id JOIN control.services s ON s.id=$1 AND s.team_id=g.team_id WHERE g.id=$2 AND g.deleted_at IS NULL FOR UPDATE OF s`, service, deployment).Scan(&namespace, &domain, &pool, &name, &hostname)
	if err != nil {
		return err
	}
	// a desired deployment move changes the endpoint, not the service's identity or
	// visitor grants. the apply transaction has already revoked old publishers.
	hostname = name + "." + namespace
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return ErrProjectConfigurationInvalid
	}
	port, err := allocateServicePort(ctx, tx, service, pool, public, now)
	if err != nil {
		return err
	}
	if err = reconcileServiceEndpoint(ctx, tx, serviceEndpoint{ServiceID: service, DeploymentID: deployment, DomainID: domain, Hostname: hostname, Namespace: namespace, PoolID: pool, Public: public, Automation: automation}, now); err != nil {
		return err
	}
	if err = bindServicePort(ctx, tx, service, port, public); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.services SET
	    certificate_hostname=$2,certificate_scope=$3,domain_id=$4,ingress_pool_id=$5,name_scope=$6 WHERE id=$1`, service, hostname, namespace, domain, pool, deployment)
	return projectConstraintError(err)
}

// ingress reservations are not target trust or connector authority. changing
// one advances the endpoint revision without closing a run or its connectors.
// callers hold the service row lock before entering this operation.
func bindServicePort(ctx context.Context, tx pgx.Tx, service string, port int, public bool) error {
	_, err := tx.Exec(ctx, `UPDATE control.services SET service_port=$2,public=$3 WHERE id=$1`, service, port, public)
	return projectConstraintError(err)
}

func allocateServicePort(ctx context.Context, tx pgx.Tx, service, pool string, public bool, now time.Time) (int, error) {
	var protocol string
	if err := tx.QueryRow(ctx, `SELECT protocol FROM control.services WHERE id=$1`, service).Scan(&protocol); err != nil {
		return 0, err
	}
	if protocol == "http" {
		// HTTP shares the ingress listener by exact hostname. this logical port
		// stays fixed for connector identity and never creates a port claim.
		return 443, nil
	}
	var port int
	err := tx.QueryRow(ctx, `SELECT port FROM control.service_port_claims WHERE service_id=$1 AND state='held'`, service).Scan(&port)
	if errors.Is(err, pgx.ErrNoRows) {
		// zero means no public binding. private service identity, certificates,
		// relay placement and connector authority do not consume ingress ports.
		// an existing reservation remains held during temporary disablement.
		if !public {
			return 0, nil
		}
		// serialize allocation within one public address pool, then reserve under
		// a unique constraint. local connectors select their own SQLite ports.
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('managed-ports/'||$1,0))`, pool); err != nil {
			return 0, err
		}
		err = tx.QueryRow(ctx, `INSERT INTO control.service_port_claims(service_id,ingress_pool_id,port,claimed_at)
		    SELECT $1,$2,candidate,$3 FROM control.ingress_service_port_ranges inventory CROSS JOIN LATERAL generate_series(inventory.first_port,inventory.last_port) candidate
		    WHERE inventory.ingress_pool_id=$2
		    AND NOT EXISTS(SELECT 1 FROM control.service_port_claims held WHERE held.ingress_pool_id=$2 AND held.port=candidate AND held.state<>'released')
		    ORDER BY md5($1||'/'||candidate::text) LIMIT 1 RETURNING port`, service, pool, now).Scan(&port)
	}
	if err != nil {
		return 0, publisherLookupError(err, ErrServicePortsExhausted)
	}
	return port, nil
}
