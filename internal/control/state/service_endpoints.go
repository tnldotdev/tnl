package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func deploymentServicePlacement(s ProjectServiceConfiguration) ServicePlacement {
	return ServicePlacement{DomainID: s.DomainID, Hostname: s.Hostname, RunAliasParent: s.RunAliasParent, CertificateScope: s.CertificateScope}
}

// endpoint identity is durable across runs, publisher replicas and deployment-key
// renames. deployment moves never silently broaden certificate authority.
func (d *Database) ensureServiceEndpoint(ctx context.Context, tx pgx.Tx, service, deployment, actor string, placement ServicePlacement, public, automation bool, now time.Time) error {
	if err := placement.Validate(); err != nil || placement.WorktreeKey != "" || placement.WorktreeLabel != "" {
		return errors.Join(ErrProjectConfigurationInvalid, err)
	}
	var namespace, domain, pool, name, hostname, team string
	err := tx.QueryRow(ctx, `SELECT g.namespace,g.domain_id,t.ingress_pool_id,s.name,s.certificate_hostname,s.team_id FROM control.deployments g JOIN control.teams t ON t.id=g.team_id JOIN control.services s ON s.id=$1 AND s.team_id=g.team_id WHERE g.id=$2 AND g.deleted_at IS NULL FOR UPDATE OF s`, service, deployment).Scan(&namespace, &domain, &pool, &name, &hostname, &team)
	if err != nil {
		return err
	}
	if placement.DomainID != "" {
		domain = placement.DomainID
	}
	// a desired deployment move changes the endpoint, not the service's identity or
	// visitor grants. the apply transaction has already revoked old publishers.
	hostname = name + "." + namespace
	certificateScope := namespace
	if placement.Hostname != "" {
		hostname = placement.Hostname
		facts, err := serviceHostnameAuthority(ctx, tx, team, actor, domain, now)
		if err != nil {
			return err
		}
		labels, err := controlstatedb.New(tx).ListTeamNamespaceLabels(ctx, team)
		if err != nil {
			return err
		}
		if facts.deploymentBranch(d.managedURLMode, hostname) {
			if hostname == namespace || !hostnameWithin(hostname, namespace) {
				return ErrServiceConflict
			}
		} else {
			if err := authorizeServiceHostname(facts, labels, team, "", hostname, "shared", d.managedURLMode); err != nil {
				return err
			}
		}
		certificateScope = hostname
		if scope := placement.CertificateScope; scope != "" {
			if !public || facts.DomainKind != "custom" || scope == facts.CanonicalDomain ||
				!hostnameWithin(scope, facts.CanonicalDomain) ||
				!config.ValidPublisherCertificateScope(hostname, placement.RunAliasParent, scope) {
				return ErrProjectConfigurationInvalid
			}
			if err := claimDeploymentCertificateScope(ctx, tx, deployment, domain, scope, now); err != nil {
				return err
			}
			certificateScope = scope
		}
		var conflict bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_namespace_claims
		    WHERE ($1=namespace OR right($1,length(namespace)+1)='.'||namespace)
		    AND deployment_id IS DISTINCT FROM $2::text
		    AND (retired_at IS NULL OR NOT control.service_namespace_reusable(namespace,$3)))`,
			hostname, deployment, now).Scan(&conflict); err != nil {
			return err
		}
		if conflict {
			return ErrServiceConflict
		}
		var claim string
		if err := tx.QueryRow(ctx, `INSERT INTO control.service_namespace_claims(namespace,deployment_id,domain_id,created_at)
		    VALUES($1,$2,$3,$4) ON CONFLICT(namespace) DO UPDATE SET
		      deployment_id=EXCLUDED.deployment_id,domain_id=EXCLUDED.domain_id,
		      created_at=CASE WHEN control.service_namespace_claims.retired_at IS NULL
		        THEN control.service_namespace_claims.created_at ELSE EXCLUDED.created_at END,
		      local_source_key='',membership_id=NULL,owner_team_id=NULL,retired_at=NULL,reusable_after=NULL
		    WHERE (control.service_namespace_claims.deployment_id=EXCLUDED.deployment_id
		      AND control.service_namespace_claims.domain_id=EXCLUDED.domain_id
		      AND control.service_namespace_claims.retired_at IS NULL)
		      OR control.service_namespace_reusable(control.service_namespace_claims.namespace,$4)
		    RETURNING namespace`,
			hostname, deployment, domain, now).Scan(&claim); err != nil {
			return publisherLookupError(err, ErrServiceConflict)
		}
		namespace = hostname
	} else {
		selected, err := controlstatedb.New(tx).GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: domain, TeamID: text(team)})
		if err != nil {
			return publisherLookupError(err, ErrServiceAccess)
		}
		if !hostnameWithin(namespace, selected.CanonicalDomain) {
			return ErrProjectConfigurationInvalid
		}
	}
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
	    certificate_hostname=$2,certificate_scope=$3,domain_id=$4,ingress_pool_id=$5,name_scope=$6 WHERE id=$1`, service, hostname, certificateScope, domain, pool, deployment)
	if err != nil {
		return projectConstraintError(err)
	}
	return d.configureServiceRunAliasParent(ctx, tx, service, actor, placement.RunAliasParent, now)
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
		// inventory changes wait for allocations, while different allocations
		// compete only on the unique port they actually choose.
		if _, err = tx.Exec(ctx, `SELECT id FROM control.ingress_pools WHERE id=$1 FOR SHARE`, pool); err != nil {
			return 0, err
		}
		for {
			var selected pgtype.Int4
			var available bool
			err = tx.QueryRow(ctx, `WITH candidate AS MATERIALIZED (
			    SELECT candidate AS port FROM control.ingress_service_port_ranges inventory
			    CROSS JOIN LATERAL generate_series(inventory.first_port,inventory.last_port) candidate
			    WHERE inventory.ingress_pool_id=$2
			    AND NOT EXISTS(SELECT 1 FROM control.service_port_claims held WHERE held.ingress_pool_id=$2 AND held.port=candidate AND held.state<>'released')
			    ORDER BY md5($1||'/'||candidate::text) LIMIT 1
			), claimed AS (
			    INSERT INTO control.service_port_claims(service_id,ingress_pool_id,port,claimed_at)
			    SELECT $1,$2,port,$3 FROM candidate ON CONFLICT DO NOTHING RETURNING port
			) SELECT (SELECT port FROM claimed),EXISTS(SELECT 1 FROM candidate)`, service, pool, now).Scan(&selected, &available)
			if err != nil {
				return 0, err
			}
			if selected.Valid {
				return int(selected.Int32), nil
			}
			if !available {
				return 0, ErrServicePortsExhausted
			}
			// a concurrent claim won this candidate. a new statement sees its
			// committed reservation and selects another port.
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
	}
	if err != nil {
		return 0, publisherLookupError(err, ErrServicePortsExhausted)
	}
	return port, nil
}
