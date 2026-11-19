package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

// callers hold the service and its ownership guard. approving a parent changes
// endpoint authority, never target trust or the captured connector identity.
func (d *Database) configureServiceRunAliasParent(ctx context.Context, tx pgx.Tx, service, actor, parent string, now time.Time) error {
	row, err := controlstatedb.New(tx).LockService(ctx, service)
	if err != nil {
		return err
	}
	if parent != "" {
		if !naming.ValidGeneratedHostnameParent(parent) || row.Protocol != "http" || !row.DomainID.Valid || row.GuestID.Valid {
			return ErrProjectConfigurationInvalid
		}
		facts, err := serviceHostnameAuthority(ctx, tx, row.TeamID.String, actor, row.DomainID.String, now)
		if err != nil {
			return err
		}
		if !hostnameWithin(parent, facts.CanonicalDomain) {
			return ErrServiceAccess
		}
		// a member-owned source cannot approve a parent above its namespace.
		// deployment endpoints use the existing administrator/shared authority.
		var deployment pgtype.Text
		if err := tx.QueryRow(ctx, `SELECT deployment_id FROM control.service_endpoints
		    WHERE service_id=$1 AND hostname=$2 AND retired_at IS NULL AND service_run_id IS NULL`,
			service, row.CertificateHostname).Scan(&deployment); err != nil {
			return publisherLookupError(err, ErrServiceAccess)
		}
		probe := "p-aaaaaaaaaaaaaaaaaaaaaaaaaa." + parent
		if deployment.Valid {
			labels, err := controlstatedb.New(tx).ListTeamNamespaceLabels(ctx, row.TeamID.String)
			if err != nil {
				return err
			}
			if err := authorizeServiceHostname(facts, labels, row.TeamID.String, "", probe, "shared", d.managedURLMode); err != nil {
				return err
			}
		} else {
			owner, err := storedServiceSourceOwner(ctx, tx, row, false)
			if err != nil {
				return err
			}
			if err := d.authorizeOwnedServiceHostname(ctx, tx, facts, owner, row.TeamID.String, row.DomainID.String, probe, now); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE control.services SET run_alias_parent=$2 WHERE id=$1`, service, parent); err != nil {
		return projectConstraintError(err)
	}
	// old aliases retain their publisher binding during DNS quarantine.
	_, err = tx.Exec(ctx, `UPDATE control.service_endpoints endpoint SET retired_at=$2,
	    reusable_after=GREATEST($2::timestamptz+interval '7 days',COALESCE(run.certificate_expires_at,$2::timestamptz)),
	    dns_state=CASE WHEN endpoint.dns_state IN('unmanaged','removed') THEN 'removed' ELSE 'removing' END,
	    dns_available_at=CASE WHEN endpoint.dns_state IN('unmanaged','removed') THEN NULL ELSE $2 END,
	    dns_revision=endpoint.dns_revision+1,dns_work_owner=NULL,dns_work_expires_at=NULL
	    FROM control.service_runs run JOIN control.services current ON current.id=run.service_id
	    WHERE endpoint.service_id=$1 AND endpoint.service_run_id=run.id AND endpoint.retired_at IS NULL
	      AND (NOT current.public OR run.run_alias_parent<>current.run_alias_parent OR run.certificate_hostname<>current.certificate_hostname
	        OR run.certificate_domain_id IS DISTINCT FROM current.domain_id)`, service, now)
	if err != nil {
		return err
	}
	// restoring endpoint authority can restore the same publisher alias.
	_, err = tx.Exec(ctx, `UPDATE control.service_endpoints alias SET public=true,
	    retired_at=NULL,reusable_after=NULL,ingress_pool_id=canonical.ingress_pool_id,
	    dns_automation=canonical.dns_automation,dns_authority_reference=canonical.dns_authority_reference,
	    dns_state=CASE WHEN canonical.dns_automation THEN 'pending' ELSE 'unmanaged' END,
	    dns_available_at=CASE WHEN canonical.dns_automation THEN $2::timestamptz ELSE NULL END,
	    dns_revision=alias.dns_revision+1,dns_work_owner=NULL,dns_work_expires_at=NULL
	    FROM control.service_runs run JOIN control.services current ON current.id=run.service_id
	    JOIN control.service_endpoints canonical ON canonical.service_id=current.id
	      AND canonical.hostname=current.certificate_hostname AND canonical.domain_id=current.domain_id
	      AND canonical.service_run_id IS NULL AND canonical.retired_at IS NULL AND canonical.public
	    WHERE alias.service_id=$1 AND alias.service_run_id=run.id AND current.public
	      AND run.closed_at IS NULL AND run.publisher_expires_at>$2
	      AND run.run_alias_parent=current.run_alias_parent AND run.certificate_hostname=current.certificate_hostname
	      AND run.certificate_domain_id IS NOT DISTINCT FROM current.domain_id
	      AND (alias.retired_at IS NOT NULL OR NOT alias.public OR alias.ingress_pool_id<>canonical.ingress_pool_id)`, service, now)
	return err
}

// the service lock serializes allocation and replacement for each publisher.
func servicePublisherHostname(ctx context.Context, tx pgx.Tx, service controlstatedb.ControlService, publisher string) (string, error) {
	var hostname string
	err := tx.QueryRow(ctx, `SELECT hostname FROM control.service_endpoints
	    WHERE service_id=$1 AND publisher_identity_id=$2 AND publisher_alias_parent=$3`,
		service.ID, publisher, service.RunAliasParent).Scan(&hostname)
	if errors.Is(err, pgx.ErrNoRows) {
		return naming.RandomHostname(naming.PublisherHostnameKind, service.RunAliasParent)
	}
	return hostname, err
}

// the saved alias belongs to a publisher, but a serving snapshot must still
// name one current run. only fresh preparation can advance that pointer.
func bindServicePublisherAlias(ctx context.Context, tx pgx.Tx, service controlstatedb.ControlService, publisher, run, hostname string, now time.Time) error {
	if hostname == "" {
		return nil
	}
	rebound, err := tx.Exec(ctx, `UPDATE control.service_endpoints alias SET
	    service_run_id=$2, public=canonical.public, retired_at=NULL, reusable_after=NULL,
	    ingress_pool_id=canonical.ingress_pool_id, dns_automation=canonical.dns_automation,
	    dns_authority_reference=canonical.dns_authority_reference,
	    dns_state=CASE WHEN NOT canonical.dns_automation THEN 'unmanaged'
	      WHEN alias.retired_at IS NULL AND alias.ingress_pool_id=canonical.ingress_pool_id
	        AND alias.dns_authority_reference IS NOT DISTINCT FROM canonical.dns_authority_reference
	        AND alias.dns_state='published' THEN 'published' ELSE 'pending' END,
	    dns_available_at=CASE WHEN NOT canonical.dns_automation OR
	      alias.retired_at IS NULL AND alias.ingress_pool_id=canonical.ingress_pool_id
	        AND alias.dns_authority_reference IS NOT DISTINCT FROM canonical.dns_authority_reference
	        AND alias.dns_state='published' THEN NULL ELSE $6::timestamptz END,
	    dns_revision=alias.dns_revision+1,dns_work_owner=NULL,dns_work_expires_at=NULL
	    FROM control.service_endpoints canonical, control.service_runs previous, control.service_runs next
	    WHERE alias.hostname=$3 AND alias.service_id=$1 AND alias.publisher_identity_id=$4 AND alias.publisher_alias_parent=$5
	      AND canonical.service_id=alias.service_id AND canonical.domain_id=alias.domain_id
	      AND canonical.hostname=$7 AND canonical.service_run_id IS NULL AND canonical.retired_at IS NULL AND canonical.public
	      AND previous.id=alias.service_run_id AND next.id=$2 AND previous.run_number<next.run_number`,
		service.ID, run, hostname, publisher, service.RunAliasParent, now, service.CertificateHostname)
	if err != nil || rebound.RowsAffected() != 0 {
		return err
	}
	var reserved string
	// reserve the exact namespace too, so a later endpoint or member namespace
	// cannot claim the alias while its run or certificate is still retained.
	err = tx.QueryRow(ctx, `INSERT INTO control.service_namespace_claims
	    (namespace,deployment_id,local_source_key,domain_id,membership_id,owner_team_id,created_at)
	    SELECT $3,claim.deployment_id,claim.local_source_key,claim.domain_id,claim.membership_id,claim.owner_team_id,$4
	    FROM control.service_endpoints endpoint JOIN control.service_namespace_claims claim
	      ON claim.namespace=endpoint.namespace AND claim.domain_id=endpoint.domain_id AND claim.retired_at IS NULL
	    WHERE endpoint.service_id=$1 AND endpoint.hostname=$2 AND endpoint.retired_at IS NULL AND endpoint.service_run_id IS NULL
	      AND NOT EXISTS(SELECT 1 FROM control.service_namespace_claims other
	        WHERE ($3=other.namespace OR right($3,length(other.namespace)+1)='.'||other.namespace
	          OR right(other.namespace,length($3)+1)='.'||$3)
	        AND (other.domain_id<>claim.domain_id OR other.deployment_id IS DISTINCT FROM claim.deployment_id
	          OR other.local_source_key<>claim.local_source_key OR other.membership_id IS DISTINCT FROM claim.membership_id
	          OR other.owner_team_id IS DISTINCT FROM claim.owner_team_id))
	    ON CONFLICT(namespace) DO NOTHING RETURNING namespace`, service.ID, service.CertificateHostname, hostname, now).Scan(&reserved)
	if err != nil {
		return projectConstraintError(publisherLookupError(err, ErrServiceConflict))
	}
	err = tx.QueryRow(ctx, `INSERT INTO control.service_endpoints
	    (hostname,service_id,service_run_id,publisher_identity_id,publisher_alias_parent,deployment_id,local_source_key,domain_id,namespace,ingress_pool_id,
	     public,dns_automation,dns_authority_reference,dns_state,dns_available_at,created_at)
	    SELECT $3,endpoint.service_id,$2,$7,$8,endpoint.deployment_id,endpoint.local_source_key,endpoint.domain_id,
	      $3,endpoint.ingress_pool_id,endpoint.public,endpoint.dns_automation,endpoint.dns_authority_reference,
	      CASE WHEN endpoint.public AND endpoint.dns_automation THEN 'pending' ELSE 'unmanaged' END,
	      CASE WHEN endpoint.public AND endpoint.dns_automation THEN $4::timestamptz ELSE NULL END,$4
	    FROM control.service_endpoints endpoint
	    WHERE endpoint.service_id=$1 AND endpoint.hostname=$5 AND endpoint.domain_id=$6 AND endpoint.retired_at IS NULL
	      AND endpoint.service_run_id IS NULL
	      AND NOT EXISTS(SELECT 1 FROM control.service_namespace_claims claim
	        WHERE ($3=claim.namespace OR right($3,length(claim.namespace)+1)='.'||claim.namespace)
	          AND (claim.domain_id<>endpoint.domain_id OR claim.deployment_id IS DISTINCT FROM endpoint.deployment_id
	            OR claim.local_source_key<>endpoint.local_source_key))
	      AND NOT EXISTS(SELECT 1 FROM control.services other WHERE other.certificate_hostname=$3 AND other.deleted_at IS NULL)
	    ON CONFLICT(hostname) DO NOTHING RETURNING hostname`,
		service.ID, run, hostname, now, service.CertificateHostname, service.DomainID, publisher, service.RunAliasParent).Scan(&reserved)
	return projectConstraintError(publisherLookupError(err, ErrServiceConflict))
}
