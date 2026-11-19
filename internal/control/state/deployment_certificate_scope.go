package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// the team mutation lock and exclusive custom-domain ownership serialize scope
// claims with other saved placements. reserve both directions of overlap so a
// wildcard cannot cover another owner's live or quarantined hostname.
func claimDeploymentCertificateScope(ctx context.Context, tx pgx.Tx, deployment, domain, scope string, now time.Time) error {
	var conflict bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_namespace_claims claim
	    WHERE (claim.namespace=$1 OR right(claim.namespace,length($1)+1)='.'||$1
	        OR right($1,length(claim.namespace)+1)='.'||claim.namespace)
	      AND (claim.deployment_id IS DISTINCT FROM $2::text OR claim.domain_id<>$3)
	      AND NOT control.service_namespace_reusable(claim.namespace,$4))`,
		scope, deployment, domain, now).Scan(&conflict); err != nil {
		return err
	}
	if conflict {
		return ErrServiceConflict
	}
	var claimed string
	err := tx.QueryRow(ctx, `INSERT INTO control.service_namespace_claims(namespace,deployment_id,domain_id,created_at)
	    VALUES($1,$2,$3,$4) ON CONFLICT(namespace) DO UPDATE SET
	      deployment_id=EXCLUDED.deployment_id,domain_id=EXCLUDED.domain_id,
	      created_at=CASE WHEN control.service_namespace_claims.retired_at IS NULL
	        THEN control.service_namespace_claims.created_at ELSE EXCLUDED.created_at END,
	      local_source_key='',membership_id=NULL,owner_team_id=NULL,retired_at=NULL,reusable_after=NULL
	    WHERE (control.service_namespace_claims.deployment_id=EXCLUDED.deployment_id
	      AND control.service_namespace_claims.domain_id=EXCLUDED.domain_id)
	      OR control.service_namespace_reusable(control.service_namespace_claims.namespace,$4)
	    RETURNING namespace`, scope, deployment, domain, now).Scan(&claimed)
	return publisherLookupError(err, ErrServiceConflict)
}
