package state

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
)

const PublisherAliasWildcardLifetime = 2 * time.Minute

// the caller holds the service and team guards. a different pool or trust
// boundary cannot take over a parent while its old DNS ownership remains.
func queuePublisherAliasWildcard(ctx context.Context, tx pgx.Tx, service, parent string, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO control.publisher_alias_wildcards
	    (parent,team_id,domain_id,domain_revision,ingress_pool_id,available_at)
	    SELECT parent,team_id,domain_id,domain_revision,ingress_pool_id,$3
	    FROM control.publisher_alias_wildcard_facts WHERE service_id=$1 AND parent=$2
	    ON CONFLICT(parent) DO NOTHING`, service, parent, now)
	return err
}

var ErrPublisherAliasWildcardBinding = errors.New("controlstate: publisher alias wildcard has no compatible DNS authority and ingress pool")

func requirePublisherAliasWildcardBinding(ctx context.Context, tx pgx.Tx, service, parent string, now time.Time) error {
	if err := queuePublisherAliasWildcard(ctx, tx, service, parent, now); err != nil {
		return err
	}
	var bound bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
	    SELECT 1 FROM control.publisher_alias_wildcard_facts facts
	    JOIN control.publisher_alias_wildcards work
	      USING (parent,team_id,domain_id,domain_revision,ingress_pool_id)
	    JOIN control.ingress_pools pool ON pool.id=facts.ingress_pool_id
	    JOIN control.dns_authorities authority ON authority.authority_reference=facts.dns_authority_reference
	    WHERE facts.service_id=$1 AND facts.parent=$2 AND pool.state IN ('enabled','draining')
	      AND num_nonnulls(pool.ipv4_address,pool.ipv6_address)>0
	      AND (work.zone_id='' OR work.zone_id=authority.provider_zone_id))`, service, parent).Scan(&bound)
	if err == nil && !bound {
		return ErrPublisherAliasWildcardBinding
	}
	return err
}

type PublisherAliasWildcardWork struct {
	Parent, TeamID, DomainID, PoolID, ZoneID, Domain, AuthorityReference string
	IPv4, IPv6                                                           *netip.Addr
	Worker                                                               string
	Epoch, ConsecutiveErrors                                             int64
	Removing, PoolUsable                                                 bool
}

var ErrPublisherAliasWildcardStale = errors.New("controlstate: publisher alias wildcard work lease is stale")

type PublisherAliasWildcardObservation uint8

const (
	PublisherAliasWildcardInconclusive PublisherAliasWildcardObservation = iota
	PublisherAliasWildcardWithdrawn
	PublisherAliasWildcardVerified
	PublisherAliasWildcardRemoved
)

func (d *Database) ClaimPublisherAliasWildcard(ctx context.Context, worker string, now time.Time, lease time.Duration) (work PublisherAliasWildcardWork, found bool, err error) {
	err = d.pool.QueryRow(ctx, `WITH candidate AS (
	    SELECT parent FROM control.publisher_alias_wildcards
	    WHERE available_at<=$1 AND (work_owner IS NULL OR work_expires_at<=$1)
	    ORDER BY available_at,parent FOR UPDATE SKIP LOCKED LIMIT 1
	), claimed AS (
	    UPDATE control.publisher_alias_wildcards work
	    SET work_owner=$2,work_epoch=work_epoch+1,work_expires_at=$3
	    FROM candidate WHERE work.parent=candidate.parent RETURNING work.*
	)
	SELECT work.parent,work.team_id,work.domain_id,work.ingress_pool_id,work.zone_id,
	    domain.canonical_domain,COALESCE(domain.dns_authority_reference,''),pool.ipv4_address,pool.ipv6_address,
	    work.work_owner,work.work_epoch,work.consecutive_errors,
	    NOT EXISTS (SELECT 1 FROM control.publisher_alias_wildcard_facts facts
	        WHERE (facts.parent,facts.team_id,facts.domain_id,facts.domain_revision,facts.ingress_pool_id)
	          =(work.parent,work.team_id,work.domain_id,work.domain_revision,work.ingress_pool_id)),
	    pool.state IN ('enabled','draining')
	FROM claimed work JOIN control.domains domain ON domain.id=work.domain_id
	JOIN control.ingress_pools pool ON pool.id=work.ingress_pool_id`, now, worker, now.Add(lease)).
		Scan(&work.Parent, &work.TeamID, &work.DomainID, &work.PoolID, &work.ZoneID, &work.Domain, &work.AuthorityReference,
			&work.IPv4, &work.IPv6, &work.Worker, &work.Epoch, &work.ConsecutiveErrors, &work.Removing, &work.PoolUsable)
	if errors.Is(err, pgx.ErrNoRows) {
		return work, false, nil
	}
	return work, err == nil, err
}

// pin provider identity before any external write. never use a later
// process's configured zone as proof of the original zone's retirement.
func (d *Database) PinPublisherAliasWildcardZone(ctx context.Context, work PublisherAliasWildcardWork, zone string, now time.Time) error {
	tag, err := d.pool.Exec(ctx, `UPDATE control.publisher_alias_wildcards work SET zone_id=$4
	    WHERE parent=$1 AND work_owner=$2 AND work_epoch=$3 AND work_expires_at>$5
	      AND (zone_id='' OR zone_id=$4)
	      AND $6 = NOT EXISTS (SELECT 1 FROM control.publisher_alias_wildcard_facts facts
	        WHERE (facts.parent,facts.team_id,facts.domain_id,facts.domain_revision,facts.ingress_pool_id)
	          =(work.parent,work.team_id,work.domain_id,work.domain_revision,work.ingress_pool_id))
	      AND ($6 OR EXISTS (SELECT 1 FROM control.ingress_pools pool WHERE pool.id=work.ingress_pool_id
	        AND pool.state IN ('enabled','draining') AND pool.ipv4_address IS NOT DISTINCT FROM $7::inet
	        AND pool.ipv6_address IS NOT DISTINCT FROM $8::inet))`,
		work.Parent, work.Worker, work.Epoch, zone, now, work.Removing, work.IPv4, work.IPv6)
	if err == nil && tag.RowsAffected() != 1 {
		err = ErrPublisherAliasWildcardStale
	}
	return err
}

func (d *Database) SavePublisherAliasWildcard(ctx context.Context, work PublisherAliasWildcardWork, shadowed []string,
	observation PublisherAliasWildcardObservation, failures int64, now, next time.Time,
) (retErr error) {
	if observation == PublisherAliasWildcardRemoved {
		// the delete and potential reassignment are atomic under the parent key.
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer rollback(ctx, tx, "settle publisher alias wildcard", &retErr)()
		tag, err := tx.Exec(ctx, `DELETE FROM control.publisher_alias_wildcards
		    WHERE parent=$1 AND work_owner=$2 AND work_epoch=$3 AND work_expires_at>$4`, work.Parent, work.Worker, work.Epoch, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrPublisherAliasWildcardStale
		}
		_, err = tx.Exec(ctx, `INSERT INTO control.publisher_alias_wildcards
		    (parent,team_id,domain_id,domain_revision,ingress_pool_id,available_at)
		    SELECT DISTINCT parent,team_id,domain_id,domain_revision,ingress_pool_id,$2::timestamptz
		    FROM control.publisher_alias_wildcard_facts WHERE parent=$1
		    ON CONFLICT(parent) DO NOTHING`, work.Parent, now)
		if err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	// a failed refresh never moves the deadline or substitutes new addresses.
	// it can add observed shadows, but only a full verification can clear them.
	tag, err := d.pool.Exec(ctx, `WITH current AS (
	    SELECT work.parent, $11::bool AND EXISTS (
	      SELECT 1 FROM control.publisher_alias_wildcard_facts facts
	      JOIN control.ingress_pools pool ON pool.id=facts.ingress_pool_id
	      JOIN control.dns_authorities authority ON authority.authority_reference=facts.dns_authority_reference
	      WHERE (facts.parent,facts.team_id,facts.domain_id,facts.domain_revision,facts.ingress_pool_id)
	            =(work.parent,work.team_id,work.domain_id,work.domain_revision,work.ingress_pool_id)
	        AND authority.authority_reference=$12 AND authority.provider_zone_id=work.zone_id
	        AND pool.state IN ('enabled','draining') AND num_nonnulls(pool.ipv4_address,pool.ipv6_address)>0
	        AND pool.ipv4_address IS NOT DISTINCT FROM $5::inet AND pool.ipv6_address IS NOT DISTINCT FROM $6::inet
	    ) AS matches
	    FROM control.publisher_alias_wildcards work WHERE work.parent=$1
	), result AS (
	    SELECT work.parent, current.matches AND $13::bool AS verified,
	        current.matches AND $14::bool AND work.verified_until>$10
	            AND work.ipv4_address IS NOT DISTINCT FROM $5::inet
	            AND work.ipv6_address IS NOT DISTINCT FROM $6::inet AS retain
	    FROM control.publisher_alias_wildcards work JOIN current USING (parent)
	)
	UPDATE control.publisher_alias_wildcards work
	    SET verified_until=CASE WHEN result.verified THEN $4 WHEN result.retain THEN work.verified_until END,
	        ipv4_address=CASE WHEN result.verified THEN $5 WHEN result.retain THEN work.ipv4_address END,
	        ipv6_address=CASE WHEN result.verified THEN $6 WHEN result.retain THEN work.ipv6_address END,
	        shadowed_labels=CASE WHEN result.verified THEN COALESCE($7,'{}'::text[])
	            WHEN result.retain THEN ARRAY(SELECT DISTINCT label FROM unnest(work.shadowed_labels||COALESCE($7,'{}'::text[])) AS label ORDER BY label)
	            ELSE '{}'::text[] END,
	        available_at=$8,consecutive_errors=$9,work_owner=NULL,work_expires_at=NULL
	    FROM result
	    WHERE work.parent=result.parent AND work.work_owner=$2 AND work.work_epoch=$3 AND work.work_expires_at>$10`,
		work.Parent, work.Worker, work.Epoch, now.Add(PublisherAliasWildcardLifetime), work.IPv4, work.IPv6, shadowed, next, failures, now,
		!work.Removing, work.AuthorityReference, observation == PublisherAliasWildcardVerified, observation == PublisherAliasWildcardInconclusive)
	if err == nil && tag.RowsAffected() != 1 {
		err = ErrPublisherAliasWildcardStale
	}
	return err
}
