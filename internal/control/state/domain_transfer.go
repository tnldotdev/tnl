package state

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

type DomainTransfer struct {
	State, Domain, Source, Destination string
	Blockers                           []string
	ExpiresAt                          *time.Time
}

// TransferDomain moves verified DNS authority without moving service state or
// asking the DNS provider to release and recreate the zone.
func (d *Database) TransferDomain(ctx context.Context, actor, domain, destination string, accept bool, now time.Time) (result DomainTransfer, retErr error) {
	if canonical, err := naming.CanonicalizeHostname(domain); err != nil || canonical != domain ||
		!validStateText(actor) || !validStateText(destination) || now.IsZero() {
		return result, ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "transfer team domain", &retErr)()
	q := controlstatedb.New(tx)
	var id, source string
	// look up only a domain the requester can act on. then lock both teams
	// in stable order before locking/rechecking the domain and its offer.
	err = tx.QueryRow(ctx, `SELECT d.id,d.team_id FROM control.domains d
	    JOIN control.team_memberships m ON m.identity_id=$3 AND m.role='owner'
	    WHERE d.canonical_domain=$1 AND d.kind='custom' AND d.released_at IS NULL
	      AND (NOT $5 AND m.team_id=d.team_id OR $5 AND m.team_id=$2
	        AND EXISTS(SELECT 1 FROM control.domain_transfer_offers o
	          WHERE o.domain_id=d.id AND o.destination_team_id=$2))
	      AND control.active_membership(m.id,$4)`, domain, destination, actor, now, accept).Scan(&id, &source)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrDomainNotFound
	}
	if err != nil {
		return result, err
	}
	if source == destination {
		return result, ErrAuthorityInvalid
	}
	teams := []string{source, destination}
	slices.Sort(teams)
	for _, team := range teams {
		if _, err := q.LockLocalTeamForMutation(ctx, team); err != nil {
			return result, publisherLookupError(err, ErrTeamNotFound)
		}
	}
	authorityTeam := source
	if accept {
		authorityTeam = destination
	}
	membership, err := lockTeamActor(ctx, q, actor, authorityTeam)
	if err != nil {
		return result, err
	}
	if membership.ActorRole != string(TeamRoleOwner) {
		return result, ErrAuthorityAccess
	}
	locked, err := q.LockTeamDomain(ctx, controlstatedb.LockTeamDomainParams{DomainID: id, TeamID: text(source)})
	if err != nil {
		return result, publisherLookupError(err, ErrDomainNotFound)
	}
	if locked.TeamID.String != source || locked.State != "ready" || !locked.DnsAuthorityReference.Valid {
		return result, ErrAuthorityConflict
	}
	checkActor := actor
	if accept {
		var sessionID string
		err := tx.QueryRow(ctx, `SELECT o.offered_by,o.offered_session_id FROM control.domain_transfer_offers o
		    JOIN control.team_memberships m ON m.team_id=o.source_team_id AND m.identity_id=o.offered_by
		    JOIN control.identities i ON i.id=o.offered_by AND i.disabled_at IS NULL
		    WHERE o.domain_id=$1 AND o.source_team_id=$2 AND o.destination_team_id=$3
		      AND o.authority_revision=$4 AND o.expires_at>$5
		      AND m.role='owner' AND control.active_membership(m.id,$5)`,
			id, source, destination, locked.AuthorityRevision, now).Scan(&checkActor, &sessionID)
		if err != nil {
			return result, publisherLookupError(err, ErrDomainNotFound)
		}
		offerCtx := WithControlPrincipal(ctx, ControlPrincipal{IdentityID: checkActor, SessionID: sessionID})
		if err := requireTeamSession(offerCtx, q, source, checkActor, now); err != nil {
			return result, err
		}
	}
	result = DomainTransfer{Domain: domain, Source: source, Destination: destination}
	blockers, err := domainTransferBlockers(ctx, tx, q, checkActor, source, id, now)
	if err != nil {
		return result, err
	}
	if len(blockers) != 0 {
		result.State, result.Blockers = "blocked", blockers
		if accept {
			result.Blockers = []string{"the source team must clear this domain before transfer"}
		}
		return result, tx.Commit(ctx)
	}
	if !accept {
		target, err := lockTeamActor(ctx, q, actor, destination)
		if err != nil && !errors.Is(err, ErrTeamNotFound) && !errors.Is(err, ErrAuthorityAccess) {
			return result, err
		}
		if err != nil || target.ActorRole != string(TeamRoleOwner) {
			expires := now.Add(7 * 24 * time.Hour)
			_, err = tx.Exec(ctx, `INSERT INTO control.domain_transfer_offers
			    (domain_id,source_team_id,destination_team_id,offered_by,offered_session_id,authority_revision,expires_at)
			    VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(domain_id) DO UPDATE SET
			      source_team_id=EXCLUDED.source_team_id,destination_team_id=EXCLUDED.destination_team_id,
			      offered_by=EXCLUDED.offered_by,offered_session_id=EXCLUDED.offered_session_id,
			      authority_revision=EXCLUDED.authority_revision,expires_at=EXCLUDED.expires_at`,
				id, source, destination, actor, companySessionID(ctx, actor), locked.AuthorityRevision, expires)
			if err != nil {
				return result, err
			}
			result.State, result.ExpiresAt = "offered", &expires
			return result, tx.Commit(ctx)
		}
	}
	// switch the source default in the same transaction. never change the
	// destination's default or reuse the source team's claim idempotency key.
	if _, err = tx.Exec(ctx, `UPDATE control.teams SET default_domain_id=(
	    SELECT id FROM control.domains WHERE kind='managed' AND state='ready' AND released_at IS NULL)
	    WHERE id=$1 AND default_domain_id=$2`, source, id); err != nil {
		return result, err
	}
	for _, team := range teams {
		if _, err = q.AdvanceTeamPolicyRevision(ctx, controlstatedb.AdvanceTeamPolicyRevisionParams{
			TeamID: team, UpdatedAt: timestamp(now),
		}); err != nil {
			return result, err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE control.dns_authorities SET team_id=$3,updated_at=$4
	    WHERE authority_reference=$1 AND domain_id=$2 AND state='ready' AND work_owner IS NULL AND team_id=$5`,
		locked.DnsAuthorityReference.String, id, destination, now, source)
	if err != nil {
		return result, err
	}
	if tag.RowsAffected() != 1 {
		return result, ErrAuthorityConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE control.domains SET team_id=$2,authority_revision=authority_revision+1,
	    claim_idempotency_key=NULL,claim_request_digest=NULL,make_default_when_ready=false,updated_at=$3
	    WHERE id=$1`, id, destination, now); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM control.domain_transfer_offers WHERE domain_id=$1`, id); err != nil {
		return result, err
	}
	result.State = "transferred"
	return result, tx.Commit(ctx)
}

func domainTransferBlockers(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, actor, source, domain string, now time.Time) ([]string, error) {
	facts, err := q.GetIdentityTeamDomainRelease(ctx, controlstatedb.GetIdentityTeamDomainReleaseParams{
		DomainID: domain, TeamID: text(source), IdentityID: actor, ObservedAt: timestamp(now),
	})
	if err != nil {
		return nil, publisherLookupError(err, ErrAuthorityAccess)
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT blocker FROM (
	    SELECT 'service: '||certificate_hostname AS blocker FROM control.services
	      WHERE domain_id=$1 AND deleted_at IS NULL
	    UNION ALL SELECT 'deployment: '||namespace FROM control.deployments
	      WHERE domain_id=$1 AND deleted_at IS NULL
	    UNION ALL SELECT 'endpoint: '||hostname FROM control.service_endpoints
	      WHERE domain_id=$1 AND (retired_at IS NULL OR dns_state NOT IN ('unmanaged','removed'))
	    UNION ALL SELECT 'wildcard DNS: *.'||parent FROM control.publisher_alias_wildcards WHERE domain_id=$1
	    UNION ALL SELECT 'publisher grant: '||namespace FROM control.publisher_grants
	      WHERE domain_id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>$2)
	    UNION ALL SELECT 'publisher enrollment: '||namespace FROM control.publisher_enrollments
	      WHERE domain_id=$1 AND redeemed_at IS NULL AND expires_at>$2
	    UNION ALL SELECT 'certificate: '||array_to_string(certificate_identifiers, ', ') FROM control.acme_orders
	      WHERE certificate_domain_id=$1 AND not_after>$2
	    ) current WHERE blocker IS NOT NULL ORDER BY blocker LIMIT 20`, domain, now)
	if err != nil {
		return nil, err
	}
	blockers, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, blocker := range facts.ReleaseBlockers {
		if blocker != "dns_authority" {
			blockers = append(blockers, blocker)
		}
	}
	return blockers, nil
}
