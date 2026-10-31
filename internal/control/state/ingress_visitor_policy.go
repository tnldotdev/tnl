package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// ingress preparation reads the same policy as publishers, authenticated by its
// current process lease and exact run. this is never a visitor admission RPC.
func (d *Database) ReadIngressVisitorPolicy(ctx context.Context, identity IngressLeaseIdentity, scope visitorscope.Scope, run string, number, policyRevision, after int64, now time.Time) (result controlv1.VisitorPolicyUpdate, retErr error) {
	if scope.Kind != visitorscope.PublicURL || !scope.Valid() || !validStateText(run) || number < 1 || policyRevision < 1 || after < 0 {
		return result, ErrVisitorPolicy
	}
	if err := validateIngressLeaseIdentity(identity); err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read ingress visitor policy", &retErr)()
	// preparation changes no lease state. a policy read must not serialize every
	// run behind one ingress-row lock or block process renewal.
	owner, err := controlstatedb.New(tx).GetIngressLease(ctx, controlstatedb.GetIngressLeaseParams{
		IngressID: identity.IngressID, IngressRunID: identity.IngressRunID,
		IngressLeaseRevision: int64(identity.IngressLeaseRevision), Now: timestamptz(now),
	})
	if err != nil {
		return result, publisherLookupError(err, ErrIngressLeaseStale)
	}
	if owner.Draining {
		return result, ErrIngressLeaseStale
	}
	var current bool
	err = tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM control.publish_runs AS run JOIN control.public_urls AS url ON url.id=run.public_url_id
		WHERE run.id=$1 AND run.public_url_id=$2 AND run.publish_run_number=$3
		  AND run.closed_at IS NULL AND run.publisher_expires_at>$4 AND run.state IN ('starting','ready')
		  AND url.ingress_pool_id=$5 AND url.policy_revision=$6
	)`, run, scope.ID, number, now, owner.IngressPoolID, policyRevision).Scan(&current)
	if err != nil {
		return result, err
	}
	if !current {
		return result, ErrVisitorPolicy
	}
	result, err = d.readVisitorPolicy(ctx, tx, scope, after, now)
	if err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).GetPublishRun(ctx, run)
	if err != nil {
		return result, err
	}
	master, err := visitortoken.PublicVisitorSourceKey(row.PublishRunTokenDigest, run, uint64(number))
	if err != nil {
		return result, err
	}
	until := result.Policy.ValidUntil
	if owner.LeaseExpiresAt.Time.Before(until) {
		until = owner.LeaseExpiresAt.Time
	}
	if row.PublisherExpiresAt.Time.Before(until) {
		until = row.PublisherExpiresAt.Time
	}
	authority, child, err := visitortoken.IssueVisitorSourceAuthority(master, tunnelv1.VisitorSourceAuthority{
		PublicURLID: scope.ID, PublishRunID: run, PublishRunNumber: uint64(number),
		IngressID: identity.IngressID, IngressRunID: identity.IngressRunID, IngressLeaseRevision: identity.IngressLeaseRevision,
		VisitorPolicyRevision: result.Policy.VisitorPolicyRevision, ValidUntil: until.Unix(),
	}, now)
	if err != nil {
		return result, ErrVisitorPolicy
	}
	wire, err := authority.MarshalBinary()
	if err != nil {
		return result, ErrVisitorPolicy
	}
	key := child[:]
	result.VisitorSourceKey, result.VisitorSourceAuthority = &key, &wire
	return result, tx.Commit(ctx)
}
