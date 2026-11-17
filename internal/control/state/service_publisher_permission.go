package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// servicePublisherSelectionMatches validates the request's identity shape. only
// the database permission decision proves that its actual grant covers a service.
func servicePublisherSelectionMatches(p PublisherIdentity, service string) bool {
	return opaqueid.Valid(service, opaqueid.ServicePrefix) &&
		(p.Kind != "guest" || p.Scope.Kind == "service" && p.Scope.ServiceID == service && p.GuestID != "" && p.Scope.GuestID == p.GuestID && p.Scope.TeamID == "") &&
		(p.Scope.Kind == "service" && p.Scope.ServiceID == service || p.Scope.Kind == DeploymentCredentialGrant || p.Scope.Kind == "namespace") &&
		opaqueid.Valid(p.ID, opaqueid.PublisherIdentityPrefix) &&
		opaqueid.Valid(p.GrantID, opaqueid.PublisherGrantPrefix) &&
		opaqueid.Valid(p.KeyID, opaqueid.PublisherIdentityKeyPrefix)
}

// publisherServicePermission checks the stored grant without changing its kind.
// callers hold service admission and pass the current time after lock waits.
// exact grants retain their existing retired-key recovery rules; a registered
// credential and namespace allocator must still have their current signing key.
func publisherServicePermission(ctx context.Context, tx pgx.Tx, publisher, grant, key, service string, now time.Time) (pgtype.Timestamptz, error) {
	var until pgtype.Timestamptz
	err := tx.QueryRow(ctx, `SELECT permission.expires_at
		FROM control.publisher_service_permission($1,$2,$4,$5) permission
		JOIN control.publisher_grants grant_record ON grant_record.id=$2 AND grant_record.publisher_identity_id=$1
		JOIN control.publisher_identity_keys signing ON signing.id=$3 AND signing.publisher_identity_id=$1
		WHERE grant_record.kind='service' OR signing.retired_at IS NULL`,
		publisher, grant, key, service, now).Scan(&until)
	return until, publisherLookupError(err, ErrServiceAccess)
}

// serviceRunPublisherPermission checks the exact persisted publisher tuple. a
// run token or an earlier selection never replaces current service permission.
func serviceRunPublisherPermission(ctx context.Context, tx pgx.Tx, run controlstatedb.ControlServiceRun, now time.Time) (pgtype.Timestamptz, error) {
	clock := newAuthorizationClock(now)
	if run.GuestID.Valid {
		// guest callers already hold trial -> service -> run. identities and
		// grants are the final locks, never a way to acquire the trial later.
		q := controlstatedb.New(tx)
		identity, err := q.LockPublisherIdentity(ctx, run.PublisherIdentityID)
		if err != nil {
			return pgtype.Timestamptz{}, publisherLookupError(err, ErrServiceAccess)
		}
		grant, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{ID: run.PublisherGrantID, PublisherIdentityID: identity.ID})
		if err != nil {
			return pgtype.Timestamptz{}, publisherLookupError(err, ErrServiceAccess)
		}
		if identity.GuestID != run.GuestID || grant.GuestID != run.GuestID || grant.ServiceID.String != run.ServiceID ||
			identity.TeamID.Valid || grant.TeamID.Valid {
			return pgtype.Timestamptz{}, ErrServiceAccess
		}
	}
	now = clock.current()
	state := serviceRunLifecycleState(run.State)
	if run.ClosedAt.Valid || !run.ServingUntil.Time.After(now) ||
		!state.active() && state != serviceRunPrepared ||
		state == serviceRunPrepared && !run.PreparationExpiresAt.Time.After(now) {
		return pgtype.Timestamptz{}, ErrServiceAccess
	}
	return publisherServicePermission(ctx, tx, run.PublisherIdentityID, run.PublisherGrantID, run.PublisherKeyID, run.ServiceID, now)
}
