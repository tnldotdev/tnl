package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

// cleanup proves possession of the original native key, not current source
// permission. its only effect is deleting the exact persisted allocation tuple.
// source sessions remain until their allocations are deleted by this operation
// or the bounded ephemeral reaper; forgetting a session then means already gone.
func (d *Database) CleanupMachinePublication(ctx context.Context, session, invocation, assertion, audience string, now time.Time) (retErr error) {
	if !opaqueid.Valid(session, "mps_") || !opaqueid.Valid(invocation, opaqueid.InvocationPrefix) {
		return ErrMachineDenied
	}
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "clean up machine publication allocation", &retErr)()
	var team string
	if err = tx.QueryRow(ctx, `SELECT p.team_id FROM control.machine_publication_sessions s JOIN control.publisher_identities p ON p.id=s.publisher_identity_id WHERE s.id=$1`, session).Scan(&team); errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockMachinePublicationCleanupTeam(ctx, team); err != nil {
		return err
	}
	var publisher, key, grant, machine, kind, namespace, domain string
	var public []byte
	err = tx.QueryRow(ctx, `SELECT s.publisher_identity_id,s.key_id,s.grant_id,s.machine_id,g.kind,COALESCE(g.namespace,''),COALESCE(g.domain_id,''),k.public_key
		FROM control.machine_publication_sessions s
		JOIN control.publisher_grants g ON g.id=s.grant_id AND g.publisher_identity_id=s.publisher_identity_id
		JOIN control.publisher_identity_keys k ON k.id=s.key_id AND k.publisher_identity_id=s.publisher_identity_id
		WHERE s.id=$1`, session).Scan(&publisher, &key, &grant, &machine, &kind, &namespace, &domain, &public)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	if kind != "namespace" {
		return ErrMachineDenied
	}
	proof, err := publisherproof.Verify(assertion, publisher, key, machineproof.PublicationCleanup(session, invocation), audience, public, clock.current())
	if err != nil {
		return ErrMachineDenied
	}
	var id string
	err = tx.QueryRow(ctx, `SELECT public_url_id FROM control.publisher_namespace_allocations WHERE publisher_identity_id=$1 AND publisher_grant_id=$2 AND invocation_id=$3`, publisher, grant, invocation).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	u, err := q.LockPublicURLForRun(ctx, id)
	if err != nil {
		return publisherLookupError(err, ErrMachineDenied)
	}
	if !u.Ephemeral || u.Purpose != "app" || u.ServiceProtocol != "http" || u.TeamID != team || u.Namespace != namespace || u.DomainID != domain || u.CreatedByMachineID.String != machine {
		return ErrMachineDenied
	}
	if u.LifecycleState == "deleted" {
		return nil
	}
	if err = machinePublicationResource(ctx, tx, u.ID, u.CanonicalHostname, clock.current()); err != nil {
		return err
	}
	if err = rejectProjectManagedDefinition(ctx, tx, u.ID); err != nil {
		return err
	}
	if err = deleteLockedPublicURL(ctx, q, u, u.MutationRevision, publisherIssuer{MachineID: machine}, clock.current()); err != nil {
		return err
	}
	// cleanup assertions may be replayed only for the same idempotent removal;
	// they cannot survive their short signing deadline while waiting on a run.
	if !proof.Until.After(clock.current()) {
		return ErrMachineDenied
	}
	return tx.Commit(ctx)
}
