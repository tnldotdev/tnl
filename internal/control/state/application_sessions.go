package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// capture runs only while creating a new workload session under the team guard.
// retries and renewals never add newly approved application grants to a session.
func captureWorkloadApplication(ctx context.Context, tx pgx.Tx, session, team, project, name string, public []byte, services []string, now time.Time) error {
	var binding, application string
	err := tx.QueryRow(ctx, `SELECT binding.id,binding.publisher_identity_id
	    FROM control.workload_applications binding
	    WHERE binding.team_id=$1 AND binding.project_key=$2 AND binding.workload_name=$3 AND binding.revoked_at IS NULL
	    AND binding.created_at<=$4`, team, project, name, now).Scan(&binding, &application)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrWorkloadDenied
	}
	if err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	identity, err := q.LockPublisherIdentity(ctx, application)
	if err != nil {
		return err
	}
	var active bool
	if err = tx.QueryRow(ctx, `SELECT control.active_publisher($1,$2)`, application, now).Scan(&active); err != nil {
		return err
	}
	if identity.Kind != "application" || !active {
		return ErrWorkloadDenied
	}
	key, err := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	if err != nil {
		return err
	}
	revision, err := q.NextPublisherKeyRevision(ctx, application)
	if err != nil {
		return err
	}
	err = q.InsertPublisherKey(ctx, controlstatedb.InsertPublisherKeyParams{ID: key, PublisherIdentityID: application, PublicKey: public, Revision: revision, CreatedAt: timestamptz(now), WorkloadSessionID: text(session), WorkloadBindingID: text(binding)})
	if err != nil {
		return err
	}
	captured, err := tx.Exec(ctx, `INSERT INTO control.workload_session_application_grants(workload_session_id,publisher_identity_id,grant_id,expires_at)
	    SELECT $1,app.id,grant_record.id,grant_record.expires_at FROM control.publisher_identities app JOIN control.publisher_grants grant_record ON grant_record.publisher_identity_id=app.id
	    WHERE app.id=$2 AND grant_record.revoked_at IS NULL AND (grant_record.expires_at IS NULL OR grant_record.expires_at>$3)
	    AND ($6::text[] IS NULL OR grant_record.operation<>'visit' OR grant_record.kind<>'service' OR EXISTS(
	        SELECT 1 FROM control.applied_project_services selected WHERE selected.team_id=$4 AND selected.project_key=$5
	        AND selected.service_id=grant_record.service_id AND selected.service=ANY($6::text[])))`, session, application, now, team, project, services)
	if err != nil {
		return err
	}
	if captured.RowsAffected() < 1 || captured.RowsAffected() > 64 {
		return ErrWorkloadDenied
	}
	return nil
}

// persistent keys retain their existing rotation rules. a federated key is
// additionally fenced by its exact source session, binding and captured grant.
func applicationKeyDeadline(ctx context.Context, q *controlstatedb.Queries, application, key, grant string, now time.Time) (*time.Time, error) {
	deadline, err := q.ReadApplicationKeyAuthority(ctx, controlstatedb.ReadApplicationKeyAuthorityParams{KeyID: key, PublisherIdentityID: application, GrantID: grant, Now: timestamptz(now)})
	if err != nil {
		return nil, publisherLookupError(err, ErrPublisherIdentity)
	}
	if deadline.Valid && deadline.InfinityModifier == pgtype.Infinity {
		return nil, nil
	}
	if !deadline.Valid || !deadline.Time.After(now) {
		return nil, ErrPublisherIdentity
	}
	return &deadline.Time, nil
}

func applicationPublisherLease(ctx context.Context, q *controlstatedb.Queries, application, key, grant string, until, now time.Time) (time.Time, error) {
	deadline, err := applicationKeyDeadline(ctx, q, application, key, grant, now)
	if deadline != nil {
		until = minTime(until, *deadline)
	}
	return until, err
}

func boundApplicationServingAuthority(ctx context.Context, q *controlstatedb.Queries, run controlstatedb.ControlPublishRun, now time.Time) (controlstatedb.ControlPublishRun, error) {
	if !run.PublisherIdentityID.Valid {
		return run, nil
	}
	until, err := applicationPublisherLease(ctx, q, run.PublisherIdentityID.String, run.PublisherKeyID.String, run.PublisherGrantID.String, run.PublisherExpiresAt.Time, now)
	if err != nil {
		return run, err
	}
	if !until.Before(run.PublisherExpiresAt.Time) {
		return run, nil
	}
	return q.BoundPublishRunApplicationAuthority(ctx, controlstatedb.BoundPublishRunApplicationAuthorityParams{ID: run.ID, ExpiresAt: timestamptz(until)})
}
