package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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

// return only the original captured grants that remain authorized now. the
// application never receives grants added after this session began.
func readWorkloadApplication(ctx context.Context, q *controlstatedb.Queries, session string, now time.Time) (controlv1.RegisteredApplication, error) {
	identity, err := q.ReadWorkloadApplicationIdentity(ctx, controlstatedb.ReadWorkloadApplicationIdentityParams{SessionID: text(session), Now: timestamptz(now)})
	if err != nil {
		return controlv1.RegisteredApplication{}, publisherLookupError(err, ErrWorkloadDenied)
	}
	grants, err := q.ListCapturedApplicationGrants(ctx, controlstatedb.ListCapturedApplicationGrantsParams{SessionID: session, Now: timestamptz(now)})
	if err != nil {
		return controlv1.RegisteredApplication{}, err
	}
	if len(grants) > 64 {
		return controlv1.RegisteredApplication{}, ErrWorkloadDenied
	}
	result := controlv1.RegisteredApplication{ClientId: identity.ID, KeyId: identity.KeyID, TeamId: identity.TeamID, Name: identity.Name, Ownership: controlv1.RegisteredApplicationOwnership(identity.Ownership), Grants: []controlv1.PublisherGrant{}}
	selectedText := func(value pgtype.Text) *string {
		if value.Valid {
			return new(value.String)
		}
		return nil
	}
	for _, grant := range grants {
		result.Grants = append(result.Grants, controlv1.PublisherGrant{Id: grant.ID, Kind: controlv1.PublisherGrantKind(grant.Kind), Operation: controlv1.ApplicationOperation(grant.Operation), PublicUrlId: selectedText(grant.PublicURLID), ServiceId: selectedText(grant.ServiceID), DomainId: selectedText(grant.DomainID), Namespace: selectedText(grant.Namespace), CreatedAt: grant.CreatedAt.Time, ExpiresAt: optionalTime(grant.CapturedExpiresAt)})
	}
	return result, nil
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
