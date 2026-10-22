-- name: CompanySessionAuthorized :one
SELECT control.company_session_authorized(sqlc.arg(team_id)::text, sqlc.arg(identity_id)::text, sqlc.arg(session_id)::text, sqlc.arg(now)::timestamptz)::boolean;

-- name: GetVisitorPolicyRevision :one
SELECT COALESCE((SELECT policy_revision FROM control.teams WHERE id=sqlc.arg(team_id)),0)::bigint;

-- name: ActiveCompanyMembership :one
SELECT control.active_membership(sqlc.arg(membership_id)::text, sqlc.arg(now)::timestamptz)::boolean;

-- name: ActiveTeamSubject :one
SELECT control.active_team_subject(sqlc.arg(team_id)::text,sqlc.arg(identity_id)::text,sqlc.arg(now)::timestamptz)::boolean;

-- name: CompanySubjectSessionAuthorized :one
SELECT control.company_subject_session_authorized(sqlc.arg(team_id)::text,sqlc.arg(identity_id)::text,sqlc.arg(session_id)::text,sqlc.arg(now)::timestamptz)::boolean;

-- name: CompanySubjectDeadline :one
SELECT control.company_subject_deadline(sqlc.arg(team_id)::text,sqlc.arg(identity_id)::text,sqlc.arg(session_id)::text,sqlc.arg(now)::timestamptz)::timestamptz;

-- name: GetCurrentIdentityConnection :one
SELECT * FROM control.identity_connections WHERE team_id=sqlc.arg(team_id) AND state='active';

-- name: LockIdentityConnection :one
SELECT * FROM control.identity_connections WHERE team_id=sqlc.arg(team_id) AND id=sqlc.arg(id) FOR UPDATE;

-- name: PutCompanyEligibility :exec
INSERT INTO control.company_eligibility(identity_connection_id,team_id,identity_id,subject,connection_revision,revision,eligible,valid_until,request_digest,updated_at)
VALUES(sqlc.arg(identity_connection_id),sqlc.arg(team_id),sqlc.arg(identity_id),sqlc.arg(subject),sqlc.arg(connection_revision),sqlc.arg(revision),sqlc.arg(eligible),sqlc.arg(valid_until),sqlc.arg(request_digest),sqlc.arg(now))
ON CONFLICT(identity_connection_id,identity_id) DO UPDATE SET
    connection_revision=EXCLUDED.connection_revision, revision=EXCLUDED.revision,
    eligible=EXCLUDED.eligible, valid_until=EXCLUDED.valid_until, request_digest=EXCLUDED.request_digest, updated_at=EXCLUDED.updated_at, expiration_notified_at=NULL;

-- name: GetCompanyEligibility :one
SELECT * FROM control.company_eligibility WHERE identity_connection_id=sqlc.arg(identity_connection_id) AND identity_id=sqlc.arg(identity_id);

-- name: InsertCompanyAccessAudit :exec
INSERT INTO control.company_access_audit(team_id,identity_connection_id,actor_identity_id,target_identity_id,operation,revision,occurred_at,details)
VALUES(sqlc.arg(team_id),sqlc.narg(identity_connection_id),sqlc.narg(actor_identity_id),sqlc.narg(target_identity_id),sqlc.arg(operation),sqlc.arg(revision),sqlc.arg(now),sqlc.arg(details)::text::jsonb);

-- name: ValidateVerifiedCompanyProof :one
SELECT EXISTS(SELECT 1 FROM control.identity_connections c JOIN control.company_eligibility e
 ON e.identity_connection_id=c.id AND e.team_id=c.team_id
 WHERE c.id=sqlc.arg(connection_id) AND c.team_id=sqlc.arg(team_id) AND c.issuer=sqlc.arg(issuer)
 AND c.source_id=sqlc.arg(source_id) AND c.revision=sqlc.arg(connection_revision) AND c.state='active'
 AND e.identity_id=sqlc.arg(identity_id) AND e.subject=sqlc.arg(subject)
 AND e.connection_revision=c.revision AND e.eligible AND e.valid_until>sqlc.arg(now))::boolean;

-- name: CopyCompanySessionContexts :exec
INSERT INTO control.company_session_contexts (session_id,team_id,identity_connection_id,connection_revision,subject,authenticated_at,expires_at)
SELECT sqlc.arg(destination_session_id)::text AS session_id,proof.team_id,proof.identity_connection_id,proof.connection_revision,proof.subject,proof.authenticated_at,LEAST(proof.expires_at,sqlc.arg(expires_at)::timestamptz) AS expires_at
FROM control.company_session_contexts AS proof JOIN control.control_sessions AS source ON source.id=proof.session_id
JOIN control.control_sessions AS destination ON destination.id=sqlc.arg(destination_session_id) AND destination.identity_id=source.identity_id
WHERE proof.session_id=sqlc.arg(source_session_id) AND proof.expires_at>sqlc.arg(now) AND source.revoked_at IS NULL
AND control.company_authentication_current(proof.team_id,source.identity_id,source.id,sqlc.arg(now))
ON CONFLICT(session_id,team_id) DO NOTHING;

-- name: InsertCompanySessionContext :exec
INSERT INTO control.company_session_contexts(session_id,team_id,identity_connection_id,connection_revision,subject,authenticated_at,expires_at)
VALUES(sqlc.arg(session_id),sqlc.arg(team_id),sqlc.arg(connection_id),sqlc.arg(connection_revision),sqlc.arg(subject),sqlc.arg(authenticated_at),sqlc.arg(expires_at));

-- name: LockCompanyLoginIntent :one
SELECT * FROM control.company_login_intents WHERE id=sqlc.arg(id) FOR UPDATE;

-- name: ConsumeCompanyLoginIntent :execrows
UPDATE control.company_login_intents SET consumed_at=sqlc.arg(now) WHERE id=sqlc.arg(id) AND consumed_at IS NULL;

-- name: CompanySessionRefreshValid :one
SELECT NOT EXISTS(SELECT 1 FROM control.company_session_contexts proof WHERE proof.session_id=sqlc.arg(session_id)
 AND NOT control.company_authentication_current(proof.team_id,sqlc.arg(identity_id)::text,proof.session_id,sqlc.arg(now)))::boolean;

-- name: GetCompanyAuthenticationDeadline :one
SELECT min(expires_at)::timestamptz FROM control.company_session_contexts WHERE session_id=sqlc.arg(session_id);
