-- name: MachinePublisherAuthority :one
-- a nullable deadline distinguishes ordinary publishers from machine sessions.
SELECT (CASE WHEN session.id IS NULL THEN NULL ELSE LEAST(session.proof_expires_at,session.expires_at,permission.expires_at) END)::timestamptz AS deadline,
    (machine.id IS NOT NULL AND machine.revoked_at IS NULL AND
      (session.id IS NULL OR session.grant_id=sqlc.arg(grant_id) AND session.identity_revision=machine.revision AND session.proof_expires_at>sqlc.arg(now_time) AND session.expires_at>sqlc.arg(now_time)
       AND permission.revoked_at IS NULL AND permission.expires_at>sqlc.arg(now_time)
       AND (permission.public_url_id IS NULL OR resource.team_id=machine.team_id AND resource.purpose='app' AND resource.service_protocol='http' AND NOT resource.ephemeral AND resource.lifecycle_state='enabled'
          AND NOT EXISTS(SELECT 1 FROM control.applied_project_services applied WHERE applied.public_url_id=resource.id AND applied.group_id IS NOT NULL))
       AND NOT EXISTS(SELECT 1 FROM control.service_namespace_claims claim WHERE claim.group_id IS NOT NULL AND (claim.retired_at IS NULL OR claim.reusable_after>sqlc.arg(now_time))
          AND (claim.namespace=COALESCE(permission.namespace,resource.canonical_hostname) OR permission.namespace IS NOT NULL AND right(claim.namespace,length(permission.namespace)+1)='.'||permission.namespace
             OR right(COALESCE(permission.namespace,resource.canonical_hostname),length(claim.namespace)+1)='.'||claim.namespace))))::boolean AS allowed
FROM control.publisher_identities publisher
LEFT JOIN control.machine_identities machine ON machine.id=publisher.created_by_machine_id AND machine.team_id=publisher.team_id
LEFT JOIN control.machine_publication_sessions session ON session.publisher_identity_id=publisher.id
LEFT JOIN control.machine_publication_permissions permission ON permission.id=session.permission_id AND permission.machine_id=machine.id AND permission.team_id=machine.team_id
LEFT JOIN control.public_urls resource ON resource.id=permission.public_url_id
WHERE publisher.id=sqlc.arg(publisher_identity_id) AND publisher.created_by_machine_id IS NOT NULL;

-- name: BoundMachinePublishRunExpiry :one
UPDATE control.publish_runs SET publisher_expires_at=LEAST(publisher_expires_at,sqlc.arg(deadline)) WHERE id=sqlc.arg(id) RETURNING *;

-- name: MachinePublisherAnonymousAllocation :one
SELECT EXISTS(SELECT 1 FROM control.machine_publication_sessions session JOIN control.machine_publication_permissions permission ON permission.id=session.permission_id WHERE session.publisher_identity_id=sqlc.arg(publisher_identity_id) AND permission.namespace IS NOT NULL AND permission.allow_anonymous)::boolean;

-- name: LockMachinePublicationCleanupTeam :one
-- cleanup retains the same team guard as refresh, including terminal teams.
-- this lock permits only removing owned allocation/source state, not serving.
WITH guard AS MATERIALIZED (
    SELECT pg_advisory_xact_lock(hashtextextended('tnl:local-team:' || sqlc.arg(team_id)::text, 0))
)
SELECT teams.id FROM control.teams AS teams CROSS JOIN guard
WHERE teams.id=sqlc.arg(team_id)
FOR NO KEY UPDATE OF teams;
