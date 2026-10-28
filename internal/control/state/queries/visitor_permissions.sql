-- name: VisitorPermission :one
SELECT reason::text, expires_at::timestamptz FROM control.visitor_identity_permission(
    sqlc.arg(resource_kind)::text,sqlc.arg(resource_id)::text,sqlc.arg(identity_id)::text,
    sqlc.arg(control_session_id)::text,sqlc.arg(preview_id)::text,sqlc.arg(now)::timestamptz);

-- name: LockVisitorIdentity :one
SELECT * FROM control.identities WHERE id = $1 AND disabled_at IS NULL FOR SHARE;

-- name: LockVisitorControlSession :one
SELECT * FROM control.control_sessions WHERE access_token_id = $1 FOR SHARE;

-- name: GetVisitorParentSession :one
SELECT * FROM control.control_sessions WHERE id = $1 FOR SHARE;

-- name: ListVisitorInventory :many
SELECT u.id, u.team_id, t.display_name AS team_name, u.canonical_hostname, u.service_protocol,
    permission.reason::text AS visitor_access
FROM control.public_urls u JOIN control.teams t ON t.id = u.team_id
CROSS JOIN LATERAL control.visitor_identity_permission('public_url',u.id,sqlc.arg(identity_id)::text,sqlc.arg(control_session_id)::text,
    COALESCE((SELECT p.id FROM control.previews p JOIN control.preview_public_urls included ON included.preview_id = p.id
      WHERE included.public_url_id = u.id AND p.team_access_enabled AND p.demo_publish_run_id IS NULL ORDER BY p.id LIMIT 1), ''),
    sqlc.arg(now)::timestamptz) permission
WHERE u.id > sqlc.arg(cursor)::text AND (sqlc.arg(team_id)::text = '' OR u.team_id = sqlc.arg(team_id))
  AND control.company_subject_session_authorized(u.team_id,sqlc.arg(identity_id)::text,sqlc.arg(control_session_id)::text,sqlc.arg(now))
ORDER BY u.id LIMIT 101;

-- name: CreateVisitorGrant :one
INSERT INTO control.visitor_grants(id, public_url_id, team_id, kind, identity_id, created_by_identity_id,
    idempotency_key, request_digest, created_at, expires_at)
VALUES ($1, $2, $3, $4, sqlc.narg(identity_id), $5, $6, $7, $8, sqlc.narg(expires_at))
ON CONFLICT (resource_kind,created_by_identity_id,kind,idempotency_key) DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key RETURNING *;

-- name: ListVisitorGrants :many
SELECT * FROM control.visitor_grants WHERE public_url_id = $1 ORDER BY id;

-- name: GetVisitorGrant :one
SELECT * FROM control.visitor_grants WHERE id = $1;

-- name: RevokeVisitorGrant :exec
UPDATE control.visitor_grants SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1;

-- name: CreateVisitorInvitation :one
INSERT INTO control.visitor_invitations(id, public_url_id, team_id, normalized_email, token_digest, created_by_identity_id,
    idempotency_key, request_digest, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (created_by_identity_id, idempotency_key) DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key RETURNING *;

-- name: GetVisitorInvitation :one
SELECT * FROM control.visitor_invitations WHERE id = $1;

-- name: LockVisitorInvitation :one
SELECT * FROM control.visitor_invitations WHERE id = $1 FOR UPDATE;

-- name: AcceptVisitorInvitation :exec
UPDATE control.visitor_invitations SET accepted_at = $2, accepted_identity_id = $3 WHERE id = $1;

-- name: RevokeVisitorInvitation :exec
UPDATE control.visitor_invitations SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1;

-- name: ListVisitorInvitations :many
SELECT * FROM control.visitor_invitations WHERE public_url_id = $1 ORDER BY id;

-- name: VisitorFeedbackPolicy :one
SELECT feedback_authors FROM control.teams WHERE id = $1 AND deleted_at IS NULL;

-- name: SetVisitorFeedbackPolicy :exec
UPDATE control.teams SET feedback_authors = $2 WHERE id = $1;

-- name: VisitorCurrentMembership :one
SELECT id FROM control.team_memberships WHERE team_id = $1 AND identity_id = $2 AND control.active_membership(id,CURRENT_TIMESTAMP);

-- name: ReadyBrowserHosts :many
SELECT DISTINCT ON(u.id) u.id AS public_url_id, u.canonical_hostname, r.id AS publish_run_id
FROM control.public_urls u JOIN control.publish_runs r ON r.public_url_id = u.id
WHERE u.lifecycle_state = 'enabled' AND u.purpose IN ('app', 'alias') AND u.service_protocol = 'http'
  AND r.state = 'ready' AND r.publisher_expires_at > sqlc.arg(now) AND r.closed_at IS NULL
  AND (u.id = sqlc.arg(public_url_id) OR EXISTS (SELECT 1 FROM control.preview_public_urls included
       WHERE included.preview_id = sqlc.arg(preview_id)::text AND included.public_url_id = u.id))
ORDER BY u.id,r.publish_run_number DESC LIMIT 32;

-- name: BindBrowserSessionHost :exec
INSERT INTO control.browser_session_run_bindings(session_digest, public_url_id, publish_run_id)
SELECT sqlc.arg(session_digest),sqlc.arg(public_url_id),publish_run_id FROM control.browser_handoff_run_bindings
WHERE handoff_digest=sqlc.arg(handoff_digest)
ON CONFLICT (session_digest, public_url_id,publish_run_id) DO NOTHING;

-- name: BrowserSessionCurrentHost :one
SELECT h.publish_run_id FROM control.browser_session_run_bindings h JOIN control.publish_runs r ON r.id = h.publish_run_id
WHERE h.session_digest = $1 AND h.public_url_id = $2 AND r.closed_at IS NULL AND r.publisher_expires_at > $3
  AND r.state = 'ready' AND r.public_url_id = h.public_url_id ORDER BY r.publish_run_number LIMIT 1;

-- name: CreateVisitorIPGrant :exec
INSERT INTO control.visitor_ip_grants(id, public_url_id, prefix_ciphertext, storage_key_id, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, sqlc.narg(expires_at));

-- name: ListVisitorIPGrants :many
SELECT * FROM control.visitor_ip_grants WHERE public_url_id = $1 AND revoked_at IS NULL ORDER BY id;

-- name: RevokeVisitorIPGrants :exec
UPDATE control.visitor_ip_grants SET revoked_at = $2 WHERE public_url_id = $1 AND revoked_at IS NULL;

-- name: RemoveVisitorIPGrant :execrows
UPDATE control.visitor_ip_grants SET revoked_at = $3 WHERE public_url_id = $1 AND id = $2 AND revoked_at IS NULL;

-- name: MarkVisitorIPSet :exec
INSERT INTO control.visitor_ip_policy_sets(public_url_id) VALUES ($1) ON CONFLICT DO NOTHING;

-- name: HasVisitorIPSet :one
SELECT EXISTS(SELECT 1 FROM control.visitor_ip_policy_sets WHERE public_url_id = $1)::boolean;

-- name: ExpiringVisitorIPURLs :many
SELECT DISTINCT public_url_id FROM control.visitor_ip_grants WHERE revoked_at IS NULL AND expires_at <= $1 ORDER BY public_url_id LIMIT 100;

-- name: SaveVisitorIPPolicy :execrows
UPDATE control.public_urls SET ip_policy = CASE WHEN sqlc.narg(hashes)::bytea IS NULL THEN 'allow_all' ELSE 'allowlist' END,
    allowed_ip_policy_ciphertext = sqlc.narg(ciphertext), allowed_ip_policy_storage_key_id = sqlc.narg(storage_key_id),
    allowed_ip_hashes = sqlc.narg(hashes), allowed_ip_hash_key_id = sqlc.narg(hash_key_id), updated_at = sqlc.arg(now),
    mutation_revision = mutation_revision + CASE WHEN sqlc.arg(advance_mutation)::boolean THEN 1 ELSE 0 END
WHERE id = sqlc.arg(public_url_id) AND (mutation_revision < 9223372036854775807 OR NOT sqlc.arg(advance_mutation));

-- name: SetPublicURLAccessMode :execrows
UPDATE control.public_urls SET access_mode = sqlc.arg(access_mode), mutation_revision = mutation_revision + 1,
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(public_url_id) AND lifecycle_state = 'enabled'
  AND mutation_revision = sqlc.arg(expected_revision) AND mutation_revision < 9223372036854775807;

-- name: ExpireVisitorIPGrants :exec
UPDATE control.visitor_ip_grants SET revoked_at = sqlc.arg(now)
WHERE public_url_id = sqlc.arg(public_url_id) AND revoked_at IS NULL AND expires_at <= sqlc.arg(now);

-- name: CleanupVisitorSessions :exec
DELETE FROM control.browser_access_sessions AS stored WHERE stored.token_digest IN (
 SELECT expired.token_digest FROM control.browser_access_sessions AS expired
 WHERE expired.expires_at <= sqlc.arg(now) OR expired.revoked_at IS NOT NULL LIMIT 100);

-- name: CleanupVisitorHandoffs :exec
DELETE FROM control.browser_access_handoffs AS stored WHERE stored.token_digest IN (
 SELECT expired.token_digest FROM control.browser_access_handoffs AS expired
 WHERE expired.expires_at <= sqlc.arg(now) OR expired.consumed_at IS NOT NULL LIMIT 100);

-- name: CleanupVisitorLogins :exec
DELETE FROM control.browser_login_attempts AS stored WHERE stored.state_digest IN (
 SELECT expired.state_digest FROM control.browser_login_attempts AS expired WHERE expired.expires_at <= sqlc.arg(now) LIMIT 100);
