-- name: VisitorPermission :one
SELECT reason::text, expires_at::timestamptz, COALESCE(grant_id,'')::text AS grant_id FROM control.visitor_identity_permission(
    sqlc.arg(resource_kind)::text,sqlc.arg(resource_id)::text,sqlc.arg(identity_id)::text,
    sqlc.arg(control_session_id)::text,sqlc.arg(preview_id)::text,sqlc.arg(now)::timestamptz);

-- name: LockVisitorIdentity :one
SELECT * FROM control.identities WHERE id = $1 AND disabled_at IS NULL FOR SHARE;

-- name: LockVisitorControlSession :one
SELECT * FROM control.control_sessions WHERE access_token_id = $1 FOR SHARE;

-- name: GetVisitorParentSession :one
SELECT * FROM control.control_sessions WHERE id = $1 FOR SHARE;

-- name: VisitorFeedbackPolicy :one
SELECT feedback_authors FROM control.teams WHERE id = $1 AND deleted_at IS NULL;

-- name: SetVisitorFeedbackPolicy :exec
UPDATE control.teams SET feedback_authors = $2 WHERE id = $1;

-- name: VisitorCurrentMembership :one
SELECT id FROM control.team_memberships WHERE team_id = $1 AND identity_id = $2 AND control.active_membership(id,CURRENT_TIMESTAMP);

-- name: CleanupVisitorSessions :exec
DELETE FROM control.service_http_browser_sessions AS stored WHERE stored.token_digest IN (
 SELECT expired.token_digest FROM control.service_http_browser_sessions AS expired
 WHERE expired.expires_at <= sqlc.arg(now) OR expired.revoked_at IS NOT NULL LIMIT 100);

-- name: CleanupVisitorHandoffs :exec
DELETE FROM control.service_http_browser_handoffs AS stored WHERE stored.token_digest IN (
 SELECT expired.token_digest FROM control.service_http_browser_handoffs AS expired
 WHERE expired.expires_at <= sqlc.arg(now) AND expired.consumed_at IS NULL LIMIT 100);

-- name: CleanupVisitorLogins :exec
DELETE FROM control.service_http_browser_logins AS stored WHERE stored.state_digest IN (
 SELECT expired.state_digest FROM control.service_http_browser_logins AS expired WHERE expired.expires_at <= sqlc.arg(now) LIMIT 100);
