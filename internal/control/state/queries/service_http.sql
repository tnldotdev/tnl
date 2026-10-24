-- name: ServiceHTTPBrowserEndpoint :one
SELECT s.team_id,s.certificate_hostname,s.service_port,
    ARRAY(SELECT run.id FROM control.service_runs run
        WHERE run.service_id=s.id AND run.state='ready' AND run.healthy
        AND run.closed_at IS NULL AND run.publisher_expires_at>sqlc.arg(now)
        AND run.certificate_expires_at>sqlc.arg(now) ORDER BY run.run_number LIMIT 256)::text[] AS run_ids
FROM control.services s
WHERE s.id=sqlc.arg(service_id) AND s.protocol='http' AND s.enabled AND s.deleted_at IS NULL;

-- name: InsertServiceHTTPBrowserLogin :exec
INSERT INTO control.service_http_browser_logins(state_digest,binding_digest,service_id,run_ids,return_path,nonce,verifier_ciphertext,storage_key_id,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);

-- name: ConsumeServiceHTTPBrowserLogin :one
UPDATE control.service_http_browser_logins SET consumed_at=sqlc.arg(now)
WHERE state_digest=sqlc.arg(state_digest) AND binding_digest=sqlc.arg(binding_digest)
AND consumed_at IS NULL AND expires_at>sqlc.arg(now)
RETURNING *;

-- name: InsertServiceHTTPBrowserSession :exec
INSERT INTO control.service_http_browser_sessions(handoff_digest,service_id,run_ids,control_session_id,return_path,handoff_expires_at,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7);

-- name: RedeemServiceHTTPBrowserSession :one
UPDATE control.service_http_browser_sessions SET cookie_digest=sqlc.arg(cookie_digest)
WHERE handoff_digest=sqlc.arg(handoff_digest) AND service_id=sqlc.arg(service_id)
AND sqlc.arg(service_run_id)::text=ANY(run_ids) AND cookie_digest IS NULL AND revoked_at IS NULL
AND handoff_expires_at>sqlc.arg(now) AND expires_at>sqlc.arg(now)
RETURNING return_path,expires_at;

-- name: ServiceHTTPBrowserPermission :one
SELECT session.identity_id,session.id AS control_session_id,person.display_name,
    LEAST(browser.expires_at,session.refresh_expires_at)::timestamptz AS expires_at
FROM control.service_http_browser_sessions browser
JOIN control.control_sessions session ON session.id=browser.control_session_id AND session.revoked_at IS NULL
JOIN control.identities person ON person.id=session.identity_id AND person.disabled_at IS NULL
WHERE browser.service_id=sqlc.arg(service_id) AND browser.cookie_digest=sqlc.arg(cookie_digest)
AND sqlc.arg(service_run_id)::text=ANY(browser.run_ids) AND browser.revoked_at IS NULL
AND browser.expires_at>sqlc.arg(now) AND session.refresh_expires_at>sqlc.arg(now);

-- name: RevokeServiceHTTPBrowserSession :exec
UPDATE control.service_http_browser_sessions SET revoked_at=sqlc.arg(now)
WHERE service_id=sqlc.arg(service_id) AND cookie_digest=sqlc.arg(cookie_digest)
AND sqlc.arg(service_run_id)::text=ANY(run_ids);

-- name: InsertServiceHTTPGrant :exec
INSERT INTO control.service_http_grants(id,service_id,kind,secret_digest,created_by_identity_id,control_session_id,expires_at)
VALUES($1,$2,$3,$4,$5,sqlc.narg(control_session_id),$6);

-- name: RevokeServiceHTTPGrant :execrows
UPDATE control.service_http_grants SET revoked_at=COALESCE(revoked_at,sqlc.arg(now))
WHERE id=sqlc.arg(id) AND service_id=sqlc.arg(service_id);

-- name: ListServiceHTTPGrants :many
SELECT id,kind,expires_at,revoked_at FROM control.service_http_grants
WHERE service_id=sqlc.arg(service_id) ORDER BY id;

-- name: ServiceHTTPGrantPermission :one
SELECT id,created_by_identity_id,control_session_id,expires_at FROM control.service_http_grants
WHERE service_id=sqlc.arg(service_id) AND kind=sqlc.arg(kind)
AND secret_digest=sqlc.arg(secret_digest) AND revoked_at IS NULL AND expires_at>sqlc.arg(now);

-- name: ServiceHTTPAppliedConfiguration :one
SELECT project.team_id,project.project_key,project.configuration_ciphertext,project.storage_key_id,service.service FROM control.applied_project_services service
JOIN control.applied_projects project ON project.team_id=service.team_id AND project.project_key=service.project_key
WHERE service.service_id=$1;

-- name: CleanupServiceHTTPLogins :exec
DELETE FROM control.service_http_browser_logins stored WHERE stored.state_digest IN
    (SELECT expired.state_digest FROM control.service_http_browser_logins expired WHERE expired.expires_at<=sqlc.arg(now) LIMIT 100);

-- name: CleanupServiceHTTPSessions :exec
DELETE FROM control.service_http_browser_sessions stored WHERE stored.handoff_digest IN
    (SELECT expired.handoff_digest FROM control.service_http_browser_sessions expired WHERE expired.expires_at<=sqlc.arg(now) OR expired.revoked_at IS NOT NULL LIMIT 100);
