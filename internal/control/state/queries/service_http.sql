-- name: ServiceHTTPBrowserEndpoint :one
SELECT s.team_id,s.guest_id,s.certificate_hostname,s.service_port,
    ARRAY(SELECT run.id FROM control.service_runs run
         WHERE run.service_id=s.id AND run.state='ready' AND run.healthy
         AND run.closed_at IS NULL AND run.publisher_expires_at>sqlc.arg(now)
         AND run.certificate_expires_at>sqlc.arg(now)
         AND EXISTS(SELECT 1 FROM control.publisher_service_permission(run.publisher_identity_id,
             run.publisher_grant_id,s.id,sqlc.arg(now)) permission
             JOIN control.publisher_grants grant_record ON grant_record.id=run.publisher_grant_id
             JOIN control.publisher_identity_keys signing ON signing.id=run.publisher_key_id
                 AND signing.publisher_identity_id=run.publisher_identity_id
                 AND (grant_record.kind='service' OR signing.retired_at IS NULL))
         ORDER BY run.run_number LIMIT 256)::text[] AS run_ids
FROM control.services s
WHERE s.id=sqlc.arg(service_id) AND s.protocol='http' AND s.enabled AND s.deleted_at IS NULL;

-- name: InsertServiceHTTPBrowserLogin :exec
INSERT INTO control.service_http_browser_logins(state_digest,binding_digest,service_id,run_ids,return_path,nonce,verifier_ciphertext,storage_key_id,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);

-- name: ReadyServiceBrowserHosts :many
SELECT service.id AS service_id,service.certificate_hostname,
    array_agg(run.id ORDER BY run.run_number)::text[] AS run_ids
FROM control.services service JOIN control.service_runs run ON run.service_id=service.id
WHERE service.enabled AND service.deleted_at IS NULL AND service.protocol='http'
    AND run.state='ready' AND run.healthy AND run.closed_at IS NULL
    AND run.publisher_expires_at>sqlc.arg(now) AND run.certificate_expires_at>sqlc.arg(now)
    AND EXISTS(SELECT 1 FROM control.publisher_service_permission(run.publisher_identity_id,
        run.publisher_grant_id,service.id,sqlc.arg(now)) permission
        JOIN control.publisher_grants grant_record ON grant_record.id=run.publisher_grant_id
        JOIN control.publisher_identity_keys signing ON signing.id=run.publisher_key_id
            AND signing.publisher_identity_id=run.publisher_identity_id
            AND (grant_record.kind='service' OR signing.retired_at IS NULL))
    AND (service.id=sqlc.arg(service_id) OR EXISTS(
        SELECT 1 FROM control.preview_services included WHERE included.preview_id=sqlc.arg(preview_id)::text
            AND included.service_id=service.id))
GROUP BY service.id,service.certificate_hostname ORDER BY service.id LIMIT 32;

-- name: ConsumeServiceHTTPBrowserLogin :one
UPDATE control.service_http_browser_logins SET consumed_at=sqlc.arg(now)
WHERE state_digest=sqlc.arg(state_digest) AND binding_digest=sqlc.arg(binding_digest)
AND consumed_at IS NULL AND expires_at>sqlc.arg(now)
RETURNING *;

-- name: InsertServiceHTTPBrowserSession :exec
INSERT INTO control.service_http_browser_sessions(token_digest,control_session_id,parent_control_session_id,expires_at,refresh_ciphertext,storage_key_id)
VALUES($1,$2,sqlc.narg(parent_control_session_id),$3,$4,$5);

-- name: InsertServiceHTTPBrowserHandoff :exec
INSERT INTO control.service_http_browser_handoffs(token_digest,session_digest,service_id,run_ids,cookie_ciphertext,storage_key_id,return_path,redirect_url,bridge,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);

-- name: LockServiceHTTPBrowserSession :one
SELECT token_digest
FROM control.service_http_browser_sessions
WHERE token_digest=$1
FOR UPDATE NOWAIT;

-- name: ReadServiceHTTPBrowserSession :one
SELECT session.*, parent.identity_id,person.display_name,parent.access_expires_at,
    LEAST(parent.refresh_expires_at,original.refresh_expires_at)::timestamptz AS refresh_expires_at,
    COALESCE(parent.revoked_at,original.revoked_at) AS parent_revoked_at
FROM control.service_http_browser_sessions session
JOIN control.control_sessions parent ON parent.id=session.control_session_id
JOIN control.identities person ON person.id=parent.identity_id AND person.disabled_at IS NULL
LEFT JOIN control.control_sessions original ON original.id=session.parent_control_session_id AND original.identity_id=parent.identity_id
WHERE session.token_digest=sqlc.arg(cookie_digest) AND session.revoked_at IS NULL AND session.expires_at>sqlc.arg(expires_at)
    AND EXISTS(SELECT 1 FROM control.service_http_browser_handoffs bound
        WHERE bound.session_digest=session.token_digest AND bound.service_id=sqlc.arg(service_id)
        AND bound.consumed_at IS NOT NULL AND bound.revoked_at IS NULL);

-- name: RotateServiceHTTPBrowserSession :exec
UPDATE control.service_http_browser_sessions SET refresh_ciphertext=$2,storage_key_id=$3
WHERE token_digest=$1;

-- name: RedeemServiceHTTPBrowserHandoff :one
UPDATE control.service_http_browser_handoffs handoff SET consumed_at=sqlc.arg(now)
FROM control.service_http_browser_sessions session
WHERE handoff.token_digest=sqlc.arg(token_digest) AND handoff.service_id=sqlc.arg(service_id)
AND sqlc.arg(service_run_id)::text=ANY(handoff.run_ids) AND handoff.consumed_at IS NULL AND handoff.revoked_at IS NULL
AND handoff.expires_at>sqlc.arg(now) AND session.token_digest=handoff.session_digest
AND session.revoked_at IS NULL AND session.expires_at>sqlc.arg(now)
RETURNING handoff.session_digest,handoff.cookie_ciphertext,handoff.storage_key_id,
    handoff.return_path,handoff.redirect_url,handoff.bridge,session.expires_at;

-- name: ServiceHTTPBrowserPermission :one
SELECT session.identity_id,session.id AS control_session_id,person.display_name,
    LEAST(browser.expires_at,session.access_expires_at,session.refresh_expires_at,original.refresh_expires_at)::timestamptz AS expires_at
FROM control.service_http_browser_sessions browser
JOIN control.control_sessions session ON session.id=browser.control_session_id AND session.revoked_at IS NULL
JOIN control.identities person ON person.id=session.identity_id AND person.disabled_at IS NULL
LEFT JOIN control.control_sessions original ON original.id=browser.parent_control_session_id AND original.identity_id=session.identity_id
WHERE browser.token_digest=sqlc.arg(cookie_digest) AND browser.revoked_at IS NULL
AND browser.expires_at>sqlc.arg(now) AND session.access_expires_at>sqlc.arg(now) AND session.refresh_expires_at>sqlc.arg(now)
AND (browser.parent_control_session_id IS NULL OR original.revoked_at IS NULL AND original.refresh_expires_at>sqlc.arg(now))
AND EXISTS(SELECT 1 FROM control.service_http_browser_handoffs bound
    WHERE bound.session_digest=browser.token_digest AND bound.service_id=sqlc.arg(service_id)
    AND bound.consumed_at IS NOT NULL AND bound.revoked_at IS NULL);

-- name: ServiceHTTPPreviewTeamPermission :one
SELECT control.company_subject_deadline(service.team_id,sqlc.arg(identity_id)::text,sqlc.arg(control_session_id)::text,sqlc.arg(now)::timestamptz)::timestamptz AS expires_at
FROM control.services service
JOIN control.team_memberships member ON member.team_id=service.team_id AND member.identity_id=sqlc.arg(identity_id)
WHERE service.id=sqlc.arg(service_id) AND service.protocol='http' AND service.enabled AND service.deleted_at IS NULL
    AND control.active_membership(member.id,sqlc.arg(now)) AND control.active_team_subject(service.team_id,member.identity_id,sqlc.arg(now))
    AND control.company_subject_session_authorized(service.team_id,member.identity_id,sqlc.arg(control_session_id)::text,sqlc.arg(now))
    AND EXISTS(SELECT 1 FROM control.previews preview JOIN control.preview_services included ON included.preview_id=preview.id AND included.team_id=preview.team_id
        WHERE included.service_id=service.id AND preview.team_id=service.team_id AND preview.team_access_enabled AND preview.demo_service_run_id IS NULL);

-- name: RevokeServiceHTTPBrowserSession :exec
UPDATE control.service_http_browser_sessions browser SET revoked_at=COALESCE(browser.revoked_at,sqlc.arg(now))
WHERE browser.token_digest=sqlc.arg(cookie_digest)
AND EXISTS(SELECT 1 FROM control.service_http_browser_handoffs bound
    WHERE bound.session_digest=browser.token_digest AND bound.service_id=sqlc.arg(service_id)
    AND bound.consumed_at IS NOT NULL AND bound.revoked_at IS NULL);

-- name: InsertServiceHTTPGrant :exec
INSERT INTO control.service_http_grants(id,service_id,kind,secret_digest,created_by_identity_id,control_session_id,expires_at)
VALUES($1,$2,$3,$4,$5,sqlc.narg(control_session_id),$6);

-- name: RevokeServiceHTTPGrant :execrows
UPDATE control.service_http_grants SET revoked_at=COALESCE(revoked_at,sqlc.arg(now))
WHERE id=sqlc.arg(id) AND service_id=sqlc.arg(service_id);

-- name: ListServiceHTTPGrants :many
SELECT id,kind,expires_at,revoked_at FROM control.service_http_grants
WHERE service_id=sqlc.arg(service_id) ORDER BY id;

-- name: ServicePublicEndpointBinding :one
SELECT destination_port,identity_id,device_id,workload_session_id FROM control.public_service_visitors
WHERE visitor_connection_id=$1;
