-- name: CreateShare :one
INSERT INTO control.shares (
    id, preview_id, team_id, scope, label, entry_service_id, control_session_id, issuer_company_context,
    created_by_identity_id,idempotency_key,request_digest,secret_digest,created_at,expires_at
) VALUES (
    sqlc.arg(id),sqlc.narg(preview_id),sqlc.arg(team_id),sqlc.arg(scope),sqlc.arg(label),
    sqlc.arg(entry_service_id),sqlc.narg(control_session_id),sqlc.narg(issuer_company_context)::text::jsonb,sqlc.arg(created_by_identity_id),
    sqlc.arg(idempotency_key),sqlc.arg(request_digest),sqlc.arg(secret_digest),sqlc.arg(created_at),sqlc.arg(expires_at)
)
ON CONFLICT (created_by_identity_id,idempotency_key)
DO UPDATE SET idempotency_key=EXCLUDED.idempotency_key
RETURNING *;

-- name: AddShareService :one
INSERT INTO control.share_services(share_id,team_id,service_id)
SELECT share.id,share.team_id,service.id FROM control.shares share
JOIN control.services service ON service.id=sqlc.arg(service_id) AND service.team_id=share.team_id
WHERE share.id=sqlc.arg(share_id) AND share.created_by_identity_id=sqlc.arg(identity_id)
    AND service.enabled AND service.deleted_at IS NULL AND service.protocol='http'
    AND (share.scope='service' OR (share.scope='preview' AND EXISTS(
        SELECT 1 FROM control.preview_services included WHERE included.preview_id=share.preview_id
            AND included.team_id=share.team_id AND included.service_id=service.id)))
RETURNING service_id;

-- name: FindGuestShareRequest :one
SELECT * FROM control.shares WHERE guest_id=sqlc.arg(guest_id) AND idempotency_key=sqlc.arg(idempotency_key);

-- name: CreateGuestShare :one
-- caller holds the trial and exact service and verifies the trial credential
-- and observed source. publication permission alone never authorizes sharing.
INSERT INTO control.shares(id,guest_id,scope,label,entry_service_id,idempotency_key,
    request_digest,secret_digest,created_at,expires_at)
SELECT sqlc.arg(id)::text AS id,guest.id AS guest_id,'guest'::text AS scope,
    sqlc.arg(label)::text AS label,service.id AS entry_service_id,sqlc.arg(idempotency_key)::text AS idempotency_key,
    sqlc.arg(request_digest)::bytea AS request_digest,sqlc.arg(secret_digest)::bytea AS secret_digest,
    sqlc.arg(now)::timestamptz AS created_at,LEAST(guest.expires_at,sqlc.arg(expires_at)::timestamptz) AS expires_at
FROM control.guest_trials guest JOIN control.services service ON service.guest_id=guest.id
WHERE guest.id=sqlc.arg(guest_id) AND service.id=sqlc.arg(service_id)
    AND service.enabled AND service.deleted_at IS NULL AND service.protocol='http'
    AND control.guest_share_live(guest.id,sqlc.arg(now))
    AND LEAST(guest.expires_at,sqlc.arg(expires_at))>sqlc.arg(now)
RETURNING *;

-- name: AddGuestShareService :execrows
INSERT INTO control.share_services(share_id,guest_id,service_id)
SELECT share.id,share.guest_id,service.id FROM control.shares share
JOIN control.services service ON service.id=share.entry_service_id AND service.guest_id=share.guest_id
WHERE share.id=sqlc.arg(share_id) AND share.guest_id=sqlc.arg(guest_id)
    AND share.scope='guest' AND service.enabled AND service.deleted_at IS NULL AND service.protocol='http';

-- name: RevokeGuestShare :one
UPDATE control.shares SET revoked_at=COALESCE(revoked_at,sqlc.arg(now)::timestamptz),
    revoked_by_guest_id=COALESCE(revoked_by_guest_id,guest_id)
WHERE id=sqlc.arg(share_id) AND guest_id=sqlc.arg(guest_id)
RETURNING *;

-- name: GetShare :one
SELECT * FROM control.shares WHERE id=$1;

-- name: FindShareRequest :one
SELECT * FROM control.shares WHERE created_by_identity_id=$1 AND idempotency_key=$2;

-- name: ListShareServices :many
SELECT service_id FROM control.share_services WHERE share_id=$1 ORDER BY service_id;

-- name: ListShares :many
SELECT * FROM control.shares WHERE preview_id=sqlc.arg(preview_id) AND id>sqlc.arg(after_id)
ORDER BY id LIMIT 101;

-- name: ListTeamShares :many
SELECT * FROM control.shares WHERE team_id=sqlc.arg(team_id)
    AND created_by_identity_id=sqlc.arg(identity_id) AND id>sqlc.arg(after_id)
ORDER BY id LIMIT 101;

-- name: RevokeShare :one
UPDATE control.shares SET revoked_at=COALESCE(revoked_at,sqlc.arg(revoked_at)::timestamptz),
    revoked_by_identity_id=COALESCE(revoked_by_identity_id,sqlc.arg(identity_id)::text)
WHERE id=sqlc.arg(share_id) AND created_by_identity_id=sqlc.arg(identity_id)
RETURNING *;
