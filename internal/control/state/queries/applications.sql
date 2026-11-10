-- name: ReadApplicationRegistrationRequest :one
SELECT * FROM control.application_registration_requests
WHERE created_by_identity_id=sqlc.arg(identity_id) AND idempotency_key=sqlc.arg(idempotency_key);

-- name: RecordApplicationRegistrationRequest :exec
INSERT INTO control.application_registration_requests
    (created_by_identity_id,idempotency_key,request_digest,publisher_identity_id,key_id,grant_ids,created_at)
VALUES (sqlc.arg(identity_id),sqlc.arg(idempotency_key),sqlc.arg(request_digest),
    sqlc.arg(publisher_identity_id),sqlc.arg(key_id),sqlc.arg(grant_ids),sqlc.arg(created_at));

-- name: ReadApplicationVisitAuthority :many
SELECT client_id::text AS client_id,grant_id::text AS grant_id,key_id::text AS key_id,
    public_key::bytea AS public_key,expires_at::timestamptz AS expires_at
FROM control.application_visit_authority(sqlc.arg(resource_kind)::text,sqlc.arg(resource_id)::text,sqlc.arg(now)::timestamptz)
ORDER BY grant_id LIMIT 257;

-- name: CountApplicationVisitGrants :one
-- count dormant member grants too: restoring membership must not overflow policy.
SELECT count(*) FROM control.publisher_grants g
JOIN control.publisher_identities p ON p.id=g.publisher_identity_id
WHERE g.operation='visit' AND g.kind=sqlc.arg(kind)
    AND COALESCE(g.public_url_id,g.service_id)=sqlc.arg(resource_id)::text
    AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>sqlc.arg(now))
    AND p.revoked_at IS NULL;

-- name: ReadApplicationKeyAuthority :one
SELECT expires_at::timestamptz AS expires_at
FROM control.application_key_authority(sqlc.arg(publisher_identity_id)::text,sqlc.arg(key_id)::text,sqlc.arg(grant_id)::text,sqlc.arg(now)::timestamptz);

-- name: BoundPublishRunApplicationAuthority :one
UPDATE control.publish_runs SET publisher_expires_at=LEAST(publisher_expires_at,sqlc.arg(expires_at)::timestamptz)
WHERE id=sqlc.arg(id) AND closed_at IS NULL RETURNING *;
