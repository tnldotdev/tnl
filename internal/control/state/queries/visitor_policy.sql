-- name: ReadVisitorPolicyRevision :one
SELECT revision FROM control.visitor_policies WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id);

-- name: ReadVisitorPolicyEvents :many
SELECT revision,changed_at FROM control.visitor_policy_events
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id) AND revision>sqlc.arg(after_revision)
ORDER BY revision LIMIT 256;

-- name: ReadVisitorVerificationKeyRevision :one
SELECT revision FROM control.visitor_verification_key_revision WHERE id=1;

-- name: ReadVisitorTokenIssuer :one
SELECT issuer FROM control.visitor_token_issuer WHERE id;

-- name: ReadVisitorPolicyService :one
SELECT * FROM control.services WHERE id=sqlc.arg(id);

-- name: ReadVisitorShareVerifiers :many
SELECT authority.share_id::text AS share_id,authority.secret_digest::bytea AS secret_digest,authority.expires_at::timestamptz AS expires_at
FROM control.visitor_share_authority(sqlc.arg(public_url_id)::text,sqlc.arg(now)::timestamptz) authority
ORDER BY share_id LIMIT 257;

-- name: LockVisitorShareAuthority :one
SELECT authority.secret_digest::bytea AS secret_digest,authority.expires_at::timestamptz AS expires_at
FROM control.visitor_share_authority(sqlc.arg(public_url_id)::text,sqlc.arg(now)::timestamptz) authority
JOIN control.shares share ON share.id=authority.share_id
WHERE share.id=sqlc.arg(share_id) FOR SHARE OF share;

-- name: ReadVisitorGrantVerifiers :many
SELECT authority.grant_id::text AS grant_id,authority.kind::text AS kind,authority.secret_digest::bytea AS secret_digest,authority.expires_at::timestamptz AS expires_at
FROM control.visitor_service_grant_authority(sqlc.arg(service_id)::text,sqlc.arg(now)::timestamptz) authority
ORDER BY grant_id LIMIT 257;

-- name: LockVisitorGrantAuthority :one
SELECT authority.kind::text AS kind,authority.secret_digest::bytea AS secret_digest,authority.expires_at::timestamptz AS expires_at
FROM control.visitor_service_grant_authority(sqlc.arg(service_id)::text,sqlc.arg(now)::timestamptz) authority
JOIN control.service_http_grants credential ON credential.id=authority.grant_id
WHERE credential.id=sqlc.arg(grant_id) FOR SHARE OF credential;
