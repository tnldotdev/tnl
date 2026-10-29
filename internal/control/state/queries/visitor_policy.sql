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
