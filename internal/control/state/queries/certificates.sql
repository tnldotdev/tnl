-- name: EnsureACMEAccount :one
INSERT INTO control.acme_accounts (
    id,
    directory_url,
    contact_email,
    account_key_ciphertext,
    account_key_storage_key_id,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(directory_url),
    sqlc.arg(contact_email),
    sqlc.arg(account_key_ciphertext),
    sqlc.arg(account_key_storage_key_id),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
)
ON CONFLICT (directory_url) DO UPDATE
SET contact_email = excluded.contact_email,
    updated_at = GREATEST(control.acme_accounts.updated_at, excluded.updated_at)
RETURNING *;

-- name: GetManagedCertificateDomainKind :one
SELECT kind FROM control.domains WHERE id=sqlc.arg(domain_id);

-- name: RotateACMEAccountKey :exec
UPDATE control.acme_accounts
SET account_key_ciphertext = sqlc.arg(account_key_ciphertext),
    account_key_storage_key_id = sqlc.arg(account_key_storage_key_id),
    updated_at = GREATEST(updated_at, sqlc.arg(updated_at))
WHERE id = sqlc.arg(account_id)
  AND account_key_storage_key_id = sqlc.arg(previous_key_id)
  AND account_key_ciphertext = sqlc.arg(previous_ciphertext);

-- name: GetACMEAccountByDirectory :one
SELECT *
FROM control.acme_accounts
WHERE directory_url = sqlc.arg(directory_url);

-- name: UpdateACMEAccountRegistration :one
UPDATE control.acme_accounts
SET contact_email = sqlc.arg(contact_email),
    account_url = sqlc.arg(account_url),
    accepted_terms_url = sqlc.arg(accepted_terms_url),
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(account_id)
RETURNING *;

-- name: LockCertificateIssuanceControl :one
SELECT allowed
FROM control.maintenance_controls
WHERE operation = 'certificate_issuance'
FOR SHARE;

-- name: GetACMEOrder :one
SELECT *
FROM control.acme_orders
WHERE id = sqlc.arg(issuance_id);

-- name: LockACMEOrder :one
SELECT *
FROM control.acme_orders
WHERE id = sqlc.arg(issuance_id)
FOR UPDATE;

-- name: ListACMEOrderAuthorizations :many
SELECT *
FROM control.acme_authorizations
WHERE order_id = sqlc.arg(issuance_id)
ORDER BY identifier;

-- name: MarkACMEOrderInstalled :one
UPDATE control.acme_orders
SET state = 'installed',
    installed_at = COALESCE(installed_at, sqlc.arg(installed_at)),
    order_revision = order_revision + CASE WHEN installed_at IS NULL THEN 1 ELSE 0 END,
    -- the first installation fences the old work revision. release that claim
    -- so DNS cleanup can resume immediately; repeated acknowledgments leave a
    -- current cleanup worker's lease intact.
    work_owner = CASE WHEN installed_at IS NULL THEN NULL ELSE work_owner END,
    work_expires_at = CASE WHEN installed_at IS NULL THEN NULL ELSE work_expires_at END,
    updated_at = GREATEST(updated_at, sqlc.arg(installed_at))
WHERE id = sqlc.arg(issuance_id)
  AND state IN ('waiting_for_install', 'installed')
RETURNING *;

-- name: InsertCertificateIssuanceAuditEvent :exec
INSERT INTO control.admin_audit_events (
    actor_identity_id,
    actor,
    request_id,
    operation,
    target_kind,
    target_id,
    occurred_at
) VALUES (
    sqlc.arg(actor_identity_id),
    sqlc.arg(actor_identity_id),
    sqlc.arg(request_id),
    'certificate_issuance.create',
    'certificate_issuance',
    sqlc.arg(issuance_id),
    sqlc.arg(occurred_at)
);

-- name: ClaimACMEOrderWork :one
WITH candidate AS (
    SELECT orders.id
    FROM control.acme_orders AS orders
    WHERE (
          orders.state IN ('pending', 'authorizing', 'ready_to_finalize', 'finalizing')
          OR orders.state IN ('waiting_for_install', 'installed') AND EXISTS (
              SELECT 1
              FROM control.acme_authorizations AS authorizations
              WHERE authorizations.order_id = orders.id
                AND authorizations.challenge_type = 'dns-01'
                AND authorizations.state IN ('valid', 'cleaning')
          )
          OR orders.state IN ('failed', 'canceled') AND (orders.finalization_possible AND orders.not_after IS NULL OR EXISTS (
              SELECT 1
              FROM control.acme_authorizations AS authorizations
              WHERE authorizations.order_id = orders.id
                AND authorizations.challenge_type = 'dns-01'
                AND authorizations.state = 'cleaning'
          ))
      )
      AND orders.available_at <= sqlc.arg(claimed_at)
      AND (orders.retry_not_before IS NULL OR orders.retry_not_before<=sqlc.arg(claimed_at))
      AND (orders.work_owner IS NULL OR orders.work_expires_at <= sqlc.arg(claimed_at))
    ORDER BY orders.available_at, orders.id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE control.acme_orders AS orders
SET work_owner = sqlc.arg(work_owner),
    work_epoch = orders.work_epoch + 1,
    work_expires_at = sqlc.arg(work_expires_at),
    attempts = orders.attempts + 1,
    updated_at = GREATEST(orders.updated_at, sqlc.arg(claimed_at))
FROM candidate
WHERE orders.id = candidate.id
RETURNING orders.*;

-- name: SaveACMEOrderWork :one
UPDATE control.acme_orders
SET state = sqlc.arg(state),
    order_revision = order_revision + 1,
    order_url = sqlc.narg(order_url),
    finalize_url = sqlc.narg(finalize_url),
    finalization_possible = sqlc.arg(finalization_possible) OR sqlc.arg(state)::text IN ('ready_to_finalize','finalizing'),
    certificate_url = sqlc.narg(certificate_url),
    certificate_pem = sqlc.narg(certificate_pem),
    not_before = sqlc.narg(not_before),
    not_after = sqlc.narg(not_after),
    renew_at = sqlc.narg(renew_at),
    available_at = sqlc.arg(available_at),
    last_error = sqlc.narg(last_error),
    retry_not_before=CASE WHEN sqlc.narg(last_error)::text IS NOT NULL AND sqlc.arg(available_at)::timestamptz>sqlc.arg(completed_at)::timestamptz
        THEN sqlc.arg(available_at)::timestamptz ELSE NULL END,
    work_owner = NULL,
    work_expires_at = NULL,
    updated_at = sqlc.arg(completed_at)
WHERE id = sqlc.arg(issuance_id)
  AND work_owner = sqlc.arg(work_owner)
  AND work_epoch = sqlc.arg(work_epoch)
  AND work_expires_at > sqlc.arg(completed_at)
  AND order_revision = sqlc.arg(expected_order_revision)
RETURNING *;

-- name: SaveACMEAuthorizationWork :one
INSERT INTO control.acme_authorizations (
    id,
    order_id,
    identifier,
    authorization_url,
    challenge_type,
    challenge_url,
    challenge_token,
    challenge_digest,
    presentation_reference,
    state,
    authorization_revision,
    attempts,
    available_at,
    presented_at,
    validated_at,
    cleanup_completed_at,
    expires_at,
    last_error,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(order_id),
    sqlc.arg(identifier),
    sqlc.arg(authorization_url),
    sqlc.narg(challenge_type),
    sqlc.narg(challenge_url),
    sqlc.narg(challenge_token),
    sqlc.narg(challenge_digest),
    sqlc.narg(presentation_reference),
    sqlc.arg(state),
    sqlc.arg(authorization_revision),
    sqlc.arg(attempts),
    sqlc.arg(available_at),
    sqlc.narg(presented_at),
    sqlc.narg(validated_at),
    sqlc.narg(cleanup_completed_at),
    sqlc.narg(expires_at),
    sqlc.narg(last_error),
    sqlc.arg(created_at),
    sqlc.arg(updated_at)
)
ON CONFLICT (order_id, identifier) DO UPDATE
SET state = excluded.state,
    authorization_revision = control.acme_authorizations.authorization_revision + 1,
    attempts = excluded.attempts,
    available_at = excluded.available_at,
    presented_at = excluded.presented_at,
    validated_at = excluded.validated_at,
    cleanup_completed_at = excluded.cleanup_completed_at,
    expires_at = excluded.expires_at,
    last_error = excluded.last_error,
    updated_at = excluded.updated_at
WHERE control.acme_authorizations.authorization_url = excluded.authorization_url
  AND control.acme_authorizations.challenge_type IS NOT DISTINCT FROM excluded.challenge_type
  AND control.acme_authorizations.challenge_url IS NOT DISTINCT FROM excluded.challenge_url
  AND control.acme_authorizations.challenge_token IS NOT DISTINCT FROM excluded.challenge_token
  AND control.acme_authorizations.challenge_digest IS NOT DISTINCT FROM excluded.challenge_digest
  AND control.acme_authorizations.presentation_reference IS NOT DISTINCT FROM excluded.presentation_reference
  AND control.acme_authorizations.authorization_revision = sqlc.arg(expected_authorization_revision)
RETURNING *;
