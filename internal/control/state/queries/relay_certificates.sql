-- name: ClaimRelayServiceForCertificateOrder :one
SELECT services.*
FROM control.relay_services AS services
WHERE services.enabled
  AND (
      services.transport_certificate_expires_at IS NULL
      OR EXISTS (
          SELECT 1
          FROM control.relay_certificate_orders AS completed
          WHERE completed.relay_service_id = services.relay_service_id
            AND completed.state = 'complete'
            AND completed.certificate_pem = convert_to(services.transport_certificate_pem, 'UTF8')
            AND completed.renew_at <= sqlc.arg(now)
      )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM control.relay_certificate_orders AS orders
      WHERE orders.relay_service_id = services.relay_service_id
        AND orders.state NOT IN ('complete', 'failed')
  )
  AND NOT EXISTS (
      SELECT 1
      FROM control.relay_certificate_orders AS recent
      WHERE recent.relay_service_id = services.relay_service_id
        AND recent.state = 'failed'
        AND recent.updated_at > sqlc.arg(retry_failed_after)
  )
ORDER BY services.transport_certificate_expires_at NULLS FIRST, services.relay_service_id
FOR UPDATE SKIP LOCKED
LIMIT 1;

-- name: InsertRelayCertificateOrder :one
INSERT INTO control.relay_certificate_orders (
    id,
    account_id,
    relay_service_id,
    tls_server_name,
    private_key_ciphertext,
    private_key_storage_key_id,
    csr_der,
    csr_digest,
    state,
    available_at,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(account_id),
    sqlc.arg(relay_service_id),
    sqlc.arg(tls_server_name),
    sqlc.arg(private_key_ciphertext),
    sqlc.arg(private_key_storage_key_id),
    sqlc.arg(csr_der),
    sqlc.arg(csr_digest),
    'pending',
    sqlc.arg(created_at),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
)
RETURNING *;

-- name: ClaimRelayCertificateOrderWork :one
WITH candidate AS (
    SELECT id
    FROM control.relay_certificate_orders
    WHERE state NOT IN ('complete', 'failed')
      AND available_at <= sqlc.arg(claimed_at)
      AND (work_owner IS NULL OR work_expires_at <= sqlc.arg(claimed_at))
    ORDER BY available_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE control.relay_certificate_orders AS orders
SET work_owner = sqlc.arg(work_owner),
    work_epoch = orders.work_epoch + 1,
    work_expires_at = sqlc.arg(work_expires_at),
    attempts = orders.attempts + 1,
    updated_at = GREATEST(orders.updated_at, sqlc.arg(claimed_at))
FROM candidate
WHERE orders.id = candidate.id
RETURNING orders.*;

-- name: SaveRelayCertificateOrderWork :one
UPDATE control.relay_certificate_orders
SET state = sqlc.arg(state),
    order_revision = order_revision + 1,
    order_url = sqlc.narg(order_url),
    finalize_url = sqlc.narg(finalize_url),
    certificate_url = sqlc.narg(certificate_url),
    authorization_url = sqlc.narg(authorization_url),
    authorization_expires_at = sqlc.narg(authorization_expires_at),
    challenge_url = sqlc.narg(challenge_url),
    challenge_token = sqlc.narg(challenge_token),
    challenge_digest = sqlc.narg(challenge_digest),
    presentation_reference = sqlc.narg(presentation_reference),
    certificate_pem = sqlc.narg(certificate_pem),
    not_before = sqlc.narg(not_before),
    not_after = sqlc.narg(not_after),
    renew_at = sqlc.narg(renew_at),
    available_at = sqlc.arg(available_at),
    last_error = sqlc.narg(last_error),
    work_owner = NULL,
    work_expires_at = NULL,
    updated_at = sqlc.arg(completed_at)
WHERE id = sqlc.arg(order_id)
  AND work_owner = sqlc.arg(work_owner)
  AND work_epoch = sqlc.arg(work_epoch)
  AND work_expires_at > sqlc.arg(completed_at)
  AND order_revision = sqlc.arg(expected_order_revision)
RETURNING *;

-- name: GetRelayDNSChallengeContext :one
SELECT id, relay_service_id, tls_server_name, state, challenge_digest, presentation_reference
FROM control.relay_certificate_orders
WHERE id = sqlc.arg(order_id)
  AND challenge_digest IS NOT NULL;

-- name: ListRelayDNSChallengePresentations :many
SELECT challenge_digest, state
FROM control.relay_certificate_orders
WHERE tls_server_name = sqlc.arg(tls_server_name)
  AND challenge_digest IS NOT NULL
ORDER BY id;

-- name: RotateRelayCertificateOrderPrivateKey :exec
UPDATE control.relay_certificate_orders
SET private_key_ciphertext = sqlc.arg(private_key_ciphertext),
    private_key_storage_key_id = sqlc.arg(private_key_storage_key_id),
    updated_at = GREATEST(updated_at, sqlc.arg(updated_at))
WHERE id = sqlc.arg(order_id)
  AND private_key_storage_key_id = sqlc.arg(previous_key_id)
  AND private_key_ciphertext = sqlc.arg(previous_ciphertext);
