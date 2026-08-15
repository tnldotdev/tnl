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

-- name: GetControlTLSCacheEntry :one
SELECT cache_ciphertext, cache_storage_key_id
FROM control.control_tls_cache
WHERE directory_url = sqlc.arg(directory_url)
  AND cache_key = sqlc.arg(cache_key);

-- name: PutControlTLSCacheEntry :exec
INSERT INTO control.control_tls_cache (
    directory_url,
    cache_key,
    cache_ciphertext,
    cache_storage_key_id,
    updated_at
) VALUES (
    sqlc.arg(directory_url),
    sqlc.arg(cache_key),
    sqlc.arg(cache_ciphertext),
    sqlc.arg(cache_storage_key_id),
    sqlc.arg(updated_at)
)
ON CONFLICT (directory_url, cache_key) DO UPDATE SET
    cache_ciphertext = EXCLUDED.cache_ciphertext,
    cache_storage_key_id = EXCLUDED.cache_storage_key_id,
    updated_at = EXCLUDED.updated_at;

-- name: RotateControlTLSCacheEntry :exec
UPDATE control.control_tls_cache
SET cache_ciphertext = sqlc.arg(cache_ciphertext),
    cache_storage_key_id = sqlc.arg(cache_storage_key_id),
    updated_at = sqlc.arg(updated_at)
WHERE directory_url = sqlc.arg(directory_url)
  AND cache_key = sqlc.arg(cache_key)
  AND cache_storage_key_id = sqlc.arg(previous_key_id)
  AND cache_ciphertext = sqlc.arg(previous_ciphertext);

-- name: DeleteControlTLSCacheEntry :exec
DELETE FROM control.control_tls_cache
WHERE directory_url = sqlc.arg(directory_url)
  AND cache_key = sqlc.arg(cache_key);

-- name: GetRouteSessionByTokenID :one
SELECT *
FROM control.route_sessions
WHERE session_token_id = sqlc.arg(session_token_id);

-- name: GetACMEOrderByIdempotency :one
SELECT *
FROM control.acme_orders
WHERE route_session_id = sqlc.arg(route_session_id)
  AND idempotency_key = sqlc.arg(idempotency_key);

-- name: LockCertificateIssuanceControl :one
SELECT allowed
FROM control.maintenance_controls
WHERE control_name = 'certificate_issuance'
FOR SHARE;

-- name: InsertACMEOrder :one
INSERT INTO control.acme_orders (
    id,
    account_id,
    route_session_id,
    route_id,
    route_version,
    idempotency_key,
    request_digest,
    certificate_cache_key,
    certificate_scope,
    certificate_identifiers,
    challenge_method,
    csr_der,
    csr_digest,
    state,
    available_at,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(account_id),
    sqlc.arg(route_session_id),
    sqlc.arg(route_id),
    sqlc.arg(route_version),
    sqlc.arg(idempotency_key),
    sqlc.arg(request_digest),
    sqlc.arg(certificate_cache_key),
    sqlc.arg(certificate_scope),
    sqlc.arg(certificate_identifiers),
    sqlc.arg(challenge_method),
    sqlc.arg(csr_der),
    sqlc.arg(csr_digest),
    'pending',
    sqlc.arg(created_at),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
)
RETURNING *;

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

-- name: MarkACMEAuthorizationsPresented :execrows
UPDATE control.acme_authorizations
SET state = 'presented',
    authorization_revision = authorization_revision + 1,
    presented_at = COALESCE(presented_at, sqlc.arg(presented_at)),
    available_at = sqlc.arg(presented_at),
    updated_at = GREATEST(updated_at, sqlc.arg(presented_at))
WHERE order_id = sqlc.arg(issuance_id)
  AND challenge_type = 'tls-alpn-01'
  AND state = 'presenting';

-- name: WakeACMEOrder :exec
UPDATE control.acme_orders
SET available_at = LEAST(available_at, sqlc.arg(available_at)),
    updated_at = GREATEST(updated_at, sqlc.arg(available_at))
WHERE id = sqlc.arg(issuance_id)
  AND state IN ('authorizing', 'ready_to_finalize', 'finalizing');

-- name: CompleteACMEAuthorizationCleanup :execrows
UPDATE control.acme_authorizations
SET state = 'complete',
    authorization_revision = authorization_revision + 1,
    cleanup_completed_at = COALESCE(cleanup_completed_at, sqlc.arg(completed_at)),
    updated_at = GREATEST(updated_at, sqlc.arg(completed_at))
WHERE order_id = sqlc.arg(issuance_id)
  AND challenge_type = 'tls-alpn-01'
  AND state IN ('presenting', 'presented', 'validating', 'valid', 'cleaning', 'failed');

-- name: GetActiveRouteSessionChallengeExpiry :one
SELECT MIN(authorizations.expires_at)::timestamptz AS expires_at
FROM control.acme_authorizations AS authorizations
JOIN control.acme_orders AS orders ON orders.id = authorizations.order_id
WHERE orders.route_session_id = sqlc.arg(route_session_id)
  AND authorizations.challenge_type = 'tls-alpn-01'
  AND authorizations.state IN ('presenting', 'presented', 'validating', 'valid', 'cleaning')
  AND authorizations.expires_at > sqlc.arg(now);

-- name: LockACMEOrderForInstall :one
SELECT orders.*
FROM control.acme_orders AS orders
JOIN control.route_sessions AS issued_session
  ON issued_session.id = orders.route_session_id
 AND issued_session.route_id = orders.route_id
 AND issued_session.route_version = orders.route_version
WHERE orders.id = sqlc.arg(issuance_id)
  AND issued_session.team_id = sqlc.arg(team_id)
  AND orders.certificate_cache_key = sqlc.arg(certificate_cache_key)
  AND orders.certificate_scope = sqlc.arg(certificate_scope)
  AND orders.certificate_identifiers = sqlc.arg(certificate_identifiers)
  AND orders.challenge_method = sqlc.arg(challenge_method)
  AND orders.state IN ('waiting_for_install', 'installed')
  AND orders.certificate_pem IS NOT NULL
  AND orders.not_before <= sqlc.arg(installed_at)
  AND orders.not_after = sqlc.arg(not_after)
  AND orders.not_after > sqlc.arg(installed_at)
FOR UPDATE OF orders;

-- name: MarkACMEOrderInstalled :one
UPDATE control.acme_orders
SET state = 'installed',
    installed_at = COALESCE(installed_at, sqlc.arg(installed_at)),
    order_revision = order_revision + CASE WHEN installed_at IS NULL THEN 1 ELSE 0 END,
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
          OR orders.state IN ('failed', 'canceled') AND EXISTS (
              SELECT 1
              FROM control.acme_authorizations AS authorizations
              WHERE authorizations.order_id = orders.id
                AND authorizations.challenge_type = 'dns-01'
                AND authorizations.state = 'cleaning'
          )
      )
      AND orders.available_at <= sqlc.arg(claimed_at)
      AND (orders.work_owner IS NULL OR orders.work_expires_at <= sqlc.arg(claimed_at))
      -- ACME validation can begin only after every live ingress process has the challenge route.
      AND (
          NOT EXISTS (
              SELECT 1
              FROM control.acme_authorizations AS authorizations
              WHERE authorizations.order_id = orders.id
                AND authorizations.challenge_type = 'tls-alpn-01'
                AND authorizations.state = 'presented'
          )
          OR EXISTS (
              SELECT 1
              FROM control.ingress_leases AS ingresses
              WHERE ingresses.lease_expires_at > sqlc.arg(claimed_at)
                AND NOT ingresses.draining
          ) AND NOT EXISTS (
              SELECT 1
              FROM control.ingress_leases AS ingresses
              CROSS JOIN control.ingress_routing_table_clock AS clock
              WHERE ingresses.lease_expires_at > sqlc.arg(claimed_at)
                AND NOT ingresses.draining
                AND ingresses.routing_table_revision < clock.current_revision
          )
      )
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
    certificate_url = sqlc.narg(certificate_url),
    certificate_pem = sqlc.narg(certificate_pem),
    not_before = sqlc.narg(not_before),
    not_after = sqlc.narg(not_after),
    renew_at = sqlc.narg(renew_at),
    available_at = sqlc.arg(available_at),
    last_error = sqlc.narg(last_error),
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

-- name: CancelRouteSessionACMEOrders :exec
UPDATE control.acme_orders
SET state = 'canceled',
    order_revision = order_revision + 1,
    work_owner = NULL,
    work_expires_at = NULL,
    available_at = sqlc.arg(canceled_at),
    updated_at = GREATEST(updated_at, sqlc.arg(canceled_at))
WHERE route_session_id = sqlc.arg(route_session_id)
  AND certificate_pem IS NULL
  AND state IN ('pending', 'authorizing', 'ready_to_finalize', 'finalizing', 'failed');

-- name: CancelRouteSessionACMEAuthorizations :exec
UPDATE control.acme_authorizations AS authorizations
SET state = CASE
        WHEN challenge_type = 'dns-01' THEN 'cleaning'
        ELSE 'canceled'
    END,
    authorization_revision = authorization_revision + 1,
    cleanup_completed_at = CASE
        WHEN challenge_type = 'tls-alpn-01' THEN COALESCE(cleanup_completed_at, sqlc.arg(canceled_at))
        ELSE cleanup_completed_at
    END,
    available_at = sqlc.arg(canceled_at),
    updated_at = GREATEST(authorizations.updated_at, sqlc.arg(canceled_at))
FROM control.acme_orders AS orders
WHERE orders.id = authorizations.order_id
  AND orders.route_session_id = sqlc.arg(route_session_id)
  AND authorizations.state NOT IN ('complete', 'canceled');
