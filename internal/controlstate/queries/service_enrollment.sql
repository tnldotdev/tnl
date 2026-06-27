-- name: GetServiceAuthority :one
SELECT *
FROM control.service_authorities
WHERE singleton;

-- name: InitializeServiceAuthority :one
WITH initialized AS (
    INSERT INTO control.service_authorities (
        singleton,
        certificate_pem,
        private_key_der,
        certificate_serial,
        created_at,
        expires_at
    ) VALUES (
        true,
        sqlc.arg(certificate_pem),
        sqlc.arg(private_key_der),
        sqlc.arg(certificate_serial),
        sqlc.arg(created_at),
        sqlc.arg(expires_at)
    )
    ON CONFLICT (singleton) DO UPDATE SET
        singleton = EXCLUDED.singleton
    RETURNING *
)
SELECT * FROM initialized
UNION ALL
SELECT * FROM control.service_authorities WHERE singleton
LIMIT 1;

-- name: CreateRelayService :one
INSERT INTO control.relay_services (
    relay_service_id,
    relay_address,
    tls_server_name,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(relay_service_id),
    sqlc.arg(relay_address),
    sqlc.arg(tls_server_name),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
)
ON CONFLICT (relay_service_id) DO UPDATE SET
    updated_at = EXCLUDED.updated_at
WHERE control.relay_services.relay_address = EXCLUDED.relay_address
  AND control.relay_services.tls_server_name = EXCLUDED.tls_server_name
  AND control.relay_services.enabled
RETURNING *;

-- name: CreateServiceEnrollmentToken :one
INSERT INTO control.service_enrollment_tokens (
    id,
    lookup_id,
    token_digest,
    role,
    relay_service_id,
    created_by_identity_id,
    created_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(lookup_id),
    sqlc.arg(token_digest),
    sqlc.arg(role),
    sqlc.narg(relay_service_id),
    sqlc.arg(created_by_identity_id),
    sqlc.arg(created_at)
)
RETURNING *;

-- name: ListServiceEnrollmentTokens :many
SELECT *
FROM control.service_enrollment_tokens
ORDER BY created_at DESC, id DESC;

-- name: RevokeServiceEnrollmentToken :one
UPDATE control.service_enrollment_tokens
SET revoked_at = COALESCE(revoked_at, sqlc.arg(revoked_at)),
    revoked_by_identity_id = COALESCE(revoked_by_identity_id, sqlc.arg(revoked_by_identity_id))
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: CreateServiceEnrollmentAdminAuditEvent :exec
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
    sqlc.arg(actor),
    sqlc.arg(request_id),
    sqlc.arg(operation),
    'service_enrollment_token',
    sqlc.arg(target_id),
    sqlc.arg(occurred_at)
)
ON CONFLICT (request_id, operation, target_kind, target_id) DO NOTHING;

-- name: LockServiceEnrollmentToken :one
SELECT tokens.*,
       services.relay_address,
       services.tls_server_name
FROM control.service_enrollment_tokens AS tokens
LEFT JOIN control.relay_services AS services USING (relay_service_id)
WHERE tokens.lookup_id = sqlc.arg(lookup_id)
FOR UPDATE OF tokens;

-- name: RecordServiceEnrollmentUse :exec
UPDATE control.service_enrollment_tokens
SET last_used_at = sqlc.arg(last_used_at),
    last_used_process_id = sqlc.arg(last_used_process_id),
    use_count = use_count + 1
WHERE id = sqlc.arg(id);

-- name: CreateServiceEnrollmentEvent :exec
INSERT INTO control.service_enrollment_events (
    service_enrollment_token_id,
    role,
    process_id,
    relay_service_id,
    certificate_serial,
    certificate_expires_at,
    occurred_at
) VALUES (
    sqlc.arg(service_enrollment_token_id),
    sqlc.arg(role),
    sqlc.arg(process_id),
    sqlc.narg(relay_service_id),
    sqlc.arg(certificate_serial),
    sqlc.arg(certificate_expires_at),
    sqlc.arg(occurred_at)
);

-- name: LockRelayServiceTransport :one
SELECT *
FROM control.relay_services
WHERE relay_service_id = sqlc.arg(relay_service_id)
  AND enabled
FOR UPDATE;

-- name: SetRelayServiceTransport :one
UPDATE control.relay_services
SET transport_certificate_pem = sqlc.arg(transport_certificate_pem),
    transport_private_key_pem = sqlc.arg(transport_private_key_pem),
    transport_certificate_serial = sqlc.arg(transport_certificate_serial),
    transport_certificate_expires_at = sqlc.arg(transport_certificate_expires_at),
    updated_at = sqlc.arg(updated_at)
WHERE relay_service_id = sqlc.arg(relay_service_id)
  AND enabled
RETURNING *;
