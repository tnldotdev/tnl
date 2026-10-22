-- name: GetConnectorIngressAssignmentRequest :one
SELECT * FROM control.connector_ingress_assignment_requests
WHERE identity_id = sqlc.arg(identity_id) AND idempotency_key = sqlc.arg(idempotency_key);

-- name: InsertConnectorIngressAssignmentRequest :exec
INSERT INTO control.connector_ingress_assignment_requests(identity_id, idempotency_key,
    request_digest, result_ciphertext, storage_key_id, expires_at)
VALUES (sqlc.arg(identity_id), sqlc.arg(idempotency_key), sqlc.arg(request_digest),
    sqlc.arg(result_ciphertext), sqlc.arg(storage_key_id), sqlc.arg(expires_at));

-- name: CleanupConnectorIngressAssignmentRequests :exec
DELETE FROM control.connector_ingress_assignment_requests request
WHERE (request.identity_id, request.idempotency_key) IN (
    SELECT identity_id, idempotency_key FROM control.connector_ingress_assignment_requests
    WHERE expires_at <= sqlc.arg(now)::timestamptz - interval '24 hours'
    ORDER BY expires_at LIMIT 1000);
