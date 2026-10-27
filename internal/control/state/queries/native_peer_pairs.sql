-- name: GetNativePeerPair :one
SELECT * FROM control.native_peer_pairs WHERE subject_kind=sqlc.arg(subject_kind)
    AND subject_id=sqlc.arg(subject_id) AND service_run_id=sqlc.arg(service_run_id) FOR UPDATE;

-- name: ReplaceNativePeerPair :execrows
DELETE FROM control.native_peer_pairs WHERE id=sqlc.arg(id);

-- name: InsertNativePeerPair :one
INSERT INTO control.native_peer_pairs(id,service_id,service_run_id,run_number,publisher_identity_id,
    subject_kind,subject_id,idempotency_key,request_digest,key_digest,key_ciphertext,storage_key_id,slots,
    delivery_generation,created_at,last_authorized_at,last_request_at,replay_fence_until,expires_at)
VALUES (sqlc.arg(id),sqlc.arg(service_id),sqlc.arg(service_run_id),sqlc.arg(run_number),sqlc.arg(publisher_identity_id),
    sqlc.arg(subject_kind),sqlc.arg(subject_id),sqlc.arg(idempotency_key),sqlc.arg(request_digest),sqlc.arg(key_digest),sqlc.arg(key_ciphertext),
    sqlc.arg(storage_key_id),convert_from(sqlc.arg(slots)::bytea,'UTF8')::jsonb,nextval('control.native_peer_delivery_generation'),
    sqlc.arg(now),sqlc.arg(now),sqlc.arg(request_at),sqlc.arg(request_at)::timestamptz+interval '5 minutes',sqlc.arg(expires_at)) RETURNING *;

-- name: LimitNativePeerPair :one
-- an uncertain delivery retry may only shorten the existing deadline.
UPDATE control.native_peer_pairs SET expires_at=LEAST(expires_at,sqlc.arg(authority_expires_at))
WHERE id=sqlc.arg(id) AND expires_at>sqlc.arg(now) AND last_authorized_at<=sqlc.arg(now)
    AND sqlc.arg(authority_expires_at)::timestamptz>sqlc.arg(now) RETURNING *;

-- name: RenewNativePeerPair :one
-- only a fresh signed renewal after the last successful authorization can
-- extend the same pair; an expired row never regains serving authority.
UPDATE control.native_peer_pairs SET expires_at=sqlc.arg(authority_expires_at),last_authorized_at=sqlc.arg(now),
    last_request_at=sqlc.arg(request_at),replay_fence_until=sqlc.arg(request_at)::timestamptz+interval '5 minutes',
    last_renewal_digest=sqlc.arg(renewal_digest)
WHERE id=sqlc.arg(id) AND expires_at>sqlc.arg(now) AND last_authorized_at<sqlc.arg(now)
    AND last_request_at<sqlc.arg(request_at) AND sqlc.arg(authority_expires_at)::timestamptz>sqlc.arg(now) RETURNING *;

-- name: CleanupExpiredNativePeerPairs :execrows
DELETE FROM control.native_peer_pairs victim WHERE victim.id IN (
    SELECT candidate.id FROM control.native_peer_pairs candidate WHERE candidate.expires_at<=sqlc.arg(now)
        AND candidate.replay_fence_until<=sqlc.arg(now)
    ORDER BY candidate.expires_at,candidate.id LIMIT sqlc.arg(batch_size) FOR UPDATE OF candidate SKIP LOCKED
);
