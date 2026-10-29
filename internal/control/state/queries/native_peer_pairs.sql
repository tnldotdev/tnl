-- name: GetNativePeerPairForOwner :one
SELECT * FROM control.native_peer_pairs WHERE subject_kind=sqlc.arg(subject_kind)
    AND subject_id=sqlc.arg(subject_id) AND service_run_id=sqlc.arg(service_run_id)
    AND owner_key=sqlc.arg(owner_key) FOR UPDATE;

-- name: CountNativePeerPairOwners :one
SELECT count(*) FROM (
    SELECT id FROM control.native_peer_pairs WHERE service_run_id=sqlc.arg(service_run_id)
        AND (expires_at>sqlc.arg(now) OR replay_fence_until>sqlc.arg(now))
    LIMIT sqlc.arg(owner_limit)
) AS retained;

-- name: ListNativePeerPairCandidates :many
-- candidates convey no delivery authority. the publisher checks each delivery
-- separately after the exact relay claims have been accepted.
SELECT id,delivery_generation FROM control.native_peer_pairs
WHERE service_id=sqlc.arg(service_id) AND service_run_id=sqlc.arg(service_run_id)
    AND run_number=sqlc.arg(run_number) AND publisher_identity_id=sqlc.arg(publisher_identity_id)
    AND expires_at>sqlc.arg(now) AND id COLLATE "C">sqlc.arg(after_id) COLLATE "C"
ORDER BY id COLLATE "C" LIMIT 65;

-- name: ReplaceNativePeerPair :execrows
DELETE FROM control.native_peer_pairs WHERE id=sqlc.arg(id);

-- name: InsertNativePeerPair :one
INSERT INTO control.native_peer_pairs(id,service_id,service_run_id,run_number,publisher_identity_id,
    subject_kind,subject_id,parent_control_session_id,owner_key,idempotency_key,request_digest,key_digest,key_ciphertext,delivery_id,storage_key_id,slots,
    delivery_generation,created_at,last_authorized_at,last_request_at,replay_fence_until,expires_at)
VALUES (sqlc.arg(id),sqlc.arg(service_id),sqlc.arg(service_run_id),sqlc.arg(run_number),sqlc.arg(publisher_identity_id),
    sqlc.arg(subject_kind),sqlc.arg(subject_id),sqlc.narg(parent_control_session_id),sqlc.arg(owner_key),sqlc.arg(idempotency_key),sqlc.arg(request_digest),sqlc.arg(key_digest),sqlc.arg(key_ciphertext),sqlc.arg(delivery_id),
    sqlc.arg(storage_key_id),convert_from(sqlc.arg(slots)::bytea,'UTF8')::jsonb,nextval('control.native_peer_delivery_generation'),
    sqlc.arg(now),sqlc.arg(now),sqlc.arg(request_at),sqlc.arg(request_at)::timestamptz+interval '5 minutes',sqlc.arg(expires_at))
ON CONFLICT ON CONSTRAINT native_peer_pairs_delivery_id_key DO NOTHING RETURNING *;

-- name: LimitNativePeerPair :one
-- an uncertain delivery retry may only shorten the existing deadline.
UPDATE control.native_peer_pairs SET expires_at=LEAST(expires_at,sqlc.arg(authority_expires_at)),
    publisher_prepared_until=CASE WHEN publisher_prepared_until IS NOT NULL
        THEN LEAST(publisher_prepared_until,expires_at,sqlc.arg(authority_expires_at)) END
WHERE id=sqlc.arg(id) AND expires_at>sqlc.arg(now) AND last_authorized_at<=sqlc.arg(now)
    AND sqlc.arg(authority_expires_at)::timestamptz>sqlc.arg(now) RETURNING *;

-- name: RenewNativePeerPair :one
-- only a fresh signed renewal after the last successful authorization can
-- extend the same pair; an expired row never regains serving authority.
UPDATE control.native_peer_pairs SET expires_at=sqlc.arg(authority_expires_at),last_authorized_at=sqlc.arg(now),
    publisher_prepared_until=CASE WHEN publisher_prepared_until IS NOT NULL
        THEN LEAST(publisher_prepared_until,expires_at,sqlc.arg(authority_expires_at)) END,
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

-- name: RebindNativePeerPairRelays :one
-- a fresh owner-signed renewal may replace delivery carriers, not the pair key,
-- generation or source history. new claims must precede publisher installation.
UPDATE control.native_peer_pairs SET slots=convert_from(sqlc.arg(slots)::bytea,'UTF8')::jsonb,
    publisher_prepared_until=NULL WHERE id=sqlc.arg(id) RETURNING *;

-- name: FenceReplacedNativePeerPairLeg :exec
-- retain the last source, timestamp and nonce. a new process must prove a fresh
-- claim from that same source; assignment replacement never changes IP policy.
UPDATE control.native_peer_pair_leg_claims SET relay_id=sqlc.arg(relay_id),relay_run_id=sqlc.arg(relay_run_id),
    relay_lease_revision=sqlc.arg(relay_lease_revision),confirmed_until=sqlc.arg(now)
WHERE pair_id=sqlc.arg(pair_id) AND connection_slot=sqlc.arg(connection_slot);

-- name: LockNativePeerPairForLegClaim :one
SELECT * FROM control.native_peer_pairs WHERE id=sqlc.arg(id) FOR UPDATE;

-- name: ConfirmNativePeerPairPrepared :execrows
-- only a checked publisher report can advance this startup barrier. a retry
-- retains a newer report, capped by the currently checked delivery authority.
UPDATE control.native_peer_pairs
SET publisher_prepared_until=LEAST(sqlc.arg(authority_expires_at),GREATEST(publisher_prepared_until,sqlc.arg(binding_expires_at)))
WHERE id=sqlc.arg(id) AND delivery_generation=sqlc.arg(delivery_generation)
    AND expires_at>sqlc.arg(now);

-- name: SaveNativePeerPairLegClaim :one
-- two rows maximum per pair. an uncertain response requires a fresh proof from
-- the same observed source and the same relay process, never the old nonce.
INSERT INTO control.native_peer_pair_leg_claims(pair_id,connection_slot,requested_at,nonce_digest,source_ip,
    relay_id,relay_run_id,relay_lease_revision,checked_at,confirmed_until)
VALUES (sqlc.arg(pair_id),sqlc.arg(connection_slot),sqlc.arg(requested_at),sqlc.arg(nonce_digest),
    sqlc.arg(source_ip),sqlc.arg(relay_id),sqlc.arg(relay_run_id),sqlc.arg(relay_lease_revision),sqlc.arg(checked_at),sqlc.arg(confirmed_until))
ON CONFLICT (pair_id,connection_slot) DO UPDATE SET
    requested_at=EXCLUDED.requested_at,nonce_digest=EXCLUDED.nonce_digest,
    checked_at=EXCLUDED.checked_at,confirmed_until=EXCLUDED.confirmed_until
WHERE control.native_peer_pair_leg_claims.requested_at<EXCLUDED.requested_at
    AND control.native_peer_pair_leg_claims.nonce_digest<>EXCLUDED.nonce_digest
    AND control.native_peer_pair_leg_claims.source_ip=EXCLUDED.source_ip
    AND control.native_peer_pair_leg_claims.relay_id=EXCLUDED.relay_id
    AND control.native_peer_pair_leg_claims.relay_run_id=EXCLUDED.relay_run_id
    AND control.native_peer_pair_leg_claims.relay_lease_revision=EXCLUDED.relay_lease_revision
RETURNING pair_id;

-- name: LimitNativePeerPreparedForClaim :exec
-- a fresh claim may shorten a prior installation, never silently grow it.
UPDATE control.native_peer_pairs SET publisher_prepared_until=sqlc.arg(confirmed_until)
WHERE id=sqlc.arg(pair_id) AND publisher_prepared_until>sqlc.arg(confirmed_until);

-- name: ReadNativePeerClaimBounds :many
SELECT connection_slot,checked_at,confirmed_until,source_ip,relay_id,relay_run_id,relay_lease_revision
FROM control.native_peer_pair_leg_claims WHERE pair_id=sqlc.arg(pair_id)
ORDER BY connection_slot LIMIT 2;

-- name: ReadNativePeerObservationRelayBounds :many
-- relay leases are current-state recheck deadlines, not pair renewals.
SELECT slot.connection_slot,lease.lease_expires_at,relay.relay_address,relay.tls_server_name
FROM control.service_connection_slots slot
JOIN control.relay_leases lease ON lease.relay_id=slot.relay_id AND lease.relay_run_id=slot.relay_run_id
    AND lease.relay_lease_revision=slot.relay_lease_revision AND lease.relay_service_id=slot.relay_service_id
JOIN control.relay_services relay ON relay.relay_service_id=lease.relay_service_id
WHERE slot.service_run_id=sqlc.arg(service_run_id) AND slot.service_id=sqlc.arg(service_id)
    AND slot.state='ready' AND slot.session_open AND NOT lease.draining AND relay.enabled
    AND lease.lease_expires_at>sqlc.arg(now)
ORDER BY slot.connection_slot LIMIT 2 FOR SHARE OF lease,relay;
