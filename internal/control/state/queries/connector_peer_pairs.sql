-- name: GetConnectorPeerPairForOwner :one
SELECT * FROM control.connector_peer_pairs WHERE subject_kind=sqlc.arg(subject_kind)
    AND subject_id=sqlc.arg(subject_id) AND service_run_id=sqlc.arg(service_run_id)
    AND owner_key=sqlc.arg(owner_key) FOR UPDATE;

-- name: CountConnectorPeerPairOwners :one
SELECT count(*) FROM (
    SELECT id FROM control.connector_peer_pairs WHERE service_run_id=sqlc.arg(service_run_id)
        AND (expires_at>sqlc.arg(now) OR replay_fence_until>sqlc.arg(now))
    LIMIT sqlc.arg(owner_limit)
) AS retained;

-- name: ListConnectorPeerPairCandidates :many
-- candidates convey no delivery authority. the publisher checks each delivery
-- separately after the exact relay claims have been accepted.
SELECT id,CASE WHEN retired_at IS NOT NULL THEN high_water_generation ELSE
    COALESCE((SELECT pending.delivery_generation FROM control.connector_peer_pending_bindings pending
        WHERE pending.pair_id=connector_peer_pairs.id AND pending.pending_until>sqlc.arg(now)),delivery_generation)
    END::bigint AS delivery_generation,owner_revision,retired_at,
    GREATEST(expires_at,replay_fence_until)::timestamptz AS retained_until
FROM control.connector_peer_pairs
WHERE service_id=sqlc.arg(service_id) AND service_run_id=sqlc.arg(service_run_id)
    AND run_number=sqlc.arg(run_number) AND publisher_identity_id=sqlc.arg(publisher_identity_id)
    AND ((sqlc.arg(include_candidates)::boolean AND retired_at IS NULL AND expires_at>sqlc.arg(now))
        OR (retired_at IS NOT NULL AND GREATEST(expires_at,replay_fence_until)>sqlc.arg(now)))
    AND id COLLATE "C">sqlc.arg(after_id) COLLATE "C"
ORDER BY id COLLATE "C" LIMIT 65;

-- name: ReplaceConnectorPeerPair :execrows
DELETE FROM control.connector_peer_pairs WHERE id=sqlc.arg(id) AND retired_at IS NULL;

-- name: InsertConnectorPeerPair :one
INSERT INTO control.connector_peer_pairs(id,service_id,service_run_id,run_number,publisher_identity_id,
    subject_kind,subject_id,parent_control_session_id,owner_key,idempotency_key,owner_public_key,request_digest,key_digest,key_ciphertext,delivery_id,storage_key_id,slots,
    delivery_generation,created_at,last_authorized_at,last_request_at,replay_fence_until,expires_at)
VALUES (sqlc.arg(id),sqlc.arg(service_id),sqlc.arg(service_run_id),sqlc.arg(run_number),sqlc.arg(publisher_identity_id),
    sqlc.arg(subject_kind),sqlc.arg(subject_id),sqlc.narg(parent_control_session_id),sqlc.arg(owner_key),sqlc.arg(idempotency_key),sqlc.arg(owner_public_key),sqlc.arg(request_digest),sqlc.arg(key_digest),sqlc.arg(key_ciphertext),sqlc.arg(delivery_id),
    sqlc.arg(storage_key_id),convert_from(sqlc.arg(slots)::bytea,'UTF8')::jsonb,nextval('control.connector_peer_delivery_generation'),
    sqlc.arg(now),sqlc.arg(now),sqlc.arg(request_at),sqlc.arg(request_at)::timestamptz+interval '5 minutes',sqlc.arg(expires_at))
ON CONFLICT ON CONSTRAINT connector_peer_pairs_delivery_id_key DO NOTHING RETURNING *;

-- name: LimitConnectorPeerPair :one
-- an uncertain delivery retry may only shorten the existing deadline.
UPDATE control.connector_peer_pairs SET expires_at=LEAST(expires_at,sqlc.arg(authority_expires_at)),
    publisher_prepared_until=CASE WHEN publisher_prepared_until IS NOT NULL
        THEN LEAST(publisher_prepared_until,expires_at,sqlc.arg(authority_expires_at)) END
WHERE id=sqlc.arg(id) AND retired_at IS NULL AND expires_at>sqlc.arg(now) AND last_authorized_at<=sqlc.arg(now)
    AND sqlc.arg(authority_expires_at)::timestamptz>sqlc.arg(now) RETURNING *;

-- name: RenewConnectorPeerPair :one
-- only a fresh signed renewal after the last successful authorization can
-- extend the same pair; an expired row never regains serving authority.
UPDATE control.connector_peer_pairs SET expires_at=sqlc.arg(authority_expires_at),last_authorized_at=sqlc.arg(now),
    publisher_prepared_until=CASE WHEN publisher_prepared_until IS NOT NULL
        THEN LEAST(publisher_prepared_until,expires_at,sqlc.arg(authority_expires_at)) END,
    last_request_at=sqlc.arg(request_at),replay_fence_until=sqlc.arg(request_at)::timestamptz+interval '5 minutes',
    last_renewal_digest=sqlc.arg(renewal_digest)
WHERE id=sqlc.arg(id) AND retired_at IS NULL AND expires_at>sqlc.arg(now) AND last_authorized_at<sqlc.arg(now)
    AND last_request_at<sqlc.arg(request_at) AND sqlc.arg(authority_expires_at)::timestamptz>sqlc.arg(now) RETURNING *;

-- name: CleanupExpiredConnectorPeerPairs :execrows
DELETE FROM control.connector_peer_pairs victim WHERE victim.id IN (
    SELECT candidate.id FROM control.connector_peer_pairs candidate WHERE candidate.expires_at<=sqlc.arg(now)
        AND candidate.replay_fence_until<=sqlc.arg(now)
    ORDER BY candidate.expires_at,candidate.id LIMIT sqlc.arg(batch_size) FOR UPDATE OF candidate SKIP LOCKED
);

-- name: LockConnectorPeerPairForLegClaim :one
SELECT * FROM control.connector_peer_pairs WHERE id=sqlc.arg(id) FOR UPDATE;

-- name: ConfirmConnectorPeerPairPrepared :execrows
-- only a checked publisher report can advance this startup barrier. a retry
-- retains a newer report, capped by the currently checked delivery authority.
UPDATE control.connector_peer_pairs
SET publisher_prepared_until=LEAST(sqlc.arg(authority_expires_at),GREATEST(publisher_prepared_until,sqlc.arg(binding_expires_at)))
WHERE id=sqlc.arg(id) AND retired_at IS NULL AND delivery_generation=sqlc.arg(delivery_generation)
    AND expires_at>sqlc.arg(now);

-- name: SaveConnectorPeerPairLegClaim :one
-- two rows maximum per binding. an uncertain response requires a fresh proof from
-- the same observed source and the same relay process, never the old nonce.
INSERT INTO control.connector_peer_pair_leg_claims(pair_id,connection_slot,requested_at,nonce_digest,source_ip,
    relay_id,relay_run_id,relay_lease_revision,checked_at,confirmed_until,delivery_generation)
SELECT sqlc.arg(pair_id),sqlc.arg(connection_slot),sqlc.arg(requested_at),sqlc.arg(nonce_digest),
    sqlc.arg(source_ip),sqlc.arg(relay_id),sqlc.arg(relay_run_id),sqlc.arg(relay_lease_revision),sqlc.arg(checked_at),sqlc.arg(confirmed_until),sqlc.arg(delivery_generation)
FROM control.connector_peer_pairs pair WHERE pair.id=sqlc.arg(pair_id) AND pair.retired_at IS NULL
ON CONFLICT (pair_id,delivery_generation,connection_slot) DO UPDATE SET
    requested_at=EXCLUDED.requested_at,nonce_digest=EXCLUDED.nonce_digest,
    checked_at=EXCLUDED.checked_at,confirmed_until=EXCLUDED.confirmed_until
WHERE EXISTS(SELECT 1 FROM control.connector_peer_pairs pair WHERE pair.id=EXCLUDED.pair_id AND pair.retired_at IS NULL)
    AND control.connector_peer_pair_leg_claims.requested_at<EXCLUDED.requested_at
    AND control.connector_peer_pair_leg_claims.nonce_digest<>EXCLUDED.nonce_digest
    AND control.connector_peer_pair_leg_claims.source_ip=EXCLUDED.source_ip
    AND control.connector_peer_pair_leg_claims.relay_id=EXCLUDED.relay_id
    AND control.connector_peer_pair_leg_claims.relay_run_id=EXCLUDED.relay_run_id
    AND control.connector_peer_pair_leg_claims.relay_lease_revision=EXCLUDED.relay_lease_revision
RETURNING pair_id;

-- name: LimitConnectorPeerPreparedForClaim :exec
-- a fresh claim may shorten a prior installation, never silently grow it.
UPDATE control.connector_peer_pairs SET publisher_prepared_until=sqlc.arg(confirmed_until)
WHERE id=sqlc.arg(pair_id) AND retired_at IS NULL AND publisher_prepared_until>sqlc.arg(confirmed_until);

-- name: ReadConnectorPeerClaimBounds :many
SELECT connection_slot,checked_at,confirmed_until,source_ip,relay_id,relay_run_id,relay_lease_revision
FROM control.connector_peer_pair_leg_claims WHERE pair_id=sqlc.arg(pair_id)
    AND delivery_generation=(SELECT delivery_generation FROM control.connector_peer_pairs WHERE id=sqlc.arg(pair_id) AND retired_at IS NULL)
ORDER BY connection_slot LIMIT 2;

-- name: ReadConnectorPeerBindingClaims :many
SELECT claims.* FROM control.connector_peer_pair_leg_claims claims WHERE claims.pair_id=sqlc.arg(pair_id)
    AND claims.delivery_generation=sqlc.arg(delivery_generation)
    AND EXISTS(SELECT 1 FROM control.connector_peer_pairs pair WHERE pair.id=sqlc.arg(pair_id) AND pair.retired_at IS NULL)
ORDER BY claims.connection_slot LIMIT 2;

-- name: GetConnectorPeerPendingBinding :one
SELECT * FROM control.connector_peer_pending_bindings WHERE pair_id=sqlc.arg(pair_id)
    AND EXISTS(SELECT 1 FROM control.connector_peer_pairs pair WHERE pair.id=sqlc.arg(pair_id) AND pair.retired_at IS NULL);

-- name: InitializeConnectorPeerSession :one
UPDATE control.connector_peer_pairs SET session_key_ciphertext=sqlc.arg(ciphertext),session_key_digest=sqlc.arg(digest),
    session_key_storage_key_id=sqlc.arg(storage_key_id),trust_revision=sqlc.arg(trust_revision)
WHERE id=sqlc.arg(id) AND retired_at IS NULL AND session_key_ciphertext IS NULL RETURNING *;

-- name: ReadConnectorPeerObservationRelayBounds :many
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

-- name: LockConnectorPeerRetirementTeam :one
-- use the existing owner guard without requiring current team authority.
WITH guard AS MATERIALIZED (
    SELECT pg_advisory_xact_lock_shared(hashtextextended('tnl:local-team:' || sqlc.arg(team_id)::text, 0))
)
SELECT teams.id FROM control.teams AS teams CROSS JOIN guard
WHERE teams.id=sqlc.arg(team_id) FOR SHARE OF teams;

-- name: LockConnectorPeerRetirementGuest :one
SELECT id FROM control.guest_trials WHERE id=sqlc.arg(guest_id) FOR UPDATE;

-- name: HasRetainedConnectorPeerPair :one
-- the exact run token grants negative reads only while an existing window remains.
SELECT EXISTS(SELECT 1 FROM control.connector_peer_pairs
    WHERE service_id=sqlc.arg(service_id) AND service_run_id=sqlc.arg(service_run_id)
        AND run_number=sqlc.arg(run_number) AND publisher_identity_id=sqlc.arg(publisher_identity_id)
        AND GREATEST(expires_at,replay_fence_until)>sqlc.arg(now))::boolean;

-- name: RetireConnectorPeerPair :one
-- the caller holds owner -> service -> run -> exact pair and verifies both proofs.
-- terminal retries compare the stored digest; no upsert or deadline advance exists.
UPDATE control.connector_peer_pairs
SET owner_revision=2,retired_at=sqlc.arg(now),retire_request_digest=sqlc.arg(retire_request_digest),
    publisher_prepared_until=NULL,publisher_proved_until=NULL,publisher_proof_digest=NULL
WHERE id=sqlc.arg(id) AND service_id=sqlc.arg(service_id) AND service_run_id=sqlc.arg(service_run_id)
    AND run_number=sqlc.arg(run_number) AND publisher_identity_id=sqlc.arg(publisher_identity_id)
    AND delivery_id=sqlc.arg(delivery_id) AND owner_key=sqlc.arg(owner_key)
    AND owner_revision=1 AND retired_at IS NULL AND last_authorized_at<=sqlc.arg(now)
    AND GREATEST(expires_at,replay_fence_until)>sqlc.arg(now)
    AND session_key_digest IS NOT NULL
RETURNING *;

-- name: DeleteConnectorPeerPendingBinding :execrows
DELETE FROM control.connector_peer_pending_bindings WHERE pair_id=sqlc.arg(pair_id);

-- name: DeleteConnectorPeerPairLegClaims :execrows
DELETE FROM control.connector_peer_pair_leg_claims WHERE pair_id=sqlc.arg(pair_id);

-- name: RetireConnectorPeerAuditBindings :execrows
UPDATE control.connector_peer_audit_bindings SET retired_at=COALESCE(retired_at,sqlc.arg(now))
WHERE pair_id=sqlc.arg(pair_id);

-- the following positive statements replace the operation owners' inline SQL
-- after normal generation. storage guards fence those inline writers meanwhile.

-- name: InsertConnectorPeerPendingBinding :one
INSERT INTO control.connector_peer_pending_bindings(pair_id,delivery_generation,operation_id,challenge,slots,
    key_ciphertext,key_digest,storage_key_id,created_at,pending_until)
SELECT sqlc.arg(pair_id),sqlc.arg(delivery_generation),sqlc.arg(operation_id),sqlc.arg(challenge),
    convert_from(sqlc.arg(slots)::bytea,'UTF8')::jsonb,sqlc.arg(key_ciphertext),sqlc.arg(key_digest),
    sqlc.arg(storage_key_id),sqlc.arg(now),sqlc.arg(pending_until)
FROM control.connector_peer_pairs pair WHERE pair.id=sqlc.arg(pair_id) AND pair.retired_at IS NULL
RETURNING *;

-- name: PrepareConnectorPeerRebind :execrows
UPDATE control.connector_peer_pairs
SET high_water_generation=sqlc.arg(delivery_generation),rebind_operation_id=sqlc.arg(operation_id),
    rebind_generation=sqlc.arg(delivery_generation),rebind_status='pending',
    rebind_prepare_digest=sqlc.arg(request_digest),rebind_activate_digest=NULL,rebind_abort_digest=NULL
WHERE id=sqlc.arg(pair_id) AND retired_at IS NULL;

-- name: ActivateConnectorPeerBinding :execrows
UPDATE control.connector_peer_pairs
SET slots=convert_from(sqlc.arg(slots)::bytea,'UTF8')::jsonb,delivery_generation=sqlc.arg(delivery_generation),
    key_ciphertext=sqlc.arg(key_ciphertext),key_digest=sqlc.arg(key_digest),storage_key_id=sqlc.arg(storage_key_id),
    binding_operation_id=sqlc.arg(operation_id),binding_challenge=sqlc.arg(challenge),
    publisher_prepared_until=sqlc.narg(publisher_prepared_until),publisher_proved_until=sqlc.narg(publisher_proved_until),
    publisher_proof_digest=sqlc.narg(publisher_proof_digest),rebind_status='active',rebind_activate_digest=sqlc.arg(request_digest)
WHERE id=sqlc.arg(pair_id) AND retired_at IS NULL;

-- name: AbortConnectorPeerRebind :execrows
UPDATE control.connector_peer_pairs SET rebind_status='aborted',rebind_abort_digest=sqlc.arg(request_digest)
WHERE id=sqlc.arg(pair_id) AND retired_at IS NULL;

-- name: ExpireConnectorPeerRebind :execrows
UPDATE control.connector_peer_pairs SET rebind_status='expired' WHERE id=sqlc.arg(pair_id) AND retired_at IS NULL;

-- name: SaveConnectorPeerPublisherProof :execrows
UPDATE control.connector_peer_pairs SET publisher_proved_until=sqlc.arg(proved_until),publisher_proof_digest=sqlc.arg(proof_digest)
WHERE id=sqlc.arg(pair_id) AND retired_at IS NULL;

-- name: SaveConnectorPeerPendingPublisherProof :execrows
UPDATE control.connector_peer_pending_bindings SET publisher_proved_until=sqlc.arg(proved_until),publisher_proof_digest=sqlc.arg(proof_digest)
WHERE pair_id=sqlc.arg(pair_id)
    AND EXISTS(SELECT 1 FROM control.connector_peer_pairs pair WHERE pair.id=sqlc.arg(pair_id) AND pair.retired_at IS NULL);

-- name: ConfirmConnectorPeerPendingPrepared :execrows
UPDATE control.connector_peer_pending_bindings
SET publisher_prepared_until=LEAST(sqlc.arg(authority_expires_at),GREATEST(publisher_prepared_until,sqlc.arg(binding_expires_at)))
WHERE pair_id=sqlc.arg(pair_id)
    AND EXISTS(SELECT 1 FROM control.connector_peer_pairs pair WHERE pair.id=sqlc.arg(pair_id) AND pair.retired_at IS NULL);

-- name: LimitConnectorPeerPendingForClaim :execrows
UPDATE control.connector_peer_pending_bindings
SET publisher_prepared_until=CASE WHEN publisher_prepared_until IS NULL THEN NULL ELSE LEAST(publisher_prepared_until,sqlc.arg(confirmed_until)) END,
    publisher_proved_until=CASE WHEN publisher_proved_until IS NULL THEN NULL ELSE LEAST(publisher_proved_until,sqlc.arg(confirmed_until)) END
WHERE pair_id=sqlc.arg(pair_id)
    AND EXISTS(SELECT 1 FROM control.connector_peer_pairs pair WHERE pair.id=sqlc.arg(pair_id) AND pair.retired_at IS NULL);

-- name: SaveConnectorPeerAuditBinding :execrows
INSERT INTO control.connector_peer_audit_bindings
    (pair_id,service_id,service_run_id,run_number,publisher_identity_id,identity_id,device_id,source_ip,created_at,expires_at,delivery_generation)
SELECT sqlc.arg(pair_id),sqlc.arg(service_id),sqlc.arg(service_run_id),sqlc.arg(run_number),sqlc.arg(publisher_identity_id),
    sqlc.narg(identity_id),sqlc.narg(device_id),sqlc.arg(source_ip),sqlc.arg(created_at),sqlc.arg(expires_at),sqlc.arg(delivery_generation)
FROM control.connector_peer_pairs pair WHERE pair.id=sqlc.arg(pair_id) AND pair.retired_at IS NULL
ON CONFLICT (pair_id,delivery_generation) DO UPDATE SET expires_at=GREATEST(control.connector_peer_audit_bindings.expires_at,EXCLUDED.expires_at)
WHERE control.connector_peer_audit_bindings.retired_at IS NULL
    AND control.connector_peer_audit_bindings.service_id=EXCLUDED.service_id
    AND control.connector_peer_audit_bindings.service_run_id=EXCLUDED.service_run_id
    AND control.connector_peer_audit_bindings.run_number=EXCLUDED.run_number
    AND control.connector_peer_audit_bindings.publisher_identity_id=EXCLUDED.publisher_identity_id
    AND control.connector_peer_audit_bindings.identity_id IS NOT DISTINCT FROM EXCLUDED.identity_id
    AND control.connector_peer_audit_bindings.device_id IS NOT DISTINCT FROM EXCLUDED.device_id
    AND control.connector_peer_audit_bindings.source_ip=EXCLUDED.source_ip
    AND control.connector_peer_audit_bindings.created_at=EXCLUDED.created_at;
