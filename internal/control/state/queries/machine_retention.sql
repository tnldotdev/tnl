-- expire credential and replay state independently. proof expiry is the full
-- cryptographic validity bound, never a shorter grant or session deadline.
-- name: CleanupMachineProvisioningSessions :execrows
DELETE FROM control.machine_provisioning_sessions WHERE credential_digest IN (
    SELECT session.credential_digest FROM control.machine_provisioning_sessions session
    WHERE session.expires_at <= sqlc.arg(now_time)
    ORDER BY session.expires_at, session.credential_digest LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
);

-- name: CleanupMachineProofUses :execrows
DELETE FROM control.machine_proof_uses WHERE (machine_id,proof_digest) IN (
    SELECT proof.machine_id,proof.proof_digest FROM control.machine_proof_uses proof
    WHERE proof.expires_at <= sqlc.arg(now_time)
    ORDER BY proof.expires_at,proof.machine_id,proof.proof_digest LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
);
