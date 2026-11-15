-- name: InsertGuestTrial :one
INSERT INTO control.guest_trials (
    id, credential_id, credential_hash, namespace_label,
    domain_id, ingress_pool_id, dns_authority_reference, source_ip_digest, source_ip_key_id,
    issuance_ip_digest, expires_at, created_at, updated_at
) VALUES (
    sqlc.arg(id), sqlc.arg(credential_id), sqlc.arg(credential_hash),
    sqlc.arg(namespace_label), sqlc.arg(domain_id), sqlc.arg(ingress_pool_id),
    sqlc.arg(dns_authority_reference), sqlc.arg(source_ip_digest), sqlc.arg(source_ip_key_id),
    sqlc.arg(issuance_ip_digest), sqlc.arg(expires_at), sqlc.arg(created_at), sqlc.arg(created_at)
)
RETURNING *;

-- name: GetGuestTrialByCredentialID :one
SELECT * FROM control.guest_trials
WHERE credential_id = sqlc.arg(credential_id);

-- name: GetGuestTrialByID :one
SELECT * FROM control.guest_trials
WHERE id = sqlc.arg(id);

-- name: GuestNamespaceReserved :one
SELECT EXISTS (SELECT 1 FROM control.guest_trials WHERE namespace_label = sqlc.arg(label));

-- name: LockGuestTrialByID :one
SELECT * FROM control.guest_trials WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: CountGuestCurrentServices :one
SELECT count(*) FROM control.services
WHERE guest_id = sqlc.arg(guest_id) AND deleted_at IS NULL;

-- name: FindGuestServiceAllocation :one
-- terminal allocations remain discoverable so a retry cannot recreate them.
SELECT * FROM control.services
WHERE guest_id = sqlc.arg(guest_id) AND idempotency_key = sqlc.arg(idempotency_key);

-- name: CountRecentGuestTrialsByIP :one
SELECT count(*) FROM control.guest_trials
WHERE source_ip_key_id = sqlc.arg(source_ip_key_id)
  AND issuance_ip_digest = sqlc.arg(issuance_ip_digest)
  AND created_at >= sqlc.arg(since);

-- name: ForgetOldGuestIssuanceDigests :execrows
UPDATE control.guest_trials AS trial SET issuance_ip_digest = NULL
WHERE trial.id IN (
    SELECT candidate.id FROM control.guest_trials AS candidate
    WHERE candidate.issuance_ip_digest IS NOT NULL AND candidate.created_at < sqlc.arg(cutoff)
    ORDER BY candidate.created_at, candidate.id LIMIT sqlc.arg(batch_size)
    FOR UPDATE OF candidate SKIP LOCKED
);

-- name: ForgetExpiredGuestCredentials :execrows
UPDATE control.guest_trials SET credential_id = NULL, credential_hash = NULL,
    source_ip_digest = NULL, source_ip_key_id = NULL,
    end_reason = COALESCE(end_reason, 'expired'),
    ended_at = COALESCE(ended_at, expires_at)
WHERE id IN (
    SELECT guest.id FROM control.guest_trials AS guest
    WHERE guest.expires_at <= sqlc.arg(now)
      AND guest.source_ip_digest IS NOT NULL
      AND guest.active_service_run_id IS NULL
      AND (guest.serving_until IS NULL OR guest.serving_until <= sqlc.arg(now))
      AND NOT EXISTS (
          SELECT 1 FROM control.services service
          WHERE service.guest_id = guest.id AND service.deleted_at IS NULL
      )
    ORDER BY guest.expires_at, guest.id LIMIT sqlc.arg(batch_size)
    FOR UPDATE OF guest SKIP LOCKED
);

-- name: ForgetExpiredGuestServiceConfigurations :execrows
-- terminal allocation keys/digests remain; targets and declarations do not.
UPDATE control.services AS service SET configuration_ciphertext=NULL,storage_key_id=NULL
WHERE service.id IN (
    SELECT candidate.id FROM control.services candidate
    JOIN control.guest_trials guest ON guest.id=candidate.guest_id
    WHERE guest.expires_at<=sqlc.arg(now) AND candidate.deleted_at IS NOT NULL
        AND candidate.configuration_ciphertext IS NOT NULL
        AND (guest.serving_until IS NULL OR guest.serving_until<=sqlc.arg(now))
        AND NOT EXISTS(SELECT 1 FROM control.service_runs run
            WHERE run.service_id=candidate.id AND run.closed_at IS NULL)
    ORDER BY candidate.id LIMIT sqlc.arg(batch_size)
    FOR UPDATE OF candidate SKIP LOCKED
);

-- name: AdvanceGuestDemoNumber :one
UPDATE control.guest_trials
SET last_demo_number = last_demo_number + 1,
    first_demo_allocated_at = COALESCE(first_demo_allocated_at, sqlc.arg(allocated_at)),
    updated_at = sqlc.arg(allocated_at)
WHERE id = sqlc.arg(id) AND last_demo_number < 9223372036854775807
RETURNING last_demo_number;

-- name: GuestOwnsService :one
SELECT EXISTS(
    SELECT 1 FROM control.services
    WHERE id = sqlc.arg(service_id) AND guest_id = sqlc.arg(guest_id)
);

-- name: GuestForService :one
SELECT guest_id FROM control.services
WHERE id = sqlc.arg(service_id) AND guest_id IS NOT NULL;

-- name: GuestServiceServingDeadline :one
-- preparation observations do not grant visitor permission or spend ready time.
SELECT CASE WHEN guest.active_ready_at IS NULL THEN sqlc.arg(now)::timestamptz
    ELSE control.guest_serving_deadline(guest.id, sqlc.arg(now)::timestamptz) END::timestamptz AS deadline
FROM control.services service JOIN control.guest_trials guest ON guest.id = service.guest_id
JOIN control.service_runs run ON run.id=guest.active_service_run_id AND run.service_id=service.id AND run.guest_id=guest.id
WHERE service.id = sqlc.arg(service_id) AND service.enabled AND service.deleted_at IS NULL;

-- name: BeginGuestServiceRun :execrows
UPDATE control.guest_trials AS guest
SET active_service_run_id = run.id, updated_at = sqlc.arg(started_at)
FROM control.service_runs run
WHERE run.id = sqlc.arg(service_run_id) AND run.service_id = sqlc.arg(service_id)
  AND run.guest_id=guest.id AND run.closed_at IS NULL
  AND guest.active_service_run_id IS NULL
  AND (guest.serving_until IS NULL OR guest.serving_until <= sqlc.arg(started_at))
  AND guest.ended_at IS NULL
  AND guest.expires_at > sqlc.arg(started_at)
  AND guest.used_ready_ns < 1200000000000;

-- name: MarkGuestRunReady :execrows
UPDATE control.guest_trials
SET active_ready_at = sqlc.arg(ready_at), updated_at = sqlc.arg(ready_at),
    ready_deadline = LEAST(expires_at, sqlc.arg(ready_at)::timestamptz +
        ((1200000000000 - used_ready_ns)::double precision / 1000000000) * interval '1 second'),
    first_ready_at = COALESCE(first_ready_at, sqlc.arg(ready_at))
WHERE active_service_run_id = sqlc.arg(service_run_id)
  AND active_ready_at IS NULL
  AND expires_at > sqlc.arg(ready_at)
  AND ended_at IS NULL
  AND used_ready_ns < 1200000000000;

-- name: UpdateGuestServingAuthority :one
-- retain issued ready authority after closure so an offline owner cannot overlap
-- its replacement. the run lock serializes readiness, heartbeat and settlement.
UPDATE control.guest_trials AS guest
SET serving_until = CASE WHEN guest.active_ready_at IS NULL THEN guest.serving_until
        ELSE GREATEST(guest.serving_until, LEAST(guest.expires_at, guest.ready_deadline, run.publisher_expires_at)) END
FROM control.service_runs AS run
WHERE run.id = sqlc.arg(service_run_id) AND guest.active_service_run_id = run.id AND run.guest_id=guest.id
RETURNING control.guest_serving_deadline(guest.id, sqlc.arg(now)::timestamptz)::timestamptz AS deadline;

-- name: LimitGuestServiceRunExpiry :one
UPDATE control.service_runs
SET publisher_expires_at = LEAST(publisher_expires_at, sqlc.arg(deadline)::timestamptz)
WHERE id = sqlc.arg(service_run_id)
RETURNING *;

-- name: FinishGuestServiceRun :execrows
UPDATE control.guest_trials
SET used_ready_ns = LEAST(1200000000000, used_ready_ns + CASE
        WHEN active_ready_at IS NULL OR serving_until IS NULL THEN 0
        ELSE GREATEST(0, (EXTRACT(EPOCH FROM (LEAST(ready_deadline, serving_until) - active_ready_at)) * 1000000000)::bigint)
    END),
    end_reason = COALESCE(end_reason, CASE
        WHEN sqlc.arg(close_reason)::text = 'guest_expired' OR expires_at <= sqlc.arg(closed_at)::timestamptz OR expires_at <= serving_until THEN 'expired'
        WHEN ready_deadline <= serving_until THEN 'ready_limit'
    END),
    ended_at = COALESCE(ended_at, CASE
        WHEN sqlc.arg(close_reason)::text = 'guest_expired' OR expires_at <= sqlc.arg(closed_at)::timestamptz OR expires_at <= serving_until THEN expires_at
        WHEN ready_deadline <= serving_until THEN ready_deadline
    END),
    active_ready_at = NULL,
    ready_deadline = NULL,
    active_service_run_id = NULL,
    updated_at = sqlc.arg(closed_at)
WHERE active_service_run_id = sqlc.arg(service_run_id);

-- name: GuestRunAllowanceSpent :one
SELECT CASE
    WHEN expires_at <= sqlc.arg(now)::timestamptz THEN 'guest_expired'
    WHEN used_ready_ns >= 1200000000000 OR ready_deadline <= sqlc.arg(now)::timestamptz THEN 'guest_ready_limit'
    ELSE ''
END::text AS reason
FROM control.guest_trials
WHERE active_service_run_id = sqlc.arg(service_run_id);

-- name: RecentGuestTrialStats :one
SELECT
    count(*) FILTER (WHERE created_at >= sqlc.arg(since))::bigint AS issued,
    count(*) FILTER (WHERE first_demo_allocated_at >= sqlc.arg(since))::bigint AS allocated,
    count(*) FILTER (WHERE first_ready_at >= sqlc.arg(since))::bigint AS ready,
    count(*) FILTER (WHERE end_reason = 'expired' AND ended_at >= sqlc.arg(since))::bigint AS expired,
    count(*) FILTER (WHERE end_reason = 'ready_limit' AND ended_at >= sqlc.arg(since))::bigint AS ready_limit
FROM control.guest_trials;
