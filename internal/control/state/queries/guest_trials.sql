-- name: InsertGuestTrial :one
INSERT INTO control.guest_trials (
    id, credential_id, credential_hash, namespace_label, team_id,
    membership_id, domain_id, dns_authority_reference, source_ip_digest, source_ip_key_id,
    issuance_ip_digest, expires_at, created_at, updated_at
) VALUES (
    sqlc.arg(id), sqlc.arg(credential_id), sqlc.arg(credential_hash),
    sqlc.arg(namespace_label), sqlc.arg(team_id), sqlc.arg(membership_id),
    sqlc.arg(domain_id), sqlc.arg(dns_authority_reference), sqlc.arg(source_ip_digest), sqlc.arg(source_ip_key_id),
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

-- name: CountGuestCurrentPublicURLs :one
SELECT count(*) FROM control.guest_public_urls AS guest_route
JOIN control.public_urls AS route ON route.id = guest_route.public_url_id
WHERE guest_route.guest_id = sqlc.arg(guest_id)
  AND route.lifecycle_state <> 'deleted';

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
      AND guest.active_publish_run_id IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM control.guest_public_urls AS owned
          JOIN control.public_urls AS route ON route.id = owned.public_url_id
          WHERE owned.guest_id = guest.id AND route.lifecycle_state <> 'deleted'
      )
    ORDER BY guest.expires_at, guest.id LIMIT sqlc.arg(batch_size)
    FOR UPDATE OF guest SKIP LOCKED
);

-- name: ForgetExpiredGuestRunDigests :execrows
UPDATE control.publish_runs AS run
SET request_digest_ciphertext = NULL, request_digest_storage_key_id = NULL
WHERE run.id IN (
    SELECT candidate.id FROM control.publish_runs AS candidate
    JOIN control.guest_public_urls AS owned ON owned.public_url_id = candidate.public_url_id
    JOIN control.guest_trials AS guest ON guest.id = owned.guest_id
    JOIN control.public_urls AS route ON route.id = owned.public_url_id
    WHERE guest.expires_at <= sqlc.arg(now)
      AND route.lifecycle_state = 'deleted'
      AND candidate.closed_at IS NOT NULL
      AND candidate.request_digest_ciphertext IS NOT NULL
    ORDER BY candidate.id LIMIT sqlc.arg(batch_size)
    FOR UPDATE OF candidate SKIP LOCKED
);

-- name: ForgetExpiredGuestRoutingHashes :execrows
UPDATE control.ingress_routing_table_events AS event
SET projection = convert_to(
    jsonb_set(
        convert_from(event.projection, 'UTF8')::jsonb - 'allowed_ip_hashes' - 'ip_policy_key_id',
        '{ip_policy}', '"allow_all"'::jsonb
    )::text, 'UTF8'
)
WHERE event.id IN (
    SELECT candidate.id FROM control.ingress_routing_table_events AS candidate
    JOIN control.guest_public_urls AS owned ON owned.public_url_id = candidate.public_url_id
    JOIN control.guest_trials AS guest ON guest.id = owned.guest_id
    JOIN control.public_urls AS route ON route.id = owned.public_url_id
    WHERE guest.expires_at <= sqlc.arg(now)
      AND route.lifecycle_state = 'deleted'
      AND candidate.public_url_expires_at <= sqlc.arg(now)
      AND convert_from(candidate.projection, 'UTF8')::jsonb ->> 'ip_policy' = 'hashed_allowlist'
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

-- name: InsertGuestPublicURL :exec
INSERT INTO control.guest_public_urls (public_url_id, guest_id, created_at)
VALUES (sqlc.arg(public_url_id), sqlc.arg(guest_id), sqlc.arg(created_at));

-- name: GuestOwnsPublicURL :one
SELECT EXISTS(
    SELECT 1 FROM control.guest_public_urls
    WHERE public_url_id = sqlc.arg(public_url_id)
      AND guest_id = sqlc.arg(guest_id)
);

-- name: GuestForPublicURL :one
SELECT guest_id FROM control.guest_public_urls
WHERE public_url_id = sqlc.arg(public_url_id);

-- name: GuestPublicURLServingDeadline :one
SELECT control.guest_serving_deadline(guest_id, sqlc.arg(now)::timestamptz)::timestamptz AS deadline
FROM control.guest_public_urls WHERE public_url_id = sqlc.arg(public_url_id);

-- name: BeginGuestPublishRun :execrows
UPDATE control.guest_trials AS guest
SET active_publish_run_id = sqlc.arg(publish_run_id), updated_at = sqlc.arg(started_at)
WHERE guest.id = (
    SELECT guest_id FROM control.guest_public_urls
    WHERE public_url_id = sqlc.arg(public_url_id)
)
  AND guest.active_publish_run_id IS NULL
  AND (guest.serving_until IS NULL OR guest.serving_until <= sqlc.arg(started_at))
  AND guest.expires_at > sqlc.arg(started_at)
  AND guest.used_ready_ns < 1200000000000;

-- name: MarkGuestRunReady :execrows
UPDATE control.guest_trials
SET active_ready_at = sqlc.arg(ready_at), updated_at = sqlc.arg(ready_at),
    ready_deadline = LEAST(expires_at, sqlc.arg(ready_at)::timestamptz +
        ((1200000000000 - used_ready_ns)::double precision / 1000000000) * interval '1 second'),
    first_ready_at = COALESCE(first_ready_at, sqlc.arg(ready_at))
WHERE active_publish_run_id = sqlc.arg(publish_run_id)
  AND active_ready_at IS NULL
  AND expires_at > sqlc.arg(ready_at)
  AND used_ready_ns < 1200000000000;

-- name: UpdateGuestServingAuthority :one
-- retain the latest issued serving horizon, including after the run closes.
-- a replacement cannot reuse this time while an offline owner may still serve.
UPDATE control.guest_trials AS guest
SET serving_until = CASE WHEN guest.active_ready_at IS NULL THEN guest.serving_until
        ELSE GREATEST(guest.serving_until, LEAST(guest.expires_at, guest.ready_deadline, run.publisher_expires_at)) END
FROM control.publish_runs AS run
WHERE run.id = sqlc.arg(publish_run_id) AND guest.active_publish_run_id = run.id
RETURNING control.guest_serving_deadline(guest.id, sqlc.arg(now)::timestamptz)::timestamptz AS deadline;

-- name: LimitGuestPublishRunExpiry :one
UPDATE control.publish_runs
SET publisher_expires_at = LEAST(publisher_expires_at, sqlc.arg(deadline)::timestamptz)
WHERE id = sqlc.arg(publish_run_id)
RETURNING *;

-- name: FinishGuestPublishRun :execrows
UPDATE control.guest_trials
SET used_ready_ns = LEAST(1200000000000, used_ready_ns + CASE
        WHEN active_ready_at IS NULL THEN 0
        ELSE GREATEST(0, (EXTRACT(EPOCH FROM (LEAST(ready_deadline,
            COALESCE(serving_until, sqlc.arg(closed_at)::timestamptz)) - active_ready_at)) * 1000000000)::bigint)
    END),
    end_reason = COALESCE(end_reason, CASE
        WHEN sqlc.arg(close_reason)::text = 'guest_expired' OR expires_at <= sqlc.arg(closed_at)::timestamptz THEN 'expired'
        WHEN ready_deadline <= COALESCE(serving_until, sqlc.arg(closed_at)::timestamptz) THEN 'ready_limit'
    END),
    ended_at = COALESCE(ended_at, CASE
        WHEN sqlc.arg(close_reason)::text = 'guest_expired' OR expires_at <= sqlc.arg(closed_at)::timestamptz THEN expires_at
        WHEN ready_deadline <= COALESCE(serving_until, sqlc.arg(closed_at)::timestamptz) THEN ready_deadline
    END),
    active_ready_at = NULL,
    ready_deadline = NULL,
    active_publish_run_id = NULL,
    updated_at = sqlc.arg(closed_at)
WHERE active_publish_run_id = sqlc.arg(publish_run_id);

-- name: GuestRunAllowanceSpent :one
SELECT CASE
    WHEN expires_at <= sqlc.arg(now)::timestamptz THEN 'guest_expired'
    WHEN used_ready_ns >= 1200000000000 OR ready_deadline <= sqlc.arg(now)::timestamptz THEN 'guest_ready_limit'
    ELSE ''
END::text AS reason
FROM control.guest_trials
WHERE active_publish_run_id = sqlc.arg(publish_run_id);

-- name: RecentGuestTrialStats :one
SELECT
    count(*) FILTER (WHERE created_at >= sqlc.arg(since))::bigint AS issued,
    count(*) FILTER (WHERE first_demo_allocated_at >= sqlc.arg(since))::bigint AS allocated,
    count(*) FILTER (WHERE first_ready_at >= sqlc.arg(since))::bigint AS ready,
    count(*) FILTER (WHERE end_reason = 'expired' AND ended_at >= sqlc.arg(since))::bigint AS expired,
    count(*) FILTER (WHERE end_reason = 'ready_limit' AND ended_at >= sqlc.arg(since))::bigint AS ready_limit
FROM control.guest_trials;
