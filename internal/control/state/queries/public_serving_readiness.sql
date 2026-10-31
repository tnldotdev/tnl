-- name: ReadPublishRunPreparationRouting :one
SELECT * FROM control.ingress_routing_table_events
WHERE public_url_id = sqlc.arg(public_url_id)
  AND publish_run_number = sqlc.arg(publish_run_number)
ORDER BY id DESC LIMIT 1;

-- name: DeleteExpiredIngressPublicRunObservations :exec
DELETE FROM control.ingress_public_run_observations
WHERE ingress_id = sqlc.arg(ingress_id) AND valid_until <= sqlc.arg(now);

-- name: DeletePublishRunObservations :exec
DELETE FROM control.ingress_public_run_observations WHERE publish_run_id = sqlc.arg(publish_run_id);

-- name: ObserveIngressPublicRun :execrows
-- renewal holds only its ingress row. do not acquire a URL/run lock here:
-- ready holds URL/run -> pool and reads this committed observation.
INSERT INTO control.ingress_public_run_observations AS installed (
    ingress_id, ingress_run_id, ingress_lease_revision,
    publish_run_id, publish_run_number, entry_revision, valid_until
)
SELECT sqlc.arg(ingress_id), sqlc.arg(ingress_run_id), sqlc.arg(ingress_lease_revision),
    run.id, run.publish_run_number, event.entry_revision,
    LEAST(sqlc.arg(valid_until)::timestamptz, sqlc.arg(lease_expires_at)::timestamptz,
          run.publisher_expires_at, event.public_url_expires_at)
FROM control.publish_runs AS run
JOIN control.public_urls AS url ON url.id = run.public_url_id
JOIN control.ingress_routing_table_events AS event ON event.public_url_id = run.public_url_id
    AND event.publish_run_number = run.publish_run_number
    AND event.entry_revision = sqlc.arg(entry_revision)
WHERE run.id = sqlc.arg(publish_run_id) AND run.publish_run_number = sqlc.arg(publish_run_number)
  AND run.closed_at IS NULL AND run.publisher_expires_at > sqlc.arg(now)
  AND url.ingress_pool_id = sqlc.arg(ingress_pool_id)
  AND event.event_kind = 'public_url_upsert' AND event.public_url_expires_at > sqlc.arg(now)
  AND event.id <= sqlc.arg(routing_table_revision)
  AND sqlc.arg(valid_until)::timestamptz > sqlc.arg(now)
ON CONFLICT (ingress_id, publish_run_id) DO UPDATE SET
    ingress_run_id = EXCLUDED.ingress_run_id,
    ingress_lease_revision = EXCLUDED.ingress_lease_revision,
    publish_run_number = EXCLUDED.publish_run_number,
    entry_revision = EXCLUDED.entry_revision,
    valid_until = EXCLUDED.valid_until
-- the lease fences process identity, not concurrent request arrival order.
-- keep each exact revision's longest installed deadline; a newer revision
-- replaces it even when its own installed deadline is shorter.
WHERE EXCLUDED.ingress_lease_revision > installed.ingress_lease_revision
   OR (EXCLUDED.ingress_lease_revision = installed.ingress_lease_revision
       AND EXCLUDED.ingress_run_id = installed.ingress_run_id
       AND (EXCLUDED.entry_revision > installed.entry_revision
            OR (EXCLUDED.entry_revision = installed.entry_revision
                AND EXCLUDED.valid_until > installed.valid_until)));

-- name: PublishRunServingPrepared :one
WITH receivers AS (
    SELECT * FROM control.ingress_leases
    WHERE ingress_pool_id = sqlc.arg(ingress_pool_id)
      AND lease_expires_at > sqlc.arg(now) AND NOT draining
      AND protocol_version = 1 AND connection_capacity > 0
)
SELECT EXISTS (SELECT 1 FROM receivers) AND NOT EXISTS (
    SELECT 1 FROM receivers AS receiver
    WHERE NOT EXISTS (
        SELECT 1 FROM control.ingress_public_run_observations AS installed
        WHERE installed.ingress_id = receiver.ingress_id
          AND installed.ingress_run_id = receiver.ingress_run_id
          AND installed.ingress_lease_revision = receiver.ingress_lease_revision
          AND installed.publish_run_id = sqlc.arg(publish_run_id)
          AND installed.publish_run_number = sqlc.arg(publish_run_number)
          AND installed.entry_revision = sqlc.arg(entry_revision)
          AND installed.valid_until > sqlc.arg(now)
    )
) AS prepared;
