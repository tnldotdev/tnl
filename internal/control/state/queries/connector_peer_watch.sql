-- name: CompareConnectorPeerWatchVersions :many
-- an untouched run starts at zero. a missing or closed run has no version.
SELECT watched.run_id::text AS run_id,
    CASE WHEN run.id IS NULL THEN -1 ELSE COALESCE(version.revision,0) END::bigint AS revision
FROM (SELECT unnest(sqlc.arg(run_ids)::text[]) AS run_id,unnest(sqlc.arg(revisions)::bigint[]) AS seen) watched
LEFT JOIN control.service_runs run ON run.id=watched.run_id AND run.started_at IS NOT NULL AND run.closed_at IS NULL
LEFT JOIN control.connector_peer_watch_versions version ON version.service_run_id=run.id
WHERE run.id IS NULL OR COALESCE(version.revision,0)<>watched.seen;
