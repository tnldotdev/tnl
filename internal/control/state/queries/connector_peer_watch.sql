-- name: CompareConnectorPeerWatchVersions :many
-- an untouched run starts at zero. a missing or closed run has no version.
SELECT watched.run_id::text AS run_id,
    CASE WHEN policy.bookmark IS NULL THEN -1 ELSE COALESCE(version.revision,0) END::bigint AS revision,
    COALESCE(policy.bookmark,'')::text AS policy_bookmark
FROM (SELECT unnest(sqlc.arg(run_ids)::text[]) AS run_id,unnest(sqlc.arg(revisions)::bigint[]) AS seen,
    unnest(sqlc.arg(policy_bookmarks)::text[]) AS policy_seen) watched
LEFT JOIN control.publisher_run_policy_bookmarks policy ON policy.service_run_id=watched.run_id
LEFT JOIN control.connector_peer_watch_versions version ON version.service_run_id=watched.run_id
WHERE policy.bookmark IS NULL OR COALESCE(version.revision,0)<>watched.seen OR policy.bookmark<>watched.policy_seen;
