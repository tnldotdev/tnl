-- name: ListReadDependencyVersions :many
SELECT bucket,revision FROM control.read_dependency_versions WHERE topic=sqlc.arg(topic);

-- name: ReadConnectorPeerWatchVersions :many
-- called only for scopes whose change records differ, in the same snapshot.
WITH current_policy AS MATERIALIZED (
    SELECT service_run_id,bookmark FROM control.publisher_run_policy_bookmarks WHERE service_run_id=ANY(sqlc.arg(run_ids)::text[])
)
SELECT watched.id::text AS run_id,(hashtext(watched.id)&255)::integer AS run_bucket,
    (hashtext(COALESCE(run.service_id,watched.id))&255)::integer AS service_bucket,
    CASE WHEN policy.bookmark IS NULL THEN -1 ELSE COALESCE(version.revision,0) END::bigint AS revision,
    COALESCE(policy.bookmark,'')::text AS policy_bookmark
FROM unnest(sqlc.arg(run_ids)::text[]) AS watched(id)
LEFT JOIN control.service_runs run ON run.id=watched.id
LEFT JOIN current_policy policy ON policy.service_run_id=watched.id
LEFT JOIN control.connector_peer_watch_versions version ON version.service_run_id=watched.id;
