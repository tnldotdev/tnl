-- name: LockServiceAuditClock :exec
SELECT pg_advisory_xact_lock(hashtextextended('tnl:service-audit:' ||
    COALESCE(sqlc.narg(team_id)::text,'guest/'||sqlc.narg(guest_id)::text),0));

-- name: ListServiceAuditOwners :many
SELECT id,team_id,guest_id FROM control.services
WHERE id=ANY(sqlc.arg(service_ids)::text[])
ORDER BY COALESCE(team_id,'guest/'||guest_id) COLLATE "C",id COLLATE "C";

-- name: InsertServiceAuditEvents :many
-- earlier owners are already locked in order. take the final owner's clock
-- before allocating a cursor; the arrays have one element per event.
WITH clock AS MATERIALIZED (
    SELECT pg_advisory_xact_lock(hashtextextended('tnl:service-audit:' ||
        COALESCE(sqlc.narg(team_id)::text,'guest/'||sqlc.narg(guest_id)::text),0))
)
INSERT INTO control.service_audit_events(id,team_id,guest_id,service_id,event_type,occurred_at,received_at,
    actor_identity_id,device_id,publisher_identity_id,run_id,visitor_connection_id,source_digest,outcome,reason,configuration_revision)
SELECT e.id,NULLIF(e.team,''),s.guest_id,s.id,e.kind,e.happened,sqlc.arg(received_at),
    NULLIF(e.actor,''),NULLIF(e.device,''),NULLIF(e.publisher,''),NULLIF(e.run,''),NULLIF(e.visitor,''),
    NULLIF(e.source,''),NULLIF(e.outcome,''),NULLIF(e.reason,''),NULLIF(e.revision,0)
FROM clock CROSS JOIN control.services s CROSS JOIN (
    SELECT unnest(sqlc.arg(ids)::text[]) AS id,unnest(sqlc.arg(teams)::text[]) AS team,
        unnest(sqlc.arg(services)::text[]) AS service,unnest(sqlc.arg(kinds)::text[]) AS kind,
        unnest(sqlc.arg(times)::timestamptz[]) AS happened,unnest(sqlc.arg(actors)::text[]) AS actor,
        unnest(sqlc.arg(devices)::text[]) AS device,unnest(sqlc.arg(publishers)::text[]) AS publisher,
        unnest(sqlc.arg(runs)::text[]) AS run,unnest(sqlc.arg(visitors)::text[]) AS visitor,
        unnest(sqlc.arg(sources)::text[]) AS source,unnest(sqlc.arg(outcomes)::text[]) AS outcome,
        unnest(sqlc.arg(reasons)::text[]) AS reason,unnest(sqlc.arg(revisions)::bigint[]) AS revision,
        generate_subscripts(sqlc.arg(ids)::text[],1) AS position
) e
WHERE s.id=e.service
ORDER BY e.position
ON CONFLICT(id) DO NOTHING
RETURNING id;

-- name: ListServiceAuditEventsByID :many
SELECT * FROM control.service_audit_events WHERE id=ANY(sqlc.arg(event_ids)::text[]);

-- name: ListServiceAuditEvents :many
SELECT * FROM control.service_audit_events
WHERE team_id=sqlc.arg(team_id) AND cursor>sqlc.arg(after_cursor)
    AND received_at >= sqlc.arg(retained_after)
    AND (sqlc.narg(since)::timestamptz IS NULL OR occurred_at>=sqlc.narg(since))
    AND (sqlc.narg(service_id)::text IS NULL OR service_id=sqlc.narg(service_id))
ORDER BY cursor LIMIT sqlc.arg(page_limit);

-- name: CleanupServiceAuditEvents :execrows
DELETE FROM control.service_audit_events WHERE cursor IN (
    SELECT expired.cursor FROM control.service_audit_events AS expired WHERE expired.received_at<sqlc.arg(before_time)
    ORDER BY expired.received_at,expired.cursor LIMIT sqlc.arg(batch_size) FOR UPDATE SKIP LOCKED
);
