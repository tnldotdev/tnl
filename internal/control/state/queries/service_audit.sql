-- name: LockServiceAuditClock :exec
SELECT pg_advisory_xact_lock(hashtextextended('tnl:service-audit:' ||
    COALESCE(sqlc.narg(team_id)::text,'guest/'||sqlc.narg(guest_id)::text),0));

-- name: ListServiceAuditOwners :many
SELECT id,team_id,guest_id FROM control.services
WHERE id=ANY(sqlc.arg(service_ids)::text[])
ORDER BY COALESCE(team_id,'guest/'||guest_id) COLLATE "C",id COLLATE "C";

-- name: InsertServiceAuditEvents :many
INSERT INTO control.service_audit_events(id,team_id,guest_id,service_id,event_type,occurred_at,received_at,
    actor_identity_id,device_id,publisher_identity_id,run_id,visitor_connection_id,source_ip,outcome,reason,configuration_revision)
SELECT entry.value->>'id',NULLIF(entry.value->>'team_id',''),service.guest_id,service.id,
    entry.value->>'event_type',(entry.value->>'occurred_at')::timestamptz,sqlc.arg(received_at),
    NULLIF(entry.value->>'actor_identity_id',''),NULLIF(entry.value->>'device_id',''),
    NULLIF(entry.value->>'publisher_identity_id',''),NULLIF(entry.value->>'run_id',''),
    NULLIF(entry.value->>'visitor_connection_id',''),NULLIF(entry.value->>'source_ip','')::inet,
    NULLIF(entry.value->>'outcome',''),NULLIF(entry.value->>'reason',''),NULLIF((entry.value->>'configuration_revision')::bigint,0)
FROM jsonb_array_elements(convert_from(sqlc.arg(events)::bytea,'UTF8')::jsonb) WITH ORDINALITY AS entry(value,position)
JOIN control.services service ON service.id=(entry.value->>'service_id')
ORDER BY entry.position
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
