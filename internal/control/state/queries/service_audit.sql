-- name: LockServiceAuditClock :exec
SELECT pg_advisory_xact_lock(hashtextextended('tnl:service-audit:' ||
    COALESCE(sqlc.narg(team_id)::text,'guest/'||sqlc.narg(guest_id)::text),0));

-- name: InsertServiceAuditEvent :execrows
INSERT INTO control.service_audit_events(id,team_id,guest_id,service_id,event_type,occurred_at,received_at,
    actor_identity_id,device_id,publisher_identity_id,run_id,visitor_connection_id,source_ip,outcome,reason,configuration_revision)
VALUES(sqlc.arg(id),sqlc.narg(team_id),
    (SELECT service.guest_id FROM control.services service WHERE service.id=sqlc.arg(service_id)),
    sqlc.arg(service_id),sqlc.arg(event_type),sqlc.arg(occurred_at),sqlc.arg(received_at),
    sqlc.narg(actor_identity_id),sqlc.narg(device_id),sqlc.narg(publisher_identity_id),sqlc.narg(run_id),sqlc.narg(visitor_connection_id),sqlc.narg(source_ip),sqlc.narg(outcome),sqlc.narg(reason),sqlc.narg(configuration_revision))
ON CONFLICT(id) DO NOTHING;

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
