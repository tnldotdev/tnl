-- name: AppendFreshPublisherAudit :exec
INSERT INTO control.service_audit_events(id,team_id,guest_id,service_id,event_type,occurred_at,received_at,
    actor_identity_id,device_id,publisher_identity_id,run_id,visitor_connection_id,source_digest,outcome,reason)
SELECT e.id,$1,$2,$3,e.kind,e.happened,$4,NULLIF(e.actor,''),NULLIF(e.device,''),$5,$6,
    e.visitor,e.source,e.outcome,NULLIF(e.reason,'')
FROM unnest($7::text[],$8::text[],$9::timestamptz[],$10::text[],$11::text[],$12::text[],$13::text[],$14::text[],$15::text[])
WITH ORDINALITY AS e(id,kind,happened,actor,device,visitor,source,outcome,reason,position)
ORDER BY position;
