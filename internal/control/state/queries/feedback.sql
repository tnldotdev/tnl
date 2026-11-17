-- name: GetFeedbackService :one
SELECT * FROM control.services WHERE id=sqlc.arg(id);

-- name: FeedbackRunScope :one
SELECT run.id AS service_run_id, run.service_id, run.run_number,
       service.team_id, service.guest_id, preview.id AS preview_id, preview.demo_service_run_id
FROM control.service_runs AS run
JOIN control.services AS service ON service.id = run.service_id
JOIN control.preview_services AS included ON included.service_id = service.id
JOIN control.previews AS preview ON preview.id = included.preview_id
WHERE run.id = sqlc.arg(service_run_id)
  AND run.service_id = sqlc.arg(service_id)
  AND preview.id = sqlc.arg(preview_id)
  AND run.run_number = sqlc.arg(run_number)
  AND run.publisher_expires_at > sqlc.arg(now)
  AND run.state IN ('starting', 'ready')
  AND run.closed_at IS NULL AND service.enabled AND service.deleted_at IS NULL AND service.protocol='http'
FOR UPDATE OF run;

-- name: FeedbackServiceScope :one
SELECT service.team_id,service.guest_id FROM control.services service
JOIN control.preview_services included ON included.service_id=service.id
WHERE service.id=sqlc.arg(service_id) AND included.preview_id=sqlc.arg(preview_id) AND service.protocol='http';

-- name: CreateServiceRunPreview :one
INSERT INTO control.previews (id, team_id, guest_id, created_by_identity_id, idempotency_key, created_at, demo_service_run_id)
SELECT sqlc.arg(id), u.team_id, u.guest_id, u.created_by_identity_id, 'demo/' || r.id,
    sqlc.arg(now)::timestamptz, r.id
FROM control.service_runs r JOIN control.services u ON u.id = r.service_id
WHERE r.id = sqlc.arg(service_run_id) AND r.service_id=sqlc.arg(service_id) AND r.run_number = sqlc.arg(run_number)
    AND r.closed_at IS NULL AND r.publisher_expires_at > sqlc.arg(now)
    AND u.ephemeral AND u.enabled AND u.deleted_at IS NULL AND u.protocol='http'
ON CONFLICT (demo_service_run_id) DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
RETURNING *;

-- name: AddServiceRunPreviewService :exec
INSERT INTO control.preview_services (preview_id, team_id, guest_id, service_id, added_at)
SELECT p.id, p.team_id, p.guest_id, r.service_id, sqlc.arg(now)::timestamptz
FROM control.previews p JOIN control.service_runs r ON r.id = p.demo_service_run_id
WHERE p.id = sqlc.arg(preview_id)
ON CONFLICT (preview_id, service_id) DO NOTHING;
