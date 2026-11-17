-- name: EnsureFeedbackClock :exec
INSERT INTO feedback_clocks(server_origin,project_root,preview_id) VALUES (?,?,?)
ON CONFLICT DO NOTHING;

-- name: LocalFeedbackServices :many
SELECT DISTINCT service_id FROM feedback_threads
WHERE server_origin=? AND project_root=? AND preview_id=? ORDER BY service_id;

-- name: SetDemoFeedbackRetention :exec
UPDATE feedback_clocks SET expires_at=?
WHERE server_origin=? AND project_root=? AND preview_id=?;

-- name: PruneExpiredLocalFeedback :exec
DELETE FROM feedback_clocks WHERE expires_at IS NOT NULL AND expires_at<=?;

-- name: ExpiredLocalFeedbackCount :one
SELECT count(*) FROM feedback_clocks WHERE expires_at IS NOT NULL AND expires_at<=?;

-- name: DiscardDemoFeedback :exec
DELETE FROM feedback_clocks WHERE server_origin=? AND project_root=? AND preview_id=?;

-- name: ReserveLocalFeedbackCursor :one
UPDATE feedback_clocks SET cursor=cursor+1
WHERE server_origin=? AND project_root=? AND preview_id=? AND cursor<9223372036854775807
RETURNING cursor;

-- name: LocalFeedbackHighWater :one
SELECT cursor FROM feedback_clocks WHERE server_origin=? AND project_root=? AND preview_id=?;

-- name: GetLocalFeedbackThread :one
SELECT * FROM feedback_threads WHERE server_origin=? AND project_root=? AND preview_id=? AND id=?;

-- name: LocalFeedbackReportRetry :one
SELECT * FROM feedback_threads WHERE server_origin=? AND project_root=? AND preview_id=?
AND service_id=? AND service_run_id=? AND actor_reference=? AND idempotency_key=?;

-- name: CreateLocalFeedbackThread :exec
INSERT INTO feedback_threads(id,server_origin,project_root,preview_id,service_id,service_run_id,page_path,state,
    latest_event_cursor,report,actor_reference,idempotency_key,request_digest)
VALUES (?,?,?,?,?,?,?,'open',?,?,?,?,?);

-- name: ListLocalFeedbackThreads :many
SELECT * FROM feedback_threads
WHERE server_origin=sqlc.arg(server_origin) AND project_root=sqlc.arg(project_root) AND preview_id=sqlc.arg(preview_id)
AND (sqlc.arg(service_id)='' OR service_id=sqlc.arg(service_id))
AND (sqlc.arg(page_path)='' OR page_path=sqlc.arg(page_path))
AND (sqlc.arg(thread_state)='' OR state=sqlc.arg(thread_state))
AND id>sqlc.arg(after_id) ORDER BY id LIMIT 101;

-- name: LocalFeedbackEventRetry :one
SELECT * FROM feedback_events WHERE feedback_id=? AND actor_kind=? AND actor_reference=? AND idempotency_key=?;

-- name: InsertLocalFeedbackEvent :exec
INSERT INTO feedback_events(feedback_id,cursor,actor_kind,actor_reference,idempotency_key,request_digest,event)
VALUES (?,?,?,?,?,?,?);

-- name: UpdateLocalFeedbackActivity :exec
UPDATE feedback_threads SET state=sqlc.arg(next_state),latest_event_cursor=sqlc.arg(cursor),
message_count=message_count+sqlc.arg(add_message) WHERE id=sqlc.arg(id);

-- name: ListLocalFeedbackEvents :many
SELECT e.* FROM feedback_events e JOIN feedback_threads t ON t.id=e.feedback_id
WHERE t.server_origin=sqlc.arg(server_origin) AND t.project_root=sqlc.arg(project_root) AND t.preview_id=sqlc.arg(preview_id)
AND (sqlc.arg(service_id)='' OR t.service_id=sqlc.arg(service_id))
AND (sqlc.arg(feedback_id)='' OR t.id=sqlc.arg(feedback_id))
AND e.cursor>sqlc.arg(after_cursor) ORDER BY e.cursor LIMIT 26;

-- name: DeleteLocalFeedbackThread :execrows
DELETE FROM feedback_threads WHERE server_origin=? AND project_root=? AND preview_id=? AND id=? AND service_id=?;
