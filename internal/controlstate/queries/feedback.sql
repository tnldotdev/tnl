-- name: ReserveFeedbackEventCursor :one
UPDATE control.feedback_event_clock
SET next_cursor = next_cursor + 1
WHERE id = 1 AND next_cursor < 9223372036854775807
RETURNING (next_cursor - 1)::bigint AS cursor;

-- name: FeedbackEventHighWater :one
SELECT (next_cursor - 1)::bigint AS cursor
FROM control.feedback_event_clock WHERE id = 1;

-- name: CreateFeedbackThread :one
INSERT INTO control.feedback_threads (
    id, preview_id, team_id, public_url_id, publish_run_id,
    publish_run_number, service, page_path, page_title, report_text, author_display_name,
    anchor, evidence, source_at_report, created_at, state_updated_at,
    idempotency_key, request_digest
) VALUES (
    sqlc.arg(id), sqlc.arg(preview_id), sqlc.arg(team_id), sqlc.arg(public_url_id),
    sqlc.arg(publish_run_id), sqlc.arg(publish_run_number), sqlc.arg(service),
    sqlc.arg(page_path), sqlc.arg(page_title), sqlc.arg(report_text), sqlc.narg(author_display_name),
    convert_from(sqlc.narg(anchor)::bytea, 'UTF8')::jsonb,
    convert_from(sqlc.arg(evidence)::bytea, 'UTF8')::jsonb,
    convert_from(sqlc.arg(source_at_report)::bytea, 'UTF8')::jsonb,
    sqlc.arg(created_at), sqlc.arg(state_updated_at),
    sqlc.arg(idempotency_key), sqlc.arg(request_digest)
)
ON CONFLICT (publish_run_id, idempotency_key)
DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
RETURNING *;

-- name: GetFeedbackThread :one
SELECT * FROM control.feedback_threads WHERE id = $1;

-- name: GetFeedbackPublicURL :one
SELECT * FROM control.public_urls WHERE id = $1;

-- name: LockFeedbackThread :one
SELECT * FROM control.feedback_threads WHERE id = $1 FOR UPDATE;

-- name: ListFeedbackThreadsForPage :many
SELECT * FROM control.feedback_threads
WHERE preview_id = sqlc.arg(preview_id)
  AND public_url_id = sqlc.arg(public_url_id)
   AND (sqlc.arg(page_path)::text = '' OR page_path = sqlc.arg(page_path))
   AND (sqlc.arg(thread_state)::text = '' OR state = sqlc.arg(thread_state))
  AND id > sqlc.arg(after_id)
ORDER BY id LIMIT 101;

-- name: ListFeedbackThreadsForTeam :many
SELECT * FROM control.feedback_threads
WHERE team_id = sqlc.arg(team_id)
  AND id > sqlc.arg(after_id)
ORDER BY id LIMIT 101;

-- name: GetFeedbackEventByActorKey :one
SELECT * FROM control.feedback_events
WHERE feedback_id = sqlc.arg(feedback_id)
  AND actor_kind = sqlc.arg(actor_kind)
  AND actor_reference = sqlc.arg(actor_reference)
  AND idempotency_key = sqlc.arg(idempotency_key);

-- name: InsertFeedbackEvent :one
INSERT INTO control.feedback_events (
    cursor, feedback_id, team_id, event_type, actor_kind,
    actor_reference, idempotency_key, request_digest, text,
    evidence, source_state, occurred_at
) VALUES (
    sqlc.arg(cursor), sqlc.arg(feedback_id), sqlc.arg(team_id),
    sqlc.arg(event_type), sqlc.arg(actor_kind), sqlc.arg(actor_reference),
    sqlc.arg(idempotency_key), sqlc.arg(request_digest),
    sqlc.narg(text),
    convert_from(sqlc.narg(evidence)::bytea, 'UTF8')::jsonb,
    convert_from(sqlc.narg(source_state)::bytea, 'UTF8')::jsonb,
    sqlc.arg(occurred_at)
)
RETURNING *;

-- name: RecordFeedbackActivity :exec
UPDATE control.feedback_threads
SET latest_event_cursor = sqlc.arg(event_cursor),
    message_count = message_count + CASE WHEN sqlc.arg(add_message)::boolean THEN 1 ELSE 0 END
WHERE id = sqlc.arg(feedback_id);

-- name: UpdateFeedbackThreadState :one
UPDATE control.feedback_threads
SET state = sqlc.arg(next_state), state_updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(feedback_id)
  AND state = sqlc.arg(expected_state)
RETURNING *;

-- name: ListFeedbackEventsForThread :many
SELECT * FROM control.feedback_events
WHERE feedback_id = sqlc.arg(feedback_id) AND cursor > sqlc.arg(after_cursor)
ORDER BY cursor LIMIT 26;

-- name: ListFeedbackEventsForTeam :many
SELECT * FROM control.feedback_events
WHERE team_id = sqlc.arg(team_id) AND cursor > sqlc.arg(after_cursor)
ORDER BY cursor LIMIT 26;

-- name: FeedbackRunScope :one
SELECT run.id AS publish_run_id, run.public_url_id, run.publish_run_number,
       url.team_id, preview.id AS preview_id
FROM control.publish_runs AS run
JOIN control.public_urls AS url ON url.id = run.public_url_id
JOIN control.preview_public_urls AS included ON included.public_url_id = url.id
JOIN control.previews AS preview ON preview.id = included.preview_id
WHERE run.id = sqlc.arg(publish_run_id)
  AND preview.id = sqlc.arg(preview_id)
  AND run.publish_run_number = sqlc.arg(publish_run_number)
  AND run.publisher_expires_at > sqlc.arg(now)
  AND run.state IN ('starting', 'ready')
   AND url.lifecycle_state = 'enabled'
FOR UPDATE OF run;

-- name: CreatePublishRunPreview :one
INSERT INTO control.previews (id, team_id, created_by_identity_id, idempotency_key, created_at, demo_publish_run_id)
SELECT sqlc.arg(id), u.team_id, u.created_by_identity_id, 'demo/' || r.id,
    sqlc.arg(now)::timestamptz, r.id
FROM control.publish_runs r JOIN control.public_urls u ON u.id = r.public_url_id
WHERE r.id = sqlc.arg(publish_run_id) AND r.publish_run_number = sqlc.arg(publish_run_number)
    AND r.closed_at IS NULL AND r.publisher_expires_at > sqlc.arg(now)
    AND u.ephemeral AND u.lifecycle_state = 'enabled'
ON CONFLICT (demo_publish_run_id) DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
RETURNING *;

-- name: AddPublishRunPreviewURL :exec
INSERT INTO control.preview_public_urls (preview_id, team_id, public_url_id, added_at)
SELECT p.id, p.team_id, r.public_url_id, sqlc.arg(now)::timestamptz
FROM control.previews p JOIN control.publish_runs r ON r.id = p.demo_publish_run_id
WHERE p.id = sqlc.arg(preview_id)
ON CONFLICT (preview_id, public_url_id) DO NOTHING;

-- name: ReviewerShareCookieValid :one
SELECT share.id FROM control.shares AS share
JOIN control.share_cookies AS cookie ON cookie.share_id = share.id
JOIN control.share_public_urls AS included ON included.share_id = share.id
WHERE share.id = sqlc.arg(share_id)
  AND cookie.public_url_id = sqlc.arg(public_url_id)
  AND included.public_url_id = sqlc.arg(public_url_id)
  AND cookie.token_digest = sqlc.arg(token_digest)
  AND cookie.expires_at > sqlc.arg(now)
  AND share.expires_at > sqlc.arg(now)
  AND share.revoked_at IS NULL;
