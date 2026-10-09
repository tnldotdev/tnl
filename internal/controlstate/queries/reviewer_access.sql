-- reviewer writes and browser admission read current authority under the same
-- shared guard as publish run creation, before locking public URLs and runs.
-- guest previews have no local team row, but still use the same lock order.
-- name: LockReviewerTeam :exec
SELECT pg_advisory_xact_lock_shared(hashtextextended('tnl:local-team:' || sqlc.arg(team_id)::text, 0));
