-- +goose Up
-- retirement reads only the latest closed publish run for each saved URL.
CREATE INDEX publish_runs_latest_closed_for_idle
    ON control.publish_runs (public_url_id, closed_at DESC)
    WHERE closed_at IS NOT NULL;

-- +goose Down
DROP INDEX control.publish_runs_latest_closed_for_idle;
