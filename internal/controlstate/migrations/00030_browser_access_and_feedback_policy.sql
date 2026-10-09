-- +goose Up
-- prepare browser sessions and feedback policy before enabling their writers.
ALTER TABLE control.browser_login_attempts ALTER COLUMN preview_id DROP NOT NULL;
ALTER TABLE control.browser_access_sessions ALTER COLUMN preview_id DROP NOT NULL;
ALTER TABLE control.publish_runs ADD COLUMN browser_capable boolean NOT NULL DEFAULT false;
ALTER TABLE control.teams ADD COLUMN feedback_require_sign_in boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE control.teams DROP COLUMN feedback_require_sign_in;
ALTER TABLE control.publish_runs DROP COLUMN browser_capable;
ALTER TABLE control.browser_access_sessions ALTER COLUMN preview_id SET NOT NULL;
ALTER TABLE control.browser_login_attempts ALTER COLUMN preview_id SET NOT NULL;
