-- +goose Up
-- leave existing SELECT * result shapes unchanged for serving control processes.
ALTER TABLE control.browser_login_attempts ALTER COLUMN preview_id DROP NOT NULL;
ALTER TABLE control.browser_access_sessions ALTER COLUMN preview_id DROP NOT NULL;
CREATE TABLE control.publish_run_browser_capabilities (
    publish_run_id text PRIMARY KEY REFERENCES control.publish_runs(id) ON DELETE CASCADE
);
CREATE TABLE control.team_feedback_policies (
    team_id text PRIMARY KEY REFERENCES control.teams(id) ON DELETE CASCADE,
    require_sign_in boolean NOT NULL DEFAULT false
);

-- +goose Down
DROP TABLE control.team_feedback_policies;
DROP TABLE control.publish_run_browser_capabilities;
ALTER TABLE control.browser_access_sessions ALTER COLUMN preview_id SET NOT NULL;
ALTER TABLE control.browser_login_attempts ALTER COLUMN preview_id SET NOT NULL;
