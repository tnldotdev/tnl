-- +goose Up
-- keep the administrator's browser session tied to its issuing CLI session.
CREATE TABLE control.browser_admin_sessions (
    browser_token_digest bytea PRIMARY KEY REFERENCES control.browser_access_sessions(token_digest) ON DELETE CASCADE,
    parent_control_session_id text NOT NULL REFERENCES control.control_sessions(id) ON DELETE RESTRICT
);
CREATE INDEX browser_admin_sessions_parent ON control.browser_admin_sessions(parent_control_session_id);

-- +goose Down
DROP TABLE control.browser_admin_sessions;
