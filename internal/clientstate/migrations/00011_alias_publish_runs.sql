-- +goose Up
ALTER TABLE project_aliases ADD COLUMN failure_reason TEXT NOT NULL DEFAULT '';
CREATE TABLE alias_publish_runs (
    alias_id TEXT PRIMARY KEY REFERENCES project_aliases(id) ON DELETE CASCADE,
    owner TEXT NOT NULL,
    tunnel_id TEXT NOT NULL REFERENCES local_tunnels(id) ON DELETE CASCADE,
    selection_revision INTEGER NOT NULL CHECK (selection_revision > 0),
    public_url_id TEXT NOT NULL,
    publish_run_number INTEGER NOT NULL CHECK (publish_run_number > 0),
    target_public_url_id TEXT NOT NULL,
    target_publish_run_number INTEGER NOT NULL CHECK (target_publish_run_number > 0)
) STRICT;
ALTER TABLE oauth_callbacks ADD COLUMN origin_hostname TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_callbacks ADD COLUMN origin_public_url_id TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_callbacks ADD COLUMN origin_publish_run_number INTEGER NOT NULL DEFAULT 0;

CREATE TABLE oauth_alias_returns (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    state_digest BLOB NOT NULL CHECK (length(state_digest) = 32),
    callback_path TEXT NOT NULL,
    public_url_id TEXT NOT NULL,
    publish_run_number INTEGER NOT NULL CHECK (publish_run_number > 0),
    expires_at INTEGER NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1)),
    PRIMARY KEY (server_origin, hostname, state_digest)
) STRICT;

-- +goose Down
DROP TABLE oauth_alias_returns;
ALTER TABLE oauth_callbacks DROP COLUMN origin_publish_run_number;
ALTER TABLE oauth_callbacks DROP COLUMN origin_public_url_id;
ALTER TABLE oauth_callbacks DROP COLUMN origin_hostname;
DROP TABLE alias_publish_runs;
ALTER TABLE project_aliases DROP COLUMN failure_reason;
