-- +goose Up
CREATE TABLE server_profiles (
    origin TEXT PRIMARY KEY,
    selected_team_id TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
) STRICT;

CREATE TABLE client_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    selected_server_origin TEXT REFERENCES server_profiles (origin) ON DELETE SET NULL,
    installation_id TEXT NOT NULL CHECK (
        installation_id = ''
        OR (
            length(installation_id) = 45
            AND substr(installation_id, 1, 13) = 'installation_'
            AND substr(installation_id, 14) NOT GLOB '*[^0-9a-f]*'
        )
    ),
    worktree_hash_salt BLOB NOT NULL CHECK (
        length(worktree_hash_salt) IN (0, 32)
    )
) STRICT;

INSERT INTO client_settings (id, installation_id, worktree_hash_salt)
VALUES (1, '', x'');

CREATE TABLE control_sessions (
    server_origin TEXT PRIMARY KEY REFERENCES server_profiles (origin) ON DELETE CASCADE,
    authority_endpoint TEXT NOT NULL,
    session_id TEXT NOT NULL,
    access_token BLOB NOT NULL,
    access_expires_at INTEGER NOT NULL,
    refresh_token BLOB NOT NULL,
    refresh_expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE certificate_material (
    server_origin TEXT NOT NULL REFERENCES server_profiles (origin) ON DELETE CASCADE,
    team_id TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    plan TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'current')),
    key_der BLOB NOT NULL,
    csr_der BLOB NOT NULL,
    certificate_pem BLOB,
    renew_at INTEGER,
    issuance_id TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, team_id, cache_key, plan, phase)
) STRICT;

CREATE TABLE local_tunnels (
    id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'tunnel_[0-9a-f]*'),
    command TEXT NOT NULL CHECK (command IN ('publish', 'dev')),
    process_id INTEGER NOT NULL CHECK (process_id > 0),
    server_origin TEXT NOT NULL REFERENCES server_profiles (origin) ON DELETE RESTRICT,
    project_root TEXT NOT NULL,
    service TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL,
    target TEXT NOT NULL,
    framework TEXT NOT NULL,
    public_url_id TEXT NOT NULL,
    publish_run_number INTEGER NOT NULL CHECK (publish_run_number >= 0),
    state TEXT NOT NULL CHECK (state IN ('starting', 'provisioning', 'ready', 'draining', 'stopped', 'failed')),
    started_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    heartbeat_at INTEGER NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    stopped_at INTEGER,
    last_error TEXT NOT NULL
) STRICT;

CREATE INDEX local_tunnels_open_idx
    ON local_tunnels (started_at, id)
    WHERE stopped_at IS NULL;

CREATE INDEX local_tunnels_project_open_idx
    ON local_tunnels (project_root, started_at, id)
    WHERE stopped_at IS NULL;

CREATE INDEX local_tunnels_cleanup_idx
    ON local_tunnels (stopped_at, lease_expires_at);
