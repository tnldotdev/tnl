-- +goose Up
CREATE TABLE server_profiles (
    id INTEGER PRIMARY KEY,
    origin TEXT NOT NULL UNIQUE,
    selected_team_id TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
) STRICT;

CREATE TABLE client_setting (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    selected_server_origin TEXT REFERENCES server_profiles (origin) ON DELETE SET NULL,
    installation_id TEXT NOT NULL CHECK (
        installation_id = ''
        OR (
            length(installation_id) = 27
            AND substr(installation_id, 1, 5) = 'inst_'
        )
    ),
    worktree_hash_salt BLOB NOT NULL CHECK (
        length(worktree_hash_salt) IN (0, 32)
    ),
    telemetry_enabled INTEGER NOT NULL DEFAULT 1 CHECK (telemetry_enabled IN (0, 1))
) STRICT;

INSERT INTO client_setting (id, installation_id, worktree_hash_salt)
VALUES (1, '', x'');

CREATE TABLE control_sessions (
    id INTEGER PRIMARY KEY,
    server_origin TEXT NOT NULL UNIQUE REFERENCES server_profiles (origin) ON DELETE CASCADE,
    authority_endpoint TEXT NOT NULL,
    session_id TEXT NOT NULL,
    stored_access_token BLOB NOT NULL,
    access_expires_at INTEGER NOT NULL,
    stored_refresh_token BLOB NOT NULL,
    refresh_expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE certificate_materials (
    id INTEGER PRIMARY KEY,
    server_origin TEXT NOT NULL REFERENCES server_profiles (origin) ON DELETE CASCADE,
    team_id TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    plan TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'current')),
    stored_key BLOB NOT NULL,
    csr_der BLOB NOT NULL,
    certificate_pem BLOB,
    renew_at INTEGER,
    issuance_id TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (server_origin, team_id, cache_key, plan, phase),
    CHECK ((certificate_pem IS NULL AND renew_at IS NULL AND issuance_id = '') OR
           (certificate_pem IS NOT NULL AND renew_at IS NOT NULL AND issuance_id <> '')),
    CHECK (phase <> 'current' OR certificate_pem IS NOT NULL)
) STRICT;

CREATE TABLE local_tunnels (
    id TEXT PRIMARY KEY CHECK (length(id) = 26 AND substr(id, 1, 4) = 'tun_'),
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
    last_error TEXT NOT NULL,
    CHECK ((state IN ('stopped', 'failed')) = (stopped_at IS NOT NULL)),
    CHECK (state NOT IN ('ready', 'draining') OR
           (public_url_id <> '' AND hostname <> '' AND publish_run_number > 0))
) STRICT;

CREATE INDEX local_tunnels_open_idx
    ON local_tunnels (started_at, id)
    WHERE stopped_at IS NULL;

CREATE INDEX local_tunnels_project_open_idx
    ON local_tunnels (project_root, started_at, id)
    WHERE stopped_at IS NULL;

CREATE INDEX local_tunnels_cleanup_idx
    ON local_tunnels (stopped_at, lease_expires_at);
