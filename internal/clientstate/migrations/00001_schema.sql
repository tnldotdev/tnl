-- +goose Up
CREATE TABLE server_profiles (
    origin TEXT PRIMARY KEY,
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
    )
) STRICT;

INSERT INTO client_settings (id, installation_id) VALUES (1, '');

CREATE TABLE control_sessions (
    server_origin TEXT PRIMARY KEY REFERENCES server_profiles (origin) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('core', 'authorization_authority')),
    control_endpoint TEXT NOT NULL,
    session_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    access_token BLOB NOT NULL,
    access_expires_at INTEGER NOT NULL,
    refresh_token BLOB NOT NULL,
    refresh_expires_at INTEGER NOT NULL,
    grants BLOB NOT NULL,
    scopes BLOB NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE route_certificates (
    server_origin TEXT NOT NULL REFERENCES server_profiles (origin) ON DELETE CASCADE,
    route_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'current')),
    hostname TEXT NOT NULL,
    key_der BLOB NOT NULL,
    csr_der BLOB NOT NULL,
    certificate_pem BLOB,
    renew_at INTEGER,
    issuance_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 0),
    installed INTEGER NOT NULL CHECK (installed IN (0, 1)),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, route_id, phase)
) STRICT;

CREATE TABLE local_tunnels (
    id TEXT PRIMARY KEY CHECK (length(id) = 39 AND id GLOB 'tunnel_[0-9a-f]*'),
    command TEXT NOT NULL CHECK (command IN ('publish', 'dev')),
    process_id INTEGER NOT NULL CHECK (process_id > 0),
    server_origin TEXT NOT NULL REFERENCES server_profiles (origin) ON DELETE RESTRICT,
    hostname TEXT NOT NULL,
    target TEXT NOT NULL,
    framework TEXT NOT NULL,
    route_id TEXT NOT NULL,
    session_version INTEGER NOT NULL CHECK (session_version >= 0),
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

CREATE INDEX local_tunnels_cleanup_idx
    ON local_tunnels (stopped_at, lease_expires_at);
