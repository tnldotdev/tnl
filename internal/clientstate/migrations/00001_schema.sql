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
    session_id TEXT NOT NULL,
    stored_access_token BLOB NOT NULL,
    access_expires_at INTEGER NOT NULL,
    stored_refresh_token BLOB NOT NULL,
    refresh_expires_at INTEGER NOT NULL,
    refresh_pending INTEGER NOT NULL DEFAULT 0 CHECK (refresh_pending IN (0, 1)),
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
    service_protocol TEXT NOT NULL DEFAULT 'http' CHECK (service_protocol IN ('http', 'postgres', 'mysql', 'redis', 'ssh')),
    public_port INTEGER NOT NULL DEFAULT 0 CHECK (public_port BETWEEN 0 AND 65535),
    integration_group TEXT NOT NULL DEFAULT '',
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

CREATE INDEX local_tunnels_integration_group_idx ON local_tunnels (integration_group, lease_expires_at)
    WHERE stopped_at IS NULL;

-- locally observed public URL IDs let status read server state after a tunnel
-- stops. the cache contains no credentials or targets and is bounded per
-- project/server, including projects that create many temporary URLs.
CREATE TABLE local_project_url_inventory (
    project_root TEXT NOT NULL,
    server_origin TEXT NOT NULL,
    public_url_id TEXT NOT NULL,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (project_root, server_origin, public_url_id)
) STRICT;

-- +goose StatementBegin
CREATE TRIGGER local_project_url_seen AFTER UPDATE OF public_url_id ON local_tunnels
WHEN NEW.public_url_id <> '' BEGIN
    INSERT INTO local_project_url_inventory (project_root, server_origin, public_url_id, last_seen_at)
    VALUES (NEW.project_root, NEW.server_origin, NEW.public_url_id, NEW.updated_at)
    ON CONFLICT (project_root, server_origin, public_url_id)
    DO UPDATE SET last_seen_at = excluded.last_seen_at;
    DELETE FROM local_project_url_inventory
    WHERE project_root = NEW.project_root AND server_origin = NEW.server_origin
      AND last_seen_at < NEW.updated_at - 2592000000000000;
    DELETE FROM local_project_url_inventory
    WHERE rowid IN (
        SELECT rowid FROM local_project_url_inventory
        WHERE project_root = NEW.project_root AND server_origin = NEW.server_origin
        ORDER BY last_seen_at DESC, public_url_id LIMIT -1 OFFSET 256
    );
END;
-- +goose StatementEnd

CREATE TABLE guest_sessions (
    server_origin TEXT PRIMARY KEY REFERENCES server_profiles (origin) ON DELETE CASCADE,
    guest_id TEXT NOT NULL,
    stored_access_token BLOB NOT NULL,
    team_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE previews (
    server_origin TEXT NOT NULL REFERENCES server_profiles (origin) ON DELETE CASCADE,
    team_id TEXT NOT NULL CHECK (team_id <> ''),
    project_root TEXT NOT NULL CHECK (project_root <> ''),
    preview_id TEXT NOT NULL CHECK (preview_id <> ''),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, team_id, project_root)
) STRICT;

CREATE TABLE telemetry_outbox (
    event_id TEXT PRIMARY KEY CHECK (length(event_id) = 26 AND substr(event_id, 1, 4) = 'tev_'),
    created_at INTEGER NOT NULL,
    event_json TEXT NOT NULL CHECK (json_valid(event_json))
) STRICT;
CREATE INDEX telemetry_outbox_oldest_idx ON telemetry_outbox (created_at, event_id);

CREATE TABLE integration_url_publishers (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    publisher_instance_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, hostname)
) STRICT;

CREATE TABLE integration_url_hostnames (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    project_key TEXT NOT NULL,
    namespace TEXT NOT NULL,
    purpose TEXT NOT NULL,
    hostname TEXT NOT NULL,
    PRIMARY KEY (server_origin, project_key, namespace, purpose)
) STRICT;

CREATE TABLE oauth_callbacks (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    state_digest BLOB NOT NULL,
    tunnel_id TEXT NOT NULL REFERENCES local_tunnels(id) ON DELETE CASCADE,
    callback_path TEXT NOT NULL,
    callback_query TEXT NOT NULL,
    public_url_id TEXT NOT NULL,
    publish_run_number INTEGER NOT NULL CHECK (publish_run_number > 0),
    expires_at INTEGER NOT NULL,
    origin_hostname TEXT NOT NULL DEFAULT '',
    origin_public_url_id TEXT NOT NULL DEFAULT '',
    origin_publish_run_number INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (server_origin, hostname, state_digest)
) STRICT;
CREATE INDEX oauth_callbacks_expiry_idx ON oauth_callbacks (expires_at);

CREATE TABLE webhook_endpoints (
    tunnel_id TEXT NOT NULL REFERENCES local_tunnels(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    service TEXT NOT NULL,
    path TEXT NOT NULL,
    definition BLOB NOT NULL,
    fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
    PRIMARY KEY (tunnel_id, name)
) STRICT;

CREATE TABLE webhook_owners (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    integration_group TEXT NOT NULL,
    name TEXT NOT NULL,
    tunnel_id TEXT NOT NULL REFERENCES local_tunnels(id) ON DELETE CASCADE,
    PRIMARY KEY (server_origin, integration_group, name)
) STRICT;

CREATE TABLE project_aliases (
    id TEXT PRIMARY KEY,
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    project_key TEXT NOT NULL,
    team_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    service TEXT NOT NULL,
    fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
    selected_project TEXT NOT NULL,
    selection_revision INTEGER NOT NULL CHECK (selection_revision > 0),
    failure_reason TEXT NOT NULL DEFAULT '',
    UNIQUE (server_origin, project_key, team_id, membership_id, namespace, name),
    UNIQUE (server_origin, hostname)
) STRICT;

CREATE TABLE alias_declarations (
    alias_id TEXT NOT NULL REFERENCES project_aliases(id) ON DELETE CASCADE,
    tunnel_id TEXT NOT NULL REFERENCES local_tunnels(id) ON DELETE CASCADE,
    fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
    PRIMARY KEY (alias_id, tunnel_id)
) STRICT;

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

CREATE TABLE webhook_catalog (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    source_json TEXT NOT NULL CHECK (length(source_json) BETWEEN 1 AND 16384),
    etag TEXT NOT NULL CHECK (length(etag) <= 128),
    checked_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, provider)
) STRICT;

CREATE TABLE auth_operations (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    operation_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'redeeming', 'credential_received', 'exchanging', 'issued', 'completed', 'cancelled', 'denied', 'expired', 'recovery_required')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    public_json TEXT NOT NULL CHECK (length(public_json) BETWEEN 1 AND 32768),
    stored_private BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, operation_id)
) STRICT;

CREATE TABLE local_inspections (
    row_id INTEGER PRIMARY KEY,
    number INTEGER NOT NULL,
    primary_checkout_root TEXT NOT NULL,
    tunnel_id TEXT NOT NULL,
    project_root TEXT NOT NULL,
    shared_project_root TEXT NOT NULL,
    service TEXT NOT NULL,
    service_protocol TEXT NOT NULL CHECK (service_protocol IN ('http', 'postgres', 'mysql', 'redis')),
    received_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    stored_bytes INTEGER NOT NULL CHECK (stored_bytes > 0),
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
    origin TEXT NOT NULL CHECK (origin IN ('local_service', 'tnl')),
    sql_operation TEXT NOT NULL DEFAULT '' CHECK (sql_operation IN ('', 'query', 'execute')),
    result TEXT NOT NULL DEFAULT '' CHECK (result IN ('', 'ok', 'error')),
    redis_command TEXT NOT NULL DEFAULT '' CHECK (length(redis_command) <= 64),
    sql_state TEXT NOT NULL DEFAULT '' CHECK (length(sql_state) IN (0, 5)),
    sql_rows INTEGER NOT NULL DEFAULT 0 CHECK (sql_rows >= 0),
    mysql_result_sets INTEGER NOT NULL DEFAULT 0 CHECK (mysql_result_sets >= 0),
    mysql_error_code INTEGER NOT NULL DEFAULT 0 CHECK (mysql_error_code BETWEEN 0 AND 65535),
    CHECK (
      (service_protocol = 'http' AND method != '' AND status BETWEEN 100 AND 599 AND sql_operation = '' AND result = '' AND redis_command = '')
      OR (service_protocol IN ('postgres', 'mysql') AND method = '' AND path = '' AND status = 0
          AND sql_operation != '' AND result != '' AND redis_command = '')
      OR (service_protocol = 'redis' AND method = '' AND path = '' AND status = 0
          AND sql_operation = '' AND result != '' AND redis_command != '' AND sql_state = ''
          AND sql_rows = 0 AND mysql_result_sets = 0 AND mysql_error_code = 0)
    ),
    UNIQUE (primary_checkout_root, number)
) STRICT;

CREATE TABLE local_inspection_counters (
    primary_checkout_root TEXT PRIMARY KEY,
    last_number INTEGER NOT NULL CHECK (last_number > 0)
) STRICT;

CREATE TABLE local_inspection_usage (
    project_root TEXT NOT NULL,
    service TEXT NOT NULL,
    used_bytes INTEGER NOT NULL CHECK (used_bytes >= 0),
    PRIMARY KEY (project_root, service)
) STRICT;

-- +goose StatementBegin
CREATE TRIGGER local_inspections_added AFTER INSERT ON local_inspections BEGIN
    INSERT INTO local_inspection_usage (project_root, service, used_bytes)
        VALUES (NEW.project_root, NEW.service, NEW.stored_bytes)
        ON CONFLICT (project_root, service) DO UPDATE SET used_bytes = used_bytes + excluded.used_bytes;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER local_inspections_removed AFTER DELETE ON local_inspections BEGIN
    UPDATE local_inspection_usage SET used_bytes = used_bytes - OLD.stored_bytes
        WHERE project_root = OLD.project_root AND service = OLD.service;
END;
-- +goose StatementEnd

CREATE INDEX local_inspections_project_idx ON local_inspections (project_root, service, received_at DESC, row_id DESC);
CREATE INDEX local_inspections_shared_project_idx ON local_inspections (shared_project_root, received_at DESC, row_id DESC);
CREATE INDEX local_inspections_expiry_idx ON local_inspections (expires_at);

CREATE TABLE state_protection (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    protector TEXT NOT NULL CHECK (protector IN ('keychain', 'file')),
    key_check BLOB NOT NULL
) STRICT;

CREATE TABLE publisher_signing_identities (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 1024),
    identity_id TEXT NOT NULL CHECK (length(identity_id) BETWEEN 1 AND 256),
    public_value BLOB NOT NULL CHECK (length(public_value) BETWEEN 1 AND 65536),
    stored_private BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, scope)
) STRICT;

CREATE TABLE system_state (
    name TEXT PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 256),
    stored_value BLOB NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- the project row survives event eviction and publisher cleanup. its epoch
-- distinguishes cursors from other projects and a fresh database.
CREATE TABLE project_runtime (
    project_root TEXT PRIMARY KEY,
    epoch TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))) CHECK (length(epoch) = 32),
    sequence INTEGER NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    app_sequence INTEGER NOT NULL DEFAULT 0 CHECK (app_sequence >= 0 AND app_sequence <= sequence),
    observed_at INTEGER NOT NULL DEFAULT 0,
    services_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(services_json) AND json_type(services_json) = 'array')
) STRICT;

CREATE TABLE project_runtime_events (
    project_root TEXT NOT NULL REFERENCES project_runtime(project_root) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    created_at INTEGER NOT NULL,
    payload TEXT NOT NULL CHECK (json_valid(payload)),
    stored_bytes INTEGER NOT NULL CHECK (stored_bytes BETWEEN 1 AND 8388608),
    PRIMARY KEY (project_root, sequence)
) STRICT;

-- +goose StatementBegin
CREATE TRIGGER project_runtime_event_retention AFTER INSERT ON project_runtime_events BEGIN
    UPDATE project_runtime_events SET stored_bytes = length(CAST(NEW.payload AS BLOB)) + length(CAST(json_quote(NEW.event_type) AS BLOB)) + 128
        WHERE project_root = NEW.project_root AND sequence = NEW.sequence;
    DELETE FROM project_runtime_events WHERE project_root = NEW.project_root AND sequence <= (
        SELECT max(sequence) FROM (
            SELECT sequence,
                row_number() OVER (ORDER BY sequence DESC) AS count,
                sum(stored_bytes) OVER (ORDER BY sequence DESC) AS bytes
            FROM project_runtime_events WHERE project_root = NEW.project_root
        ) WHERE count > 2048 OR bytes > 8388608
    );
END;
-- +goose StatementEnd

-- both publication triggers use the complete public TunnelInfo observation.
-- integer seconds and nanoseconds avoid SQLite's floating-point time rounding.
CREATE VIEW local_tunnel_publication_observations AS
SELECT id,
    json_object('publication', json_object(
        'tunnel_id', id, 'command', command, 'state', state, 'process_id', process_id,
        'server', server_origin, 'project', project_root, 'service', service,
        'service_protocol', CASE WHEN service_protocol = 'http' THEN '' ELSE service_protocol END,
        'public_url_id', public_url_id, 'publish_run_number', publish_run_number,
        'public_port', public_port, 'hostname', hostname,
        'public_url', CASE WHEN hostname = '' THEN '' WHEN public_port > 0 THEN hostname || ':' || public_port
            WHEN service_protocol = 'http' THEN 'https://' || hostname ELSE '' END,
        'target', target, 'framework', framework, 'failure', last_error,
        'started_at', CASE WHEN started_at = 0 THEN '0001-01-01T00:00:00Z' ELSE
            strftime('%Y-%m-%dT%H:%M:%S', started_at / 1000000000 - (started_at % 1000000000 < 0), 'unixepoch')
            || printf('.%09dZ', (started_at % 1000000000 + 1000000000) % 1000000000) END,
        'updated_at', CASE WHEN updated_at = 0 THEN '0001-01-01T00:00:00Z' ELSE
            strftime('%Y-%m-%dT%H:%M:%S', updated_at / 1000000000 - (updated_at % 1000000000 < 0), 'unixepoch')
            || printf('.%09dZ', (updated_at % 1000000000 + 1000000000) % 1000000000) END,
        'heartbeat_at', CASE WHEN heartbeat_at = 0 THEN '0001-01-01T00:00:00Z' ELSE
            strftime('%Y-%m-%dT%H:%M:%S', heartbeat_at / 1000000000 - (heartbeat_at % 1000000000 < 0), 'unixepoch')
            || printf('.%09dZ', (heartbeat_at % 1000000000 + 1000000000) % 1000000000) END,
        'lease_expires_at', CASE WHEN lease_expires_at = 0 THEN '0001-01-01T00:00:00Z' ELSE
            strftime('%Y-%m-%dT%H:%M:%S', lease_expires_at / 1000000000 - (lease_expires_at % 1000000000 < 0), 'unixepoch')
            || printf('.%09dZ', (lease_expires_at % 1000000000 + 1000000000) % 1000000000) END
    )) AS payload
FROM local_tunnels;

-- publications and app observations share the project row and event table.
-- heartbeats do not create events; publication mutations do, for every protocol
-- and for direct invocations with no configured service name.
-- +goose StatementBegin
CREATE TRIGGER project_publication_started AFTER INSERT ON local_tunnels BEGIN
    INSERT INTO project_runtime (project_root) VALUES (NEW.project_root) ON CONFLICT DO NOTHING;
    UPDATE project_runtime SET sequence = sequence + 1, observed_at = NEW.updated_at WHERE project_root = NEW.project_root;
    INSERT INTO project_runtime_events (project_root, sequence, event_type, created_at, payload, stored_bytes)
    SELECT NEW.project_root, sequence, 'publication.started', NEW.updated_at,
        observation.payload, 1
    FROM project_runtime JOIN local_tunnel_publication_observations observation ON observation.id = NEW.id
    WHERE project_root = NEW.project_root;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER project_publication_changed AFTER UPDATE ON local_tunnels
WHEN NEW.state <> OLD.state OR NEW.hostname <> OLD.hostname OR NEW.public_port <> OLD.public_port
    OR NEW.target <> OLD.target OR NEW.publish_run_number <> OLD.publish_run_number
    OR NEW.public_url_id <> OLD.public_url_id OR NEW.framework <> OLD.framework OR NEW.last_error <> OLD.last_error
BEGIN
    UPDATE project_runtime SET sequence = sequence + 1, observed_at = NEW.updated_at WHERE project_root = NEW.project_root;
    INSERT INTO project_runtime_events (project_root, sequence, event_type, created_at, payload, stored_bytes)
    SELECT NEW.project_root, sequence, 'publication.changed', NEW.updated_at,
        observation.payload, 1
    FROM project_runtime JOIN local_tunnel_publication_observations observation ON observation.id = NEW.id
    WHERE project_root = NEW.project_root;
END;
-- +goose StatementEnd
