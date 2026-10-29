-- +goose Up
CREATE TABLE baseline_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    identity TEXT NOT NULL CHECK (identity = 'tnl-client-fresh-v1-services')
) STRICT;
INSERT INTO baseline_identity (id, identity) VALUES (1, 'tnl-client-fresh-v1-services');

-- provisioning journals are append-only and protected by the client wrapping
-- key. no expiration may discard a key after a remote enrollment committed.
CREATE TABLE publisher_provision_journal (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('group', 'aws')),
    binding_key TEXT NOT NULL CHECK (length(binding_key) BETWEEN 1 AND 1024),
    revision INTEGER NOT NULL CHECK (revision > 0),
    document_ciphertext BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, kind, binding_key, revision)
) STRICT;

CREATE TABLE service_client_certificates (
    server_origin TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    private_key_ciphertext BLOB NOT NULL,
    csr_der BLOB,
    -- successful request retained for session rebinding; csr_der is a pending renewal
    issued_csr_der BLOB,
    csr_created_at INTEGER NOT NULL DEFAULT 0,
    certificate_pem BLOB,
    issuer_pem BLOB,
    PRIMARY KEY(server_origin,identity_id,service_id,device_id)
);
CREATE TABLE server_profiles (
    id INTEGER PRIMARY KEY,
    origin TEXT NOT NULL UNIQUE,
    selected_team_id TEXT,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
) STRICT;

-- one remembered localhost port per signed-in identity and saved private
-- service. a unique port also prevents two server profiles from silently
-- assigning the same GUI endpoint.
CREATE TABLE service_ports (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    identity_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    port INTEGER NOT NULL UNIQUE CHECK (port BETWEEN 1 AND 65535),
    PRIMARY KEY (server_origin, identity_id, service_id)
) STRICT;

-- visitor device signing keys use the same wrapping key as control sessions.
-- an empty device_id is a durable pending enrollment, safe to retry.
CREATE TABLE visitor_devices (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    identity_id TEXT NOT NULL CHECK (length(identity_id) BETWEEN 1 AND 255),
    device_id TEXT NOT NULL DEFAULT '' CHECK (length(device_id) <= 255),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    signing_key_ciphertext BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, identity_id)
) STRICT;

-- connector status is local lifecycle state, never a source of authority or a
-- place for session tokens, provider addresses, TLS keys, or credentials.
CREATE TABLE connectors (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    identity_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'mysql', 'postgres')),
    process_id INTEGER NOT NULL CHECK (process_id > 0),
    listen_port INTEGER NOT NULL UNIQUE CHECK (listen_port BETWEEN 1 AND 65535),
    state TEXT NOT NULL CHECK (state IN ('starting', 'ready', 'stopped', 'failed')),
    updated_at INTEGER NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, identity_id, service_id)
) STRICT;

CREATE TABLE installation_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    selected_server_origin TEXT REFERENCES server_profiles (origin) ON DELETE SET NULL,
    installation_id TEXT CHECK (
        installation_id IS NULL OR (length(installation_id) = 27 AND substr(installation_id, 1, 5) = 'inst_')
    ),
    worktree_hash_salt BLOB CHECK (worktree_hash_salt IS NULL OR length(worktree_hash_salt) = 32),
    telemetry_enabled INTEGER NOT NULL DEFAULT 1 CHECK (telemetry_enabled IN (0, 1)),
    telemetry_epoch INTEGER NOT NULL DEFAULT 0 CHECK (telemetry_epoch >= 0)
) STRICT;

INSERT INTO installation_settings (id) VALUES (1);

-- +goose StatementBegin
CREATE TRIGGER telemetry_preference_changed AFTER UPDATE OF telemetry_enabled ON installation_settings
WHEN OLD.telemetry_enabled <> NEW.telemetry_enabled BEGIN
    UPDATE installation_settings SET telemetry_epoch = telemetry_epoch + 1 WHERE id = NEW.id;
END;
-- +goose StatementEnd

CREATE TABLE control_sessions (
    id INTEGER PRIMARY KEY,
    server_origin TEXT NOT NULL UNIQUE REFERENCES server_profiles (origin) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    access_token_ciphertext BLOB NOT NULL,
    access_expires_at INTEGER NOT NULL,
    refresh_token_ciphertext BLOB NOT NULL,
    refresh_expires_at INTEGER NOT NULL,
    refresh_pending INTEGER NOT NULL DEFAULT 0 CHECK (refresh_pending IN (0, 1)),
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE local_tunnels (
    id TEXT PRIMARY KEY CHECK (length(id) = 26 AND substr(id, 1, 4) = 'tun_'),
    command TEXT NOT NULL CHECK (command IN ('publish', 'dev')),
    process_id INTEGER NOT NULL CHECK (process_id > 0),
    server_origin TEXT NOT NULL REFERENCES server_profiles (origin) ON DELETE RESTRICT,
    project_root TEXT NOT NULL,
    service TEXT CHECK (service IS NULL OR service <> ''),
    service_protocol TEXT NOT NULL DEFAULT 'http' CHECK (service_protocol = 'http'),
    primary_project_root TEXT,
    integration_namespace TEXT,
    -- compatibility projection for the native caller's existing group key;
    -- only the two components are persisted.
    integration_group TEXT GENERATED ALWAYS AS (
        CASE WHEN primary_project_root IS NULL THEN ''
             ELSE primary_project_root || char(0) || integration_namespace END
    ) VIRTUAL NOT NULL,
    hostname TEXT CHECK (hostname IS NULL OR hostname <> ''),
    target TEXT CHECK (target IS NULL OR target <> ''),
    framework TEXT CHECK (framework IS NULL OR framework <> ''),
    public_url_id TEXT CHECK (public_url_id IS NULL OR public_url_id <> ''),
    publish_run_number INTEGER CHECK (publish_run_number IS NULL OR publish_run_number > 0),
    state TEXT NOT NULL CHECK (state IN ('starting', 'provisioning', 'ready', 'draining', 'stopped', 'failed')),
    started_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    heartbeat_at INTEGER NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    stopped_at INTEGER,
    failure_code TEXT CHECK (failure_code IS NULL OR failure_code <> ''),
    CHECK ((state IN ('stopped', 'failed')) = (stopped_at IS NOT NULL)),
    CHECK (state NOT IN ('ready', 'draining') OR
           (public_url_id IS NOT NULL AND hostname IS NOT NULL AND publish_run_number IS NOT NULL)),
    CHECK (failure_code IS NULL OR state = 'failed'),
    CHECK ((primary_project_root IS NULL AND integration_namespace IS NULL) OR
           (primary_project_root IS NOT NULL AND primary_project_root <> '' AND instr(primary_project_root, char(0)) = 0 AND
            integration_namespace IS NOT NULL AND integration_namespace <> '' AND instr(integration_namespace, char(0)) = 0))
) STRICT;

CREATE INDEX local_tunnels_open_idx
    ON local_tunnels (started_at, id)
    WHERE stopped_at IS NULL;

CREATE INDEX local_tunnels_project_open_idx
    ON local_tunnels (project_root, started_at, id)
    WHERE stopped_at IS NULL;

CREATE INDEX local_tunnels_cleanup_idx
    ON local_tunnels (stopped_at, lease_expires_at);

CREATE INDEX local_tunnels_integration_group_idx ON local_tunnels (server_origin, primary_project_root, integration_namespace, lease_expires_at)
    WHERE stopped_at IS NULL;

-- locally observed public URL IDs let status read server state after a tunnel
-- stops. the cache contains no credentials or targets and is bounded per
-- project/server, including projects that create many temporary URLs.
CREATE TABLE project_url_inventory (
    project_root TEXT NOT NULL,
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    public_url_id TEXT NOT NULL,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (project_root, server_origin, public_url_id)
) STRICT;

-- +goose StatementBegin
CREATE TRIGGER local_project_url_seen AFTER UPDATE OF public_url_id ON local_tunnels
WHEN NEW.public_url_id IS NOT NULL BEGIN
    INSERT INTO project_url_inventory (project_root, server_origin, public_url_id, last_seen_at)
    VALUES (NEW.project_root, NEW.server_origin, NEW.public_url_id, NEW.updated_at)
    ON CONFLICT (project_root, server_origin, public_url_id)
    DO UPDATE SET last_seen_at = excluded.last_seen_at;
    DELETE FROM project_url_inventory
    WHERE project_root = NEW.project_root AND server_origin = NEW.server_origin
      AND last_seen_at < NEW.updated_at - 2592000000000000;
    DELETE FROM project_url_inventory
    WHERE rowid IN (
        SELECT rowid FROM project_url_inventory
        WHERE project_root = NEW.project_root AND server_origin = NEW.server_origin
        ORDER BY last_seen_at DESC, public_url_id LIMIT -1 OFFSET 256
    );
END;
-- +goose StatementEnd

CREATE TABLE guest_demo_sessions (
    server_origin TEXT PRIMARY KEY REFERENCES server_profiles (origin) ON DELETE CASCADE,
    guest_id TEXT NOT NULL,
    access_token_ciphertext BLOB NOT NULL,
    team_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE project_previews (
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
    event_json TEXT NOT NULL CHECK (json_valid(event_json)),
    client_json TEXT NOT NULL DEFAULT 'null' CHECK (json_valid(client_json) AND json_type(client_json) = 'object')
) STRICT;
CREATE INDEX telemetry_outbox_oldest_idx ON telemetry_outbox (created_at, event_id);

CREATE TABLE integration_url_leases (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    publisher_instance_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, hostname)
) STRICT;

CREATE TABLE integration_url_hostnames (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    primary_project_root TEXT NOT NULL,
    namespace TEXT NOT NULL,
    purpose TEXT NOT NULL,
    hostname TEXT NOT NULL,
    PRIMARY KEY (server_origin, primary_project_root, namespace, purpose)
) STRICT;

CREATE TABLE oauth_pending_callbacks (
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
CREATE INDEX oauth_pending_callbacks_expiry_idx ON oauth_pending_callbacks (expires_at);

CREATE TABLE webhook_declarations (
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
    primary_project_root TEXT NOT NULL,
    integration_namespace TEXT NOT NULL,
    integration_group TEXT GENERATED ALWAYS AS (primary_project_root || char(0) || integration_namespace) VIRTUAL NOT NULL,
    name TEXT NOT NULL,
    tunnel_id TEXT NOT NULL REFERENCES local_tunnels(id) ON DELETE CASCADE,
    PRIMARY KEY (server_origin, primary_project_root, integration_namespace, name),
    CHECK (primary_project_root <> '' AND instr(primary_project_root, char(0)) = 0 AND
           integration_namespace <> '' AND instr(integration_namespace, char(0)) = 0)
) STRICT;

CREATE TABLE project_aliases (
    id TEXT PRIMARY KEY,
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    primary_project_root TEXT NOT NULL,
    team_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    service TEXT NOT NULL,
    fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
    selected_project_root TEXT NOT NULL,
    selection_revision INTEGER NOT NULL CHECK (selection_revision > 0),
    failure_reason TEXT NOT NULL DEFAULT '',
    UNIQUE (server_origin, primary_project_root, team_id, membership_id, namespace, name),
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

CREATE TABLE oauth_alias_handoffs (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    state_digest BLOB NOT NULL CHECK (length(state_digest) = 32),
    callback_path TEXT NOT NULL,
    public_url_id TEXT NOT NULL,
    publish_run_number INTEGER NOT NULL CHECK (publish_run_number > 0),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    consumed_at INTEGER CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    PRIMARY KEY (server_origin, hostname, state_digest)
) STRICT;

CREATE TABLE webhook_source_cache (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    source_json TEXT NOT NULL CHECK (length(source_json) BETWEEN 1 AND 16384),
    etag TEXT NOT NULL CHECK (length(etag) <= 128),
    checked_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, provider)
) STRICT;

CREATE TABLE login_operations (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    operation_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'redeeming', 'credential_received', 'exchanging', 'issued', 'completed', 'cancelled', 'denied', 'expired', 'recovery_required')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    public_json TEXT NOT NULL CHECK (length(public_json) BETWEEN 1 AND 32768),
    stored_private BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, operation_id)
) STRICT;

CREATE TABLE inspections (
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

CREATE TABLE inspection_number_counters (
    primary_checkout_root TEXT PRIMARY KEY,
    last_number INTEGER NOT NULL CHECK (last_number > 0)
) STRICT;

CREATE TABLE inspection_storage_usage (
    project_root TEXT NOT NULL,
    service TEXT NOT NULL,
    used_bytes INTEGER NOT NULL CHECK (used_bytes >= 0),
    PRIMARY KEY (project_root, service)
) STRICT;

-- +goose StatementBegin
CREATE TRIGGER inspections_added AFTER INSERT ON inspections BEGIN
    INSERT INTO inspection_storage_usage (project_root, service, used_bytes)
        VALUES (NEW.project_root, NEW.service, NEW.stored_bytes)
        ON CONFLICT (project_root, service) DO UPDATE SET used_bytes = used_bytes + excluded.used_bytes;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER inspections_removed AFTER DELETE ON inspections BEGIN
    UPDATE inspection_storage_usage SET used_bytes = used_bytes - OLD.stored_bytes
        WHERE project_root = OLD.project_root AND service = OLD.service;
END;
-- +goose StatementEnd

CREATE INDEX inspections_project_idx ON inspections (project_root, service, received_at DESC, row_id DESC);
CREATE INDEX inspections_shared_project_idx ON inspections (shared_project_root, received_at DESC, row_id DESC);
CREATE INDEX inspections_expiry_idx ON inspections (expires_at);

CREATE TABLE state_protection (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    protection_mode TEXT NOT NULL CHECK (protection_mode IN ('keychain', 'file')),
    key_check_ciphertext BLOB NOT NULL
) STRICT;

-- enrollment remains recoverable after a lost redemption reply. the one-use
-- secret, when locally issued, and the unrevealed signing key are protected.
CREATE TABLE pending_publisher_enrollments (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    enrollment_id TEXT NOT NULL,
    selection_kind TEXT NOT NULL CHECK (selection_kind IN ('namespace', 'project', 'job', 'explicit')),
    selection_key TEXT NOT NULL,
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    signing_key_ciphertext BLOB NOT NULL,
    enrollment_secret_ciphertext BLOB,
    result_json TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, enrollment_id),
    UNIQUE (server_origin, selection_kind, selection_key)
) STRICT;

CREATE TABLE publisher_identities (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    identity_id TEXT NOT NULL,
    public_document_json TEXT NOT NULL CHECK (json_valid(public_document_json)),
    signing_key_ciphertext BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, identity_id)
) STRICT;

-- a default, a named project URL, and a system job select the same installed
-- identity without copying its private key into several scope-named records.
CREATE TABLE publisher_selections (
    server_origin TEXT NOT NULL,
    selection_kind TEXT NOT NULL CHECK (selection_kind IN ('default_namespace', 'namespace', 'project', 'job', 'enrollment')),
    selection_key TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (server_origin, selection_kind, selection_key),
    FOREIGN KEY (server_origin, identity_id) REFERENCES publisher_identities(server_origin, identity_id) ON DELETE CASCADE,
    CHECK ((selection_kind = 'enrollment') = (expires_at IS NOT NULL)),
    CHECK (expires_at IS NULL OR expires_at > updated_at)
) STRICT;

CREATE INDEX publisher_enrollment_selections_expiry ON publisher_selections (expires_at)
    WHERE selection_kind = 'enrollment';

-- the root-owned system publisher keeps both documents encrypted in their
-- entirety. its file manifest protects the registry across process restarts.
CREATE TABLE publisher_job_registry (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    jobs_ciphertext BLOB NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE publisher_job_file_manifest (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    manifest_ciphertext BLOB NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- the project row survives event eviction and publisher cleanup. its epoch
-- distinguishes cursors from other projects and a fresh database.
CREATE TABLE project_journals (
    project_root TEXT PRIMARY KEY,
    cursor_epoch TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))) CHECK (length(cursor_epoch) = 32),
    last_sequence INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_app_sequence INTEGER NOT NULL DEFAULT 0 CHECK (last_app_sequence >= 0 AND last_app_sequence <= last_sequence),
    last_observed_at INTEGER,
    event_count INTEGER NOT NULL DEFAULT 0 CHECK (event_count >= 0),
    event_bytes INTEGER NOT NULL DEFAULT 0 CHECK (event_bytes >= 0),
    app_services_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(app_services_json) AND json_type(app_services_json) = 'array')
) STRICT;

CREATE TABLE project_events (
    project_root TEXT NOT NULL REFERENCES project_journals(project_root) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    occurred_at INTEGER NOT NULL,
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    stored_bytes INTEGER NOT NULL CHECK (stored_bytes BETWEEN 1 AND 8388608),
    PRIMARY KEY (project_root, sequence)
) STRICT;

-- +goose StatementBegin
-- retain exact budgets without rescanning history while it is below both limits.
CREATE TRIGGER project_event_retention AFTER INSERT ON project_events BEGIN
    UPDATE project_events SET stored_bytes = length(CAST(NEW.payload_json AS BLOB)) + length(CAST(json_quote(NEW.event_type) AS BLOB)) + 128
        WHERE project_root = NEW.project_root AND sequence = NEW.sequence;
    UPDATE project_journals SET event_count = event_count + 1,
        event_bytes = event_bytes + (SELECT stored_bytes FROM project_events WHERE project_root = NEW.project_root AND sequence = NEW.sequence)
        WHERE project_root = NEW.project_root;
    DELETE FROM project_events WHERE project_root = NEW.project_root AND sequence <= CASE
        WHEN (SELECT event_count > 2048 OR event_bytes > 8388608 FROM project_journals WHERE project_root = NEW.project_root)
        THEN (SELECT max(sequence) FROM (
            SELECT sequence,
                row_number() OVER (ORDER BY sequence DESC) AS count,
                sum(stored_bytes) OVER (ORDER BY sequence DESC) AS bytes
            FROM project_events WHERE project_root = NEW.project_root
        ) WHERE count > 2048 OR bytes > 8388608)
        ELSE 0 END;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER project_event_removed AFTER DELETE ON project_events BEGIN
    UPDATE project_journals SET event_count = event_count - 1, event_bytes = event_bytes - OLD.stored_bytes
        WHERE project_root = OLD.project_root;
END;
-- +goose StatementEnd

-- both publication triggers use the complete public TunnelInfo observation.
-- integer seconds and nanoseconds avoid SQLite's floating-point time rounding.
CREATE VIEW local_tunnel_publication_observations AS
SELECT id,
    json_object('publication', json_object(
        'tunnel_id', id, 'command', command, 'state', state, 'process_id', process_id,
        'server', server_origin, 'project', project_root, 'service', coalesce(service, ''),
        'service_protocol', CASE WHEN service_protocol = 'http' THEN '' ELSE service_protocol END,
        'public_url_id', coalesce(public_url_id, ''), 'publish_run_number', coalesce(publish_run_number, 0),
        'hostname', coalesce(hostname, ''),
        'public_url', CASE WHEN hostname IS NULL THEN '' ELSE 'https://' || hostname END,
        'target', coalesce(target, ''), 'framework', coalesce(framework, ''), 'failure', coalesce(failure_code, ''),
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
    INSERT INTO project_journals (project_root) VALUES (NEW.project_root) ON CONFLICT DO NOTHING;
    UPDATE project_journals SET last_sequence = last_sequence + 1, last_observed_at = NEW.updated_at WHERE project_root = NEW.project_root;
    INSERT INTO project_events (project_root, sequence, event_type, occurred_at, payload_json, stored_bytes)
    SELECT NEW.project_root, last_sequence, 'publication.started', NEW.updated_at,
        observation.payload, 1
    FROM project_journals JOIN local_tunnel_publication_observations observation ON observation.id = NEW.id
    WHERE project_root = NEW.project_root;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER project_publication_changed AFTER UPDATE ON local_tunnels
WHEN NEW.state IS NOT OLD.state OR NEW.hostname IS NOT OLD.hostname
    OR NEW.target IS NOT OLD.target OR NEW.publish_run_number IS NOT OLD.publish_run_number
    OR NEW.public_url_id IS NOT OLD.public_url_id OR NEW.framework IS NOT OLD.framework OR NEW.failure_code IS NOT OLD.failure_code
BEGIN
    UPDATE project_journals SET last_sequence = last_sequence + 1, last_observed_at = NEW.updated_at WHERE project_root = NEW.project_root;
    INSERT INTO project_events (project_root, sequence, event_type, occurred_at, payload_json, stored_bytes)
    SELECT NEW.project_root, last_sequence, 'publication.changed', NEW.updated_at,
        observation.payload, 1
    FROM project_journals JOIN local_tunnel_publication_observations observation ON observation.id = NEW.id
    WHERE project_root = NEW.project_root;
END;
-- +goose StatementEnd
