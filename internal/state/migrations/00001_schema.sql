-- +goose Up
CREATE TABLE identities (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE control_sessions (
    id TEXT PRIMARY KEY CHECK (id GLOB 'control_session_[0-9a-f]*' AND length(id) = 48),
    identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    authentication_method TEXT NOT NULL CHECK (authentication_method IN ('login_token', 'oidc')),
    authentication_source_revision INTEGER NOT NULL CHECK (authentication_source_revision >= 1),
    grants TEXT NOT NULL CHECK (grants IN ('publish', 'publish,admin')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    refresh_expires_at INTEGER NOT NULL CHECK (refresh_expires_at > created_at),
    access_token_id TEXT NOT NULL UNIQUE,
    access_token_hash BLOB NOT NULL UNIQUE,
    access_expires_at INTEGER NOT NULL CHECK (access_expires_at > created_at AND access_expires_at <= refresh_expires_at),
    access_token_revoked_at INTEGER,
    refresh_token_id TEXT NOT NULL UNIQUE,
    refresh_token_hash BLOB NOT NULL UNIQUE,
    refresh_token_revoked_at INTEGER,
    revoked_at INTEGER
) STRICT;

CREATE INDEX control_sessions_identity_id ON control_sessions (identity_id);
CREATE INDEX control_sessions_authentication_source
    ON control_sessions (authentication_method, authentication_source_revision) WHERE revoked_at IS NULL;

CREATE TABLE control_session_refresh_tokens (
    token_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES control_sessions(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    replaced_at INTEGER NOT NULL CHECK (replaced_at >= 0)
) STRICT;

CREATE INDEX control_session_refresh_tokens_session_id
    ON control_session_refresh_tokens (session_id);

CREATE TABLE hostnames (
    id TEXT PRIMARY KEY,
    identity_id TEXT REFERENCES identities(id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('managed', 'custom_domain', 'temporary')),
    status TEXT NOT NULL CHECK (status IN ('pending_route', 'active', 'inactive', 'available', 'retired', 'quarantined')),
    source TEXT NOT NULL CHECK (source IN ('user', 'generated')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    activated_at INTEGER,
    deactivated_at INTEGER,
    quarantine_reason TEXT CHECK (quarantine_reason IS NULL OR length(quarantine_reason) BETWEEN 1 AND 256),
    quarantined_at INTEGER,
    CHECK (
        (kind = 'managed' AND identity_id IS NOT NULL AND status IN ('active', 'inactive')) OR
        (kind = 'custom_domain' AND (
            (status = 'active' AND identity_id IS NOT NULL) OR
            (status = 'available' AND identity_id IS NULL)
        )) OR
        (kind = 'temporary' AND identity_id IS NOT NULL AND status IN ('pending_route', 'active', 'retired')) OR
        (status = 'quarantined' AND identity_id IS NOT NULL)
    ),
    CHECK ((status = 'quarantined') = (quarantine_reason IS NOT NULL AND quarantined_at IS NOT NULL))
) STRICT;

CREATE INDEX hostnames_identity_active
    ON hostnames (identity_id, created_at, id)
    WHERE kind IN ('managed', 'custom_domain') AND status IN ('active', 'inactive');
CREATE INDEX hostnames_temporary_cleanup
    ON hostnames (status, created_at) WHERE kind = 'temporary';
CREATE INDEX hostnames_friendly_capacity
    ON hostnames (kind) WHERE kind IN ('managed', 'temporary');

CREATE TABLE hostname_requests (
    identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE RESTRICT,
    request_key TEXT NOT NULL,
    requested_label TEXT NOT NULL,
    requested_kind TEXT NOT NULL CHECK (requested_kind IN ('managed', 'temporary')),
    hostname_id TEXT NOT NULL REFERENCES hostnames(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (identity_id, request_key)
) STRICT;

CREATE TABLE domain_verifications (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE RESTRICT,
    request_key TEXT NOT NULL,
    domain TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    verification_target TEXT NOT NULL UNIQUE,
    is_apex INTEGER NOT NULL CHECK (is_apex IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('pending', 'verified', 'invalidated')),
    hostname_id TEXT REFERENCES hostnames(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    verified_at INTEGER,
    invalidated_at INTEGER,
    UNIQUE (identity_id, request_key)
) STRICT;

CREATE INDEX domain_verifications_identity
    ON domain_verifications (identity_id, created_at, id);
CREATE INDEX domain_verifications_pending_domain
    ON domain_verifications (domain) WHERE status = 'pending';

CREATE TABLE routes (
    id TEXT PRIMARY KEY,
    hostname_id TEXT REFERENCES hostnames(id) ON DELETE RESTRICT,
    identity_id TEXT REFERENCES identities(id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL,
    local_target TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
    version INTEGER NOT NULL CHECK (version >= 1),
    suspension_revision INTEGER NOT NULL DEFAULT 0 CHECK (suspension_revision >= 0),
    suspension_reason TEXT CHECK (suspension_reason IS NULL OR length(suspension_reason) BETWEEN 1 AND 256),
    suspended_at INTEGER,
    authorization_issuer TEXT,
    authorization_id TEXT,
    authorization_key_id TEXT,
    authorization_retry_id TEXT,
    authorization_revision INTEGER,
    authorization_expires_at INTEGER,
    authorization_request_hash BLOB,
    authorization_ip_policy_hash BLOB,
    lifecycle_sequence INTEGER NOT NULL DEFAULT 0 CHECK (lifecycle_sequence >= 0),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    deleted_at INTEGER,
    CHECK (
        (suspension_revision = 0 AND suspension_reason IS NULL AND suspended_at IS NULL) OR
        (suspension_revision > 0 AND suspension_reason IS NOT NULL AND
            ((status = 'suspended' AND suspended_at IS NOT NULL) OR (status != 'suspended' AND suspended_at IS NULL)))
    ),
    CHECK (
        (hostname_id IS NOT NULL AND identity_id IS NOT NULL AND
            authorization_issuer IS NULL AND authorization_id IS NULL AND
            authorization_key_id IS NULL AND authorization_retry_id IS NULL AND
            authorization_revision IS NULL AND authorization_expires_at IS NULL AND
            authorization_request_hash IS NULL AND authorization_ip_policy_hash IS NULL) OR
        (hostname_id IS NULL AND identity_id IS NULL AND
            authorization_issuer IS NOT NULL AND authorization_id IS NOT NULL AND
            authorization_key_id IS NOT NULL AND authorization_retry_id IS NOT NULL AND
            authorization_revision >= 1 AND authorization_expires_at > created_at AND
            typeof(authorization_request_hash) = 'blob' AND length(authorization_request_hash) = 32 AND
            (authorization_ip_policy_hash IS NULL OR
                typeof(authorization_ip_policy_hash) = 'blob' AND length(authorization_ip_policy_hash) = 32))
    )
) STRICT;

CREATE INDEX routes_identity_id ON routes (identity_id);
CREATE UNIQUE INDEX routes_current_hostname ON routes (hostname) WHERE status IN ('active', 'suspended');
CREATE UNIQUE INDEX routes_authorization_id
    ON routes (authorization_issuer, authorization_id) WHERE authorization_id IS NOT NULL;
CREATE UNIQUE INDEX routes_authorization_retry
    ON routes (authorization_issuer, authorization_retry_id) WHERE authorization_retry_id IS NOT NULL;

CREATE TABLE route_allowed_ip_prefixes (
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    route_version INTEGER NOT NULL CHECK (route_version >= 1),
    position INTEGER NOT NULL CHECK (position >= 0 AND position < 64),
    prefix TEXT NOT NULL,
    PRIMARY KEY (route_id, route_version, position),
    UNIQUE (route_id, route_version, prefix)
) STRICT;

CREATE TABLE route_authorization_uses (
    authorization_issuer TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    authorization_key_id TEXT NOT NULL,
    authorization_retry_id TEXT NOT NULL,
    authorization_revision INTEGER NOT NULL CHECK (authorization_revision >= 1),
    authorization_expires_at INTEGER NOT NULL CHECK (authorization_expires_at >= 0),
    operation TEXT NOT NULL CHECK (operation IN ('route.create', 'route_session.create', 'authorization.renew')),
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE RESTRICT,
    route_version INTEGER NOT NULL CHECK (route_version >= 1),
    hostname TEXT NOT NULL,
    request_hash BLOB NOT NULL CHECK (typeof(request_hash) = 'blob' AND length(request_hash) = 32),
    ip_policy_hash BLOB CHECK (ip_policy_hash IS NULL OR typeof(ip_policy_hash) = 'blob' AND length(ip_policy_hash) = 32),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (authorization_issuer, authorization_id),
    UNIQUE (authorization_issuer, authorization_retry_id)
) STRICT;

CREATE TABLE route_credentials (
    id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL UNIQUE REFERENCES routes(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    revoked_at INTEGER
) STRICT;

CREATE TABLE route_sessions (
    id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK (version >= 1),
    status TEXT NOT NULL CHECK (status IN ('pending', 'starting', 'ready', 'expired')),
    token_id TEXT NOT NULL UNIQUE,
    secret_hash BLOB NOT NULL UNIQUE,
    server_instance_id TEXT NOT NULL,
    publisher_public_key TEXT,
    relay_region TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    last_heartbeat_at INTEGER NOT NULL CHECK (last_heartbeat_at >= created_at),
    expires_at INTEGER NOT NULL CHECK (expires_at >= created_at),
    UNIQUE (route_id, version)
) STRICT;

CREATE INDEX route_sessions_route_status ON route_sessions (route_id, status);

CREATE TABLE acme_accounts (
    directory_url TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    key_der BLOB NOT NULL,
    kid TEXT,
    accepted_terms_url TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE certificate_issuances (
    id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK (version >= 1),
    hostname TEXT NOT NULL,
    acme_profile TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'creating_order', 'authorizing', 'waiting_for_challenge', 'validating',
        'ready_to_finalize', 'finalizing', 'downloading', 'waiting_for_install',
        'installed', 'failed', 'blocked', 'canceled'
    )),
    csr_der BLOB NOT NULL,
    csr_hash BLOB NOT NULL,
    spki_hash BLOB NOT NULL,
    order_url TEXT,
    acme_status TEXT,
    order_attempts INTEGER NOT NULL DEFAULT 0 CHECK (order_attempts >= 0),
    order_expires_at INTEGER,
    retry_at INTEGER,
    authorization_url TEXT,
    finalize_url TEXT,
    challenge_url TEXT,
    challenge_token TEXT,
    challenge_digest BLOB,
    challenge_expires_at INTEGER,
    certificate_url TEXT,
    certificate_pem BLOB,
    not_before INTEGER,
    not_after INTEGER,
    renew_at INTEGER,
    installed_at INTEGER,
    challenge_removed_at INTEGER,
    last_error TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (route_id, version, csr_hash)
) STRICT;

CREATE INDEX certificate_issuances_route_version
    ON certificate_issuances (route_id, version, created_at DESC);

CREATE TABLE oidc_assertion_exchanges (
    assertion_hash BLOB PRIMARY KEY,
    consumed_at INTEGER NOT NULL CHECK (consumed_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at >= consumed_at)
) STRICT;

CREATE INDEX oidc_assertion_exchanges_expires_at ON oidc_assertion_exchanges (expires_at);

CREATE TABLE operational_switches (
    name TEXT PRIMARY KEY CHECK (name IN ('new_routes', 'new_sessions', 'certificate_issuance')),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    updated_by TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 256)
) STRICT;

INSERT INTO operational_switches (name, enabled, revision, updated_at, updated_by) VALUES
    ('new_routes', 1, 1, 0, 'system'),
    ('new_sessions', 1, 1, 0, 'system'),
    ('certificate_issuance', 1, 1, 0, 'system');

CREATE TABLE admin_audit_events (
    id INTEGER PRIMARY KEY,
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 256),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 68),
    operation TEXT NOT NULL CHECK (operation IN (
        'route.suspend', 'route.resume', 'hostname.remove', 'hostname.quarantine',
        'credential.revoke', 'control_session.revoke', 'switch.set'
    )),
    target TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 256),
    occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0)
) STRICT;

CREATE UNIQUE INDEX admin_audit_events_request_operation_target
    ON admin_audit_events (request_id, operation, target);
CREATE INDEX admin_audit_events_occurred_at ON admin_audit_events (occurred_at, id);

CREATE TABLE route_registrations (
    id INTEGER PRIMARY KEY,
    registration_id TEXT NOT NULL UNIQUE
        CHECK (registration_id GLOB 'registration_[0-9a-f]*' AND length(registration_id) = 45),
    route_id TEXT NOT NULL UNIQUE REFERENCES routes(id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    retry_id TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision = 1),
    acknowledged_revision INTEGER CHECK (acknowledged_revision = revision),
    acknowledged_at INTEGER CHECK (acknowledged_at >= 0),
    CHECK (
        (acknowledged_revision IS NULL AND acknowledged_at IS NULL) OR
        (acknowledged_revision IS NOT NULL AND acknowledged_at IS NOT NULL)
    )
) STRICT;

CREATE TABLE route_lifecycle_events (
    id INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE RESTRICT,
    version INTEGER NOT NULL CHECK (version >= 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0),
    transition TEXT NOT NULL CHECK (transition IN ('version_started', 'ready', 'disconnected', 'deleted')),
    UNIQUE (route_id, sequence),
    UNIQUE (route_id, version, transition)
) STRICT;

CREATE INDEX route_lifecycle_events_retention ON route_lifecycle_events (occurred_at, id);

CREATE TABLE route_usage_snapshots (
    id INTEGER PRIMARY KEY,
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE RESTRICT,
    version INTEGER NOT NULL CHECK (version >= 1),
    resolution TEXT NOT NULL CHECK (resolution IN ('minute', 'hour')),
    bucket_start INTEGER NOT NULL CHECK (bucket_start >= 0),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    observed_through INTEGER NOT NULL CHECK (observed_through >= bucket_start),
    connection_attempts INTEGER NOT NULL CHECK (connection_attempts >= 0),
    policy_denials INTEGER NOT NULL CHECK (policy_denials >= 0),
    capacity_denials INTEGER NOT NULL CHECK (capacity_denials >= 0),
    publisher_open_failures INTEGER NOT NULL CHECK (publisher_open_failures >= 0),
    successful_streams INTEGER NOT NULL CHECK (successful_streams >= 0),
    connection_nanoseconds INTEGER NOT NULL CHECK (connection_nanoseconds >= 0),
    ingress_bytes INTEGER NOT NULL CHECK (ingress_bytes >= 0),
    egress_bytes INTEGER NOT NULL CHECK (egress_bytes >= 0),
    publisher_open_latency BLOB CHECK (
        publisher_open_latency IS NULL OR typeof(publisher_open_latency) = 'blob' AND length(publisher_open_latency) = 184
    ),
    time_to_first_publisher_byte BLOB CHECK (
        time_to_first_publisher_byte IS NULL OR typeof(time_to_first_publisher_byte) = 'blob' AND length(time_to_first_publisher_byte) = 184
    ),
    successful_connection_duration BLOB CHECK (
        successful_connection_duration IS NULL OR typeof(successful_connection_duration) = 'blob' AND length(successful_connection_duration) = 184
    ),
    visitor_network_hll BLOB NOT NULL CHECK (typeof(visitor_network_hll) = 'blob' AND length(visitor_network_hll) >= 5),
    visitor_network_estimate INTEGER NOT NULL CHECK (visitor_network_estimate >= 0),
    complete INTEGER NOT NULL DEFAULT 0 CHECK (complete IN (0, 1)),
    finalized INTEGER NOT NULL DEFAULT 0 CHECK (finalized IN (0, 1)),
    CHECK (complete = 0 OR finalized = 1),
    UNIQUE (route_id, version, resolution, bucket_start)
) STRICT;

CREATE INDEX route_usage_snapshots_incomplete
    ON route_usage_snapshots (resolution, bucket_start, id) WHERE finalized = 0;

CREATE TABLE route_usage_reports (
    snapshot_id INTEGER PRIMARY KEY REFERENCES route_usage_snapshots(id) ON DELETE CASCADE,
    report_id TEXT NOT NULL UNIQUE
        CHECK (report_id GLOB 'usage_report_[0-9a-f]*' AND length(report_id) = 45),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    observed_through INTEGER NOT NULL CHECK (observed_through >= 0),
    connection_attempts INTEGER NOT NULL CHECK (connection_attempts >= 0),
    policy_denials INTEGER NOT NULL CHECK (policy_denials >= 0),
    capacity_denials INTEGER NOT NULL CHECK (capacity_denials >= 0),
    publisher_open_failures INTEGER NOT NULL CHECK (publisher_open_failures >= 0),
    successful_streams INTEGER NOT NULL CHECK (successful_streams >= 0),
    connection_nanoseconds INTEGER NOT NULL CHECK (connection_nanoseconds >= 0),
    ingress_bytes INTEGER NOT NULL CHECK (ingress_bytes >= 0),
    egress_bytes INTEGER NOT NULL CHECK (egress_bytes >= 0),
    publisher_open_latency BLOB CHECK (
        publisher_open_latency IS NULL OR typeof(publisher_open_latency) = 'blob' AND length(publisher_open_latency) = 184
    ),
    time_to_first_publisher_byte BLOB CHECK (
        time_to_first_publisher_byte IS NULL OR typeof(time_to_first_publisher_byte) = 'blob' AND length(time_to_first_publisher_byte) = 184
    ),
    successful_connection_duration BLOB CHECK (
        successful_connection_duration IS NULL OR typeof(successful_connection_duration) = 'blob' AND length(successful_connection_duration) = 184
    ),
    visitor_network_hll BLOB NOT NULL CHECK (typeof(visitor_network_hll) = 'blob' AND length(visitor_network_hll) >= 5),
    visitor_network_estimate INTEGER NOT NULL CHECK (visitor_network_estimate >= 0),
    complete INTEGER NOT NULL CHECK (complete IN (0, 1))
) STRICT;

CREATE TABLE route_usage_outbox_items (
    source_kind TEXT NOT NULL CHECK (source_kind IN ('registration', 'lifecycle_event', 'usage_snapshot')),
    source_id INTEGER NOT NULL,
    source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
    enqueued_at INTEGER NOT NULL CHECK (enqueued_at >= 0),
    last_attempted_at INTEGER CHECK (last_attempted_at >= 0),
    PRIMARY KEY (source_kind, source_id)
) STRICT;

CREATE INDEX route_usage_outbox_items_delivery
    ON route_usage_outbox_items (coalesce(last_attempted_at, enqueued_at), source_kind, source_id);

CREATE TABLE server_values (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;
