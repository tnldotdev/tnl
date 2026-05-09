-- +goose Up
CREATE TABLE identities (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;

CREATE TABLE access_credentials (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at >= created_at),
    revoked_at INTEGER
) STRICT;

CREATE INDEX access_credentials_identity_id ON access_credentials (identity_id);

CREATE TABLE hostnames (
    id TEXT PRIMARY KEY,
    identity_id TEXT REFERENCES identities(id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('managed', 'custom_domain', 'temporary')),
    status TEXT NOT NULL CHECK (status IN ('pending_route', 'active', 'inactive', 'available', 'retired')),
    source TEXT NOT NULL CHECK (source IN ('user', 'generated')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    activated_at INTEGER,
    deactivated_at INTEGER,
    CHECK (
        (kind = 'managed' AND identity_id IS NOT NULL AND status IN ('active', 'inactive')) OR
        (kind = 'custom_domain' AND (
            (status = 'active' AND identity_id IS NOT NULL) OR
            (status = 'available' AND identity_id IS NULL)
        )) OR
        (kind = 'temporary' AND identity_id IS NOT NULL AND status IN ('pending_route', 'active', 'retired'))
    )
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
    hostname_id TEXT NOT NULL REFERENCES hostnames(id) ON DELETE RESTRICT,
    identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL,
    local_target TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'deleted')),
    version INTEGER NOT NULL CHECK (version >= 1),
    lifecycle_sequence INTEGER NOT NULL DEFAULT 0 CHECK (lifecycle_sequence >= 0),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    deleted_at INTEGER
) STRICT;

CREATE INDEX routes_identity_id ON routes (identity_id);
CREATE UNIQUE INDEX routes_active_hostname ON routes (hostname) WHERE status = 'active';

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
    connections_opened INTEGER NOT NULL CHECK (connections_opened >= 0),
    connection_nanoseconds INTEGER NOT NULL CHECK (connection_nanoseconds >= 0),
    ingress_bytes INTEGER NOT NULL CHECK (ingress_bytes >= 0),
    egress_bytes INTEGER NOT NULL CHECK (egress_bytes >= 0),
    complete INTEGER NOT NULL DEFAULT 0 CHECK (complete IN (0, 1)),
    UNIQUE (route_id, version, resolution, bucket_start)
) STRICT;

CREATE INDEX route_usage_snapshots_incomplete
    ON route_usage_snapshots (resolution, bucket_start, id) WHERE complete = 0;

CREATE TABLE route_usage_outbox_items (
    source_kind TEXT NOT NULL CHECK (source_kind IN ('lifecycle_event', 'usage_snapshot')),
    source_id INTEGER NOT NULL,
    source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
    enqueued_at INTEGER NOT NULL CHECK (enqueued_at >= 0),
    PRIMARY KEY (source_kind, source_id)
) STRICT;

CREATE INDEX route_usage_outbox_items_delivery
    ON route_usage_outbox_items (source_kind, enqueued_at, source_id);

CREATE TABLE server_values (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;
