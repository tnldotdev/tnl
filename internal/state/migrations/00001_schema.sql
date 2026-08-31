-- +goose Up
CREATE TABLE principals (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE access_credentials (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
) STRICT;

CREATE INDEX access_credentials_principal_id
    ON access_credentials (principal_id);

CREATE TABLE hostname_claims (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    irreversible INTEGER NOT NULL DEFAULT 1 CHECK (irreversible IN (0, 1)),
    tombstoned_at INTEGER
) STRICT;

CREATE INDEX hostname_claims_principal_active
    ON hostname_claims (principal_id, created_at, id) WHERE tombstoned_at IS NULL;

CREATE TABLE routes (
    id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL REFERENCES hostname_claims(id) ON DELETE RESTRICT,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL,
    display_target TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'deleted')),
    generation INTEGER NOT NULL CHECK (generation >= 1),
    lifecycle_sequence INTEGER NOT NULL DEFAULT 0 CHECK (lifecycle_sequence >= 0),
    created_at INTEGER NOT NULL,
    deleted_at INTEGER
) STRICT;

CREATE INDEX routes_principal_id ON routes (principal_id);
CREATE UNIQUE INDEX routes_active_hostname ON routes (hostname) WHERE state = 'active';

CREATE TABLE route_credentials (
    id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL UNIQUE REFERENCES routes(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
) STRICT;

CREATE TABLE route_leases (
    id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    status TEXT NOT NULL CHECK (status IN ('pending', 'starting', 'ready', 'draining', 'expired')),
    credential_id TEXT NOT NULL UNIQUE,
    secret_hash BLOB NOT NULL UNIQUE,
    boot_epoch TEXT NOT NULL,
    server_public_key TEXT,
    relay_profile TEXT,
    created_at INTEGER NOT NULL,
    last_heartbeat INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    UNIQUE (route_id, generation)
) STRICT;

CREATE INDEX route_leases_route_status ON route_leases (route_id, status);

CREATE TABLE hostname_claim_requests (
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    request_key TEXT NOT NULL,
    requested_label TEXT NOT NULL,
    claim_id TEXT NOT NULL REFERENCES hostname_claims(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (principal_id, request_key)
) STRICT;

CREATE TABLE acme_accounts (
    directory_url TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    key_der BLOB NOT NULL,
    kid TEXT,
    accepted_terms_url TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE certificate_jobs (
    id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    hostname TEXT NOT NULL,
    profile TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'creating_order',
        'authorizing',
        'waiting_for_challenge',
        'validating',
        'ready_to_finalize',
        'finalizing',
        'downloading',
        'waiting_for_install',
        'succeeded',
        'invalid',
        'blocked',
        'canceled'
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
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (route_id, generation, csr_hash)
) STRICT;

CREATE INDEX certificate_jobs_route_generation
    ON certificate_jobs (route_id, generation, created_at DESC);

CREATE TABLE oidc_assertion_exchanges (
    assertion_hash BLOB PRIMARY KEY,
    consumed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX oidc_assertion_exchanges_expires_at
    ON oidc_assertion_exchanges (expires_at);

CREATE TABLE route_lifecycle_events (
    id INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    occurred_at_ns INTEGER NOT NULL CHECK (occurred_at_ns >= 0),
    transition TEXT NOT NULL CHECK (transition IN (
        'generation_started',
        'ready',
        'disconnected',
        'deleted'
    )),
    UNIQUE (route_id, sequence),
    UNIQUE (route_id, generation, transition)
) STRICT;

CREATE INDEX route_lifecycle_events_retention
    ON route_lifecycle_events (occurred_at_ns, id);

CREATE TABLE route_usage_buckets (
    id INTEGER PRIMARY KEY,
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    resolution TEXT NOT NULL CHECK (resolution IN ('minute', 'hour')),
    bucket_start_ns INTEGER NOT NULL CHECK (bucket_start_ns >= 0),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    source_through_ns INTEGER NOT NULL CHECK (source_through_ns >= bucket_start_ns),
    connections_opened INTEGER NOT NULL CHECK (connections_opened >= 0),
    connection_ns INTEGER NOT NULL CHECK (connection_ns >= 0),
    ingress_bytes INTEGER NOT NULL CHECK (ingress_bytes >= 0),
    egress_bytes INTEGER NOT NULL CHECK (egress_bytes >= 0),
    complete INTEGER NOT NULL DEFAULT 0 CHECK (complete IN (0, 1)),
    UNIQUE (route_id, generation, resolution, bucket_start_ns)
) STRICT;

CREATE INDEX route_usage_buckets_incomplete
    ON route_usage_buckets (resolution, bucket_start_ns, id)
    WHERE complete = 0;

CREATE TABLE route_export_outbox (
    source_kind TEXT NOT NULL CHECK (source_kind IN ('lifecycle_event', 'usage_snapshot')),
    source_id INTEGER NOT NULL,
    source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
    created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
    PRIMARY KEY (source_kind, source_id)
) STRICT;

CREATE INDEX route_export_outbox_delivery
    ON route_export_outbox (source_kind, created_at_ns, source_id);
