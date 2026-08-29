-- +goose Up
CREATE TABLE hostname_claims (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE routes (
    id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL REFERENCES hostname_claims(id) ON DELETE RESTRICT,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL,
    display_target TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'deleted')),
    generation INTEGER NOT NULL CHECK (generation >= 1),
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
