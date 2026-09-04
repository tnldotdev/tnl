-- +goose Up
DROP TABLE certificate_issuances;

CREATE TABLE certificate_issuances (
    id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    route_version INTEGER NOT NULL CHECK (route_version >= 1),
    hostname TEXT NOT NULL,
    directory_url TEXT NOT NULL,
    acme_profile TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'creating_order', 'authorizing', 'waiting_for_challenge',
        'ready_to_finalize', 'finalizing', 'waiting_for_install',
        'installed', 'failed'
    )),
    csr_der BLOB NOT NULL,
    csr_hash BLOB NOT NULL,
    spki_hash BLOB NOT NULL,
    order_started_at INTEGER,
    order_url TEXT,
    order_expires_at INTEGER,
    retry_at INTEGER,
    authorization_url TEXT,
    finalize_url TEXT,
    challenge_url TEXT,
    challenge_digest BLOB,
    challenge_expires_at INTEGER,
    certificate_url TEXT,
    certificate_pem BLOB,
    not_before INTEGER,
    not_after INTEGER,
    renew_at INTEGER,
    last_error TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    CHECK (
        (challenge_url IS NULL AND challenge_digest IS NULL AND challenge_expires_at IS NULL) OR
        (challenge_url IS NOT NULL AND challenge_digest IS NOT NULL AND challenge_expires_at IS NOT NULL)
    ),
    CHECK (status != 'installed' OR challenge_url IS NULL),
    UNIQUE (route_id, route_version, csr_hash, directory_url, acme_profile)
) STRICT;

CREATE INDEX certificate_issuances_route_version
    ON certificate_issuances (route_id, route_version, created_at DESC);
