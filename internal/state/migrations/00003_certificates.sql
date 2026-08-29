-- +goose Up
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
