-- +goose Up
CREATE TABLE control.guest_trials (
    id text PRIMARY KEY CHECK (id <> ''),
    credential_id text NOT NULL UNIQUE CHECK (credential_id <> ''),
    credential_hash bytea NOT NULL CHECK (octet_length(credential_hash) = 32),
    namespace_label text NOT NULL UNIQUE CHECK (namespace_label ~ '^guest-[0-9a-f]{16}$'),
    team_id text NOT NULL UNIQUE CHECK (team_id <> ''),
    membership_id text NOT NULL UNIQUE CHECK (membership_id <> ''),
    domain_id text NOT NULL CHECK (domain_id <> ''),
    dns_authority_reference text NOT NULL CHECK (dns_authority_reference <> ''),
    source_ip text NOT NULL CHECK (source_ip <> ''),
    used_ready_ns bigint NOT NULL DEFAULT 0 CHECK (used_ready_ns >= 0),
    used_bytes bigint NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    active_publish_run_id text,
    active_ready_at timestamptz,
    claimed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (active_ready_at IS NULL OR active_publish_run_id IS NOT NULL),
    CHECK (updated_at >= created_at)
);
CREATE INDEX guest_trials_source_created ON control.guest_trials (source_ip, created_at DESC);

CREATE TABLE control.guest_public_urls (
    public_url_id text PRIMARY KEY REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    guest_id text NOT NULL REFERENCES control.guest_trials(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL
);

CREATE INDEX guest_public_urls_guest_id ON control.guest_public_urls (guest_id);

CREATE TABLE control.guest_visitor_slots (
    visitor_connection_id text PRIMARY KEY CHECK (visitor_connection_id <> ''),
    guest_id text NOT NULL REFERENCES control.guest_trials(id) ON DELETE RESTRICT,
    ingress_id text NOT NULL CHECK (ingress_id <> ''),
    expires_at timestamptz NOT NULL
);
CREATE INDEX guest_visitor_slots_guest_expiry ON control.guest_visitor_slots (guest_id, expires_at);

-- +goose Down
DROP TABLE control.guest_visitor_slots;
DROP TABLE control.guest_public_urls;
DROP TABLE control.guest_trials;
