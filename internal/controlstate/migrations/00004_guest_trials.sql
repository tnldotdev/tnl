-- +goose Up
CREATE TABLE control.guest_trials (
    id text PRIMARY KEY CHECK (id <> ''),
    credential_id text UNIQUE CHECK (credential_id IS NULL OR credential_id <> ''),
    credential_hash bytea CHECK (credential_hash IS NULL OR octet_length(credential_hash) = 32),
    namespace_label text NOT NULL UNIQUE CHECK (namespace_label ~ '^guest-[0-9a-z]{8}$'),
    team_id text NOT NULL UNIQUE CHECK (team_id <> ''),
    membership_id text NOT NULL UNIQUE CHECK (membership_id <> ''),
    domain_id text NOT NULL CHECK (domain_id <> ''),
    dns_authority_reference text NOT NULL CHECK (dns_authority_reference <> ''),
    source_ip_digest text CHECK (source_ip_digest IS NULL OR source_ip_digest ~ '^[A-Za-z0-9_-]{43}$'),
    source_ip_key_id text CHECK (source_ip_key_id IS NULL OR source_ip_key_id <> ''),
    issuance_ip_digest text CHECK (issuance_ip_digest IS NULL OR issuance_ip_digest ~ '^[A-Za-z0-9_-]{43}$'),
    expires_at timestamptz NOT NULL,
    used_ready_ns bigint NOT NULL DEFAULT 0 CHECK (used_ready_ns >= 0),
    used_bytes bigint NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    first_demo_allocated_at timestamptz,
    first_ready_at timestamptz,
    end_reason text CHECK (end_reason IN ('expired', 'ready_limit', 'transfer_limit')),
    ended_at timestamptz,
    last_demo_number bigint NOT NULL DEFAULT 0 CHECK (last_demo_number >= 0),
    active_publish_run_id text,
    active_ready_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (active_ready_at IS NULL OR active_publish_run_id IS NOT NULL),
    CHECK (updated_at >= created_at),
    CHECK ((source_ip_digest IS NULL) = (source_ip_key_id IS NULL)),
    CHECK ((credential_id IS NULL) = (credential_hash IS NULL)),
    CHECK ((end_reason IS NULL) = (ended_at IS NULL)),
    CHECK (expires_at > created_at)
);
CREATE INDEX guest_trials_issuance_created ON control.guest_trials (source_ip_key_id, issuance_ip_digest, created_at DESC);
CREATE INDEX guest_trials_active_expiry ON control.guest_trials (expires_at) WHERE active_publish_run_id IS NOT NULL;
CREATE INDEX guest_trials_created_at ON control.guest_trials (created_at);

CREATE TABLE control.guest_public_urls (
    public_url_id text PRIMARY KEY REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    guest_id text NOT NULL REFERENCES control.guest_trials(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL
);

CREATE INDEX guest_public_urls_guest_id ON control.guest_public_urls (guest_id);

-- +goose Down
DROP TABLE control.guest_public_urls;
DROP TABLE control.guest_trials;
