-- +goose Up
-- credentials authorize only one saved public URL; run associations let revocation
-- close an already started run at its next heartbeat.
CREATE TABLE control.public_url_publish_credentials (
    id text PRIMARY KEY CHECK (id <> ''),
    public_url_id text NOT NULL REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    token_id text NOT NULL UNIQUE CHECK (token_id <> ''),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    issued_by_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    membership_id text NOT NULL CHECK (membership_id <> ''),
    policy_revision bigint NOT NULL CHECK (policy_revision >= 1),
    target text NOT NULL CHECK (target <> ''),
    certificate_cache_key text NOT NULL CHECK (certificate_cache_key <> ''),
    certificate_scope text NOT NULL CHECK (certificate_scope <> ''),
    certificate_identifiers text[] NOT NULL CHECK (cardinality(certificate_identifiers) > 0),
    certificate_challenge_method text NOT NULL CHECK (certificate_challenge_method IN ('dns-01', 'tls-alpn-01')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX public_url_publish_credentials_public_url
    ON control.public_url_publish_credentials (public_url_id, created_at DESC, id);

CREATE TABLE control.publish_run_publish_credentials (
    publish_run_id text PRIMARY KEY REFERENCES control.publish_runs(id) ON DELETE RESTRICT,
    public_url_id text NOT NULL REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    credential_id text NOT NULL REFERENCES control.public_url_publish_credentials(id) ON DELETE RESTRICT
);
CREATE INDEX publish_run_publish_credentials_credential
    ON control.publish_run_publish_credentials (credential_id, publish_run_id);

-- +goose Down
DROP TABLE control.publish_run_publish_credentials;
DROP TABLE control.public_url_publish_credentials;
