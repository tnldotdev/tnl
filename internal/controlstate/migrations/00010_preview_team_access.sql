-- +goose Up
ALTER TABLE control.previews ADD COLUMN team_access_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE control.feedback_threads DROP CONSTRAINT feedback_threads_author_display_name_check;
ALTER TABLE control.feedback_threads ADD CONSTRAINT feedback_threads_author_display_name_check
    CHECK (char_length(author_display_name) BETWEEN 1 AND 256);
ALTER TABLE control.feedback_threads
    ADD COLUMN author_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    ADD COLUMN author_verified boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT feedback_threads_verified_author_check CHECK (author_verified = (author_identity_id IS NOT NULL));
ALTER TABLE control.feedback_events
    ADD COLUMN author_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    ADD COLUMN author_display_name text CHECK (char_length(author_display_name) BETWEEN 1 AND 256),
    ADD COLUMN author_verified boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT feedback_events_verified_author_check CHECK (author_verified = (author_identity_id IS NOT NULL));

CREATE TABLE control.browser_login_attempts (
    state_digest bytea PRIMARY KEY CHECK (octet_length(state_digest) = 32),
    binding_digest bytea NOT NULL CHECK (octet_length(binding_digest) = 32),
    preview_id text NOT NULL REFERENCES control.previews(id) ON DELETE CASCADE,
    public_url_id text NOT NULL REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    return_path text NOT NULL CHECK (return_path LIKE '/%'),
    nonce text NOT NULL,
    verifier_ciphertext bytea NOT NULL,
    verifier_storage_key_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE TABLE control.browser_access_sessions (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    preview_id text NOT NULL REFERENCES control.previews(id) ON DELETE CASCADE,
    public_url_id text NOT NULL REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    display_name text NOT NULL,
    access_ciphertext bytea NOT NULL,
    refresh_ciphertext bytea NOT NULL,
    storage_key_id text NOT NULL,
    access_expires_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX browser_access_sessions_by_expiry ON control.browser_access_sessions (expires_at);

CREATE TABLE control.browser_access_handoffs (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    session_digest bytea NOT NULL REFERENCES control.browser_access_sessions(token_digest) ON DELETE CASCADE,
    public_url_id text NOT NULL REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    cookie_ciphertext bytea NOT NULL,
    storage_key_id text NOT NULL,
    return_path text NOT NULL CHECK (return_path LIKE '/%'),
    next_url text NOT NULL CHECK (next_url LIKE 'https://%'),
    bridge boolean NOT NULL DEFAULT false,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

-- +goose Down
ALTER TABLE control.feedback_events DROP COLUMN author_identity_id, DROP COLUMN author_display_name, DROP COLUMN author_verified;
ALTER TABLE control.feedback_threads DROP COLUMN author_identity_id, DROP COLUMN author_verified;
ALTER TABLE control.feedback_threads DROP CONSTRAINT feedback_threads_author_display_name_check;
ALTER TABLE control.feedback_threads ADD CONSTRAINT feedback_threads_author_display_name_check
    CHECK (char_length(author_display_name) BETWEEN 1 AND 64);
DROP TABLE control.browser_access_handoffs;
DROP TABLE control.browser_access_sessions;
DROP TABLE control.browser_login_attempts;
ALTER TABLE control.previews DROP COLUMN team_access_enabled;
