-- +goose Up
-- keep existing rows unchanged while control processes at the previous schema
-- version continue serving; their generated SELECT * scans expect fixed shapes.
CREATE TABLE control.publisher_identities (
    id text PRIMARY KEY CHECK (id <> ''),
    team_id text NOT NULL REFERENCES control.teams(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (name <> ''),
    kind text NOT NULL CHECK (kind IN ('installed', 'run', 'automation', 'guest')),
    created_by_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    revoked_at timestamptz,
    UNIQUE (id, team_id),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX publisher_identities_team ON control.publisher_identities(team_id, id);

CREATE TABLE control.publisher_identity_keys (
    id text PRIMARY KEY CHECK (id <> ''),
    publisher_identity_id text NOT NULL REFERENCES control.publisher_identities(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision >= 1),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    created_at timestamptz NOT NULL,
    retired_at timestamptz,
    UNIQUE (publisher_identity_id, revision),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE TABLE control.publisher_identity_grants (
    id text PRIMARY KEY CHECK (id <> ''),
    publisher_identity_id text NOT NULL REFERENCES control.publisher_identities(id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind IN ('saved_url', 'namespace')),
    public_url_id text REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    domain_id text REFERENCES control.domains(id) ON DELETE RESTRICT,
    namespace text,
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    revoked_at timestamptz,
    CHECK ((kind = 'saved_url' AND public_url_id IS NOT NULL AND domain_id IS NULL AND namespace IS NULL)
        OR (kind = 'namespace' AND public_url_id IS NULL AND domain_id IS NOT NULL AND namespace IS NOT NULL AND namespace <> '')),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX publisher_identity_grants_url ON control.publisher_identity_grants(public_url_id, id) WHERE kind = 'saved_url';
CREATE INDEX publisher_identity_grants_owner ON control.publisher_identity_grants(publisher_identity_id, id);
CREATE UNIQUE INDEX publisher_identity_grants_active_url
    ON control.publisher_identity_grants(publisher_identity_id, public_url_id)
    WHERE kind = 'saved_url' AND revoked_at IS NULL;
CREATE UNIQUE INDEX publisher_identity_grants_active_namespace
    ON control.publisher_identity_grants(publisher_identity_id, domain_id, namespace)
    WHERE kind = 'namespace' AND revoked_at IS NULL;

CREATE TABLE control.publisher_enrollment_keys (
    id text PRIMARY KEY CHECK (id <> ''),
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    team_id text NOT NULL REFERENCES control.teams(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (name <> ''),
    identity_kind text NOT NULL CHECK (identity_kind IN ('installed', 'automation')),
    grant_kind text NOT NULL CHECK (grant_kind IN ('saved_url', 'namespace')),
    public_url_id text REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    domain_id text REFERENCES control.domains(id) ON DELETE RESTRICT,
    namespace text,
    created_by_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    redeemed_identity_id text REFERENCES control.publisher_identities(id) ON DELETE RESTRICT,
    redeemed_key_id text REFERENCES control.publisher_identity_keys(id) ON DELETE RESTRICT,
    redeemed_grant_id text REFERENCES control.publisher_identity_grants(id) ON DELETE RESTRICT,
    redeemed_public_key bytea CHECK (octet_length(redeemed_public_key) = 32),
    redeemed_at timestamptz,
    CHECK ((grant_kind = 'saved_url' AND public_url_id IS NOT NULL AND domain_id IS NULL AND namespace IS NULL)
        OR (grant_kind = 'namespace' AND public_url_id IS NULL AND domain_id IS NOT NULL AND namespace IS NOT NULL AND namespace <> '')),
    CHECK (expires_at > created_at),
    CHECK ((redeemed_identity_id IS NULL) = (redeemed_at IS NULL)),
    CHECK ((redeemed_identity_id IS NULL) = (redeemed_key_id IS NULL)),
    CHECK ((redeemed_identity_id IS NULL) = (redeemed_grant_id IS NULL)),
    CHECK ((redeemed_identity_id IS NULL) = (redeemed_public_key IS NULL))
);

CREATE TABLE control.publisher_assertions (
    publisher_identity_id text NOT NULL REFERENCES control.publisher_identities(id) ON DELETE RESTRICT,
    assertion_id text NOT NULL CHECK (assertion_id <> ''),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (publisher_identity_id, assertion_id)
);
CREATE INDEX publisher_assertions_expiry ON control.publisher_assertions(expires_at);

CREATE TABLE control.publisher_access_tokens (
    digest bytea PRIMARY KEY CHECK (octet_length(digest) = 32),
    publisher_identity_id text NOT NULL REFERENCES control.publisher_identities(id) ON DELETE RESTRICT,
    grant_id text NOT NULL REFERENCES control.publisher_identity_grants(id) ON DELETE RESTRICT,
    key_id text NOT NULL REFERENCES control.publisher_identity_keys(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX publisher_access_tokens_expiry ON control.publisher_access_tokens(expires_at);

CREATE TABLE control.publish_run_publisher_identities (
    publish_run_id text PRIMARY KEY REFERENCES control.publish_runs(id) ON DELETE RESTRICT,
    public_url_id text NOT NULL REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    publisher_identity_id text NOT NULL REFERENCES control.publisher_identities(id) ON DELETE RESTRICT,
    publisher_grant_id text NOT NULL REFERENCES control.publisher_identity_grants(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL
);
CREATE INDEX publish_run_publisher_identities_identity
    ON control.publish_run_publisher_identities(publisher_identity_id, publish_run_id);

-- +goose Down
DROP TABLE control.publish_run_publisher_identities;
DROP TABLE control.publisher_access_tokens;
DROP TABLE control.publisher_assertions;
DROP TABLE control.publisher_enrollment_keys;
DROP TABLE control.publisher_identity_grants;
DROP TABLE control.publisher_identity_keys;
DROP TABLE control.publisher_identities;
