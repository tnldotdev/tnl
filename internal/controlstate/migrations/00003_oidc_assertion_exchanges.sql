-- +goose Up
CREATE TABLE control.oidc_assertion_exchanges (
    assertion_digest bytea PRIMARY KEY CHECK (octet_length(assertion_digest) = 32),
    consumed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > consumed_at)
);

CREATE INDEX oidc_assertion_exchanges_expires_at
    ON control.oidc_assertion_exchanges (expires_at);
