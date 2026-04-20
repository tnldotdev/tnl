-- +goose Up
CREATE TABLE external_token_exchanges (
    token_hash BLOB PRIMARY KEY,
    consumed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX external_token_exchanges_expires_at
    ON external_token_exchanges (expires_at);
