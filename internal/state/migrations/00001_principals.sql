-- +goose Up
CREATE TABLE principals (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE access_credentials (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
) STRICT;

CREATE INDEX access_credentials_principal_id
    ON access_credentials (principal_id);
