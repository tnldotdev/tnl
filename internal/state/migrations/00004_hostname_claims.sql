-- +goose Up
ALTER TABLE hostname_claims ADD COLUMN irreversible INTEGER NOT NULL DEFAULT 1 CHECK (irreversible IN (0, 1));
ALTER TABLE hostname_claims ADD COLUMN tombstoned_at INTEGER;

CREATE TABLE hostname_claim_requests (
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    request_key TEXT NOT NULL,
    requested_label TEXT NOT NULL,
    claim_id TEXT NOT NULL REFERENCES hostname_claims(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (principal_id, request_key)
) STRICT;

CREATE INDEX hostname_claims_principal_active
    ON hostname_claims (principal_id, created_at, id) WHERE tombstoned_at IS NULL;
