-- +goose Up
-- keep all existing credential and publish run rows and their row shapes intact.
CREATE TABLE control.publisher_namespace_allocations (
    public_url_id text PRIMARY KEY REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    publisher_identity_id text NOT NULL REFERENCES control.publisher_identities(id) ON DELETE RESTRICT,
    publisher_grant_id text NOT NULL REFERENCES control.publisher_identity_grants(id) ON DELETE RESTRICT,
    invocation_id text NOT NULL CHECK (invocation_id <> ''),
    created_at timestamptz NOT NULL,
    UNIQUE (publisher_grant_id, invocation_id)
);

-- +goose Down
DROP TABLE control.publisher_namespace_allocations;
