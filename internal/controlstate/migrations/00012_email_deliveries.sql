-- +goose Up
CREATE TABLE control.email_deliveries (
    delivery_id text PRIMARY KEY REFERENCES control.team_invitations(id) ON DELETE RESTRICT,
    payload_ciphertext bytea,
    storage_key_id text,
    available_at timestamptz NOT NULL,
    attempts bigint NOT NULL DEFAULT 0,
    lease_owner text,
    lease_expires_at timestamptz,
    completed_at timestamptz,
    last_status integer NOT NULL DEFAULT 0,
    CHECK ((payload_ciphertext IS NULL) = (storage_key_id IS NULL)),
    CHECK ((completed_at IS NULL) = (payload_ciphertext IS NOT NULL)),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL))
);
CREATE INDEX email_deliveries_pending ON control.email_deliveries(available_at) WHERE completed_at IS NULL;

-- +goose Down
DROP TABLE control.email_deliveries;
