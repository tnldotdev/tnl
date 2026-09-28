-- +goose Up
CREATE TABLE control.dns_challenge_changes (
    zone_id text NOT NULL CHECK (zone_id <> ''),
    record_name text NOT NULL CHECK (record_name <> ''),
    desired_digest bytea NOT NULL CHECK (octet_length(desired_digest) = 32),
    change_id text NOT NULL CHECK (change_id <> ''),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (zone_id, record_name)
);
