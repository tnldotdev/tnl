-- +goose Up
CREATE TABLE server_state (
    state_key TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;
