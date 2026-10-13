-- +goose Up
DROP TABLE control.authority_revision_states;

-- +goose Down
-- this prelaunch authority boundary requires a fresh database.
