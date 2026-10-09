-- +goose Up
ALTER TABLE control.managed_label_reservations
    ADD COLUMN direct_team_id text REFERENCES control.teams(id) ON DELETE RESTRICT;

-- +goose Down
ALTER TABLE control.managed_label_reservations DROP COLUMN direct_team_id;
