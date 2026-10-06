-- +goose Up
ALTER TABLE control.previews ADD COLUMN team_access_enabled boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE control.previews DROP COLUMN team_access_enabled;
