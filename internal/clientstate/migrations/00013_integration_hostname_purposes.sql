-- +goose Up
ALTER TABLE integration_url_hostnames ADD COLUMN label_version INTEGER NOT NULL DEFAULT 1;

-- +goose Down
ALTER TABLE integration_url_hostnames DROP COLUMN label_version;
