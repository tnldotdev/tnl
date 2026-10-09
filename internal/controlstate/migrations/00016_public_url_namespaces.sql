-- +goose Up
ALTER TABLE control.public_urls ADD COLUMN namespace text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE control.public_urls DROP COLUMN namespace;
