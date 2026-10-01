-- +goose Up
ALTER TABLE client_settings
ADD COLUMN telemetry_enabled INTEGER NOT NULL DEFAULT 1 CHECK (telemetry_enabled IN (0, 1));

-- +goose Down
ALTER TABLE client_settings DROP COLUMN telemetry_enabled;
