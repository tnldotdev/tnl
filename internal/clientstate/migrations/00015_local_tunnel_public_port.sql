-- +goose Up
ALTER TABLE local_tunnels ADD COLUMN public_port INTEGER NOT NULL DEFAULT 0
    CHECK (public_port BETWEEN 0 AND 65535);
ALTER TABLE local_tunnels ADD COLUMN service_protocol TEXT NOT NULL DEFAULT 'http'
    CHECK (service_protocol IN ('http', 'postgres', 'mysql'));

-- +goose Down
ALTER TABLE local_tunnels DROP COLUMN service_protocol;
ALTER TABLE local_tunnels DROP COLUMN public_port;
