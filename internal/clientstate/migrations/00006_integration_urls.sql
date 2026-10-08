-- +goose Up
CREATE TABLE integration_url_publishers (
    server_origin TEXT NOT NULL REFERENCES server_profiles(origin) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    publisher_instance_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, hostname)
) STRICT;

-- +goose Down
DROP TABLE integration_url_publishers;
