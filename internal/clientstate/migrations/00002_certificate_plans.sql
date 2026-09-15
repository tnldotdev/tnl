-- +goose Up
-- Legacy route material has no authoritative team/plan provenance and cannot be reused safely.
DROP TABLE route_certificates;

CREATE TABLE certificate_material (
    server_origin TEXT NOT NULL REFERENCES server_profiles (origin) ON DELETE CASCADE,
    team_id TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    plan TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'current')),
    key_der BLOB NOT NULL,
    csr_der BLOB NOT NULL,
    certificate_pem BLOB,
    renew_at INTEGER,
    issuance_id TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_origin, team_id, cache_key, plan, phase)
) STRICT;
