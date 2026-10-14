-- +goose Up
DROP TRIGGER local_inspections_added;
DROP TRIGGER local_inspections_removed;
ALTER TABLE local_inspections RENAME TO local_inspections_previous;

CREATE TABLE local_inspections (
    row_id INTEGER PRIMARY KEY,
    number INTEGER NOT NULL,
    primary_checkout_root TEXT NOT NULL,
    tunnel_id TEXT NOT NULL,
    project_root TEXT NOT NULL,
    shared_project_root TEXT NOT NULL,
    service TEXT NOT NULL,
    service_protocol TEXT NOT NULL CHECK (service_protocol IN ('http', 'postgres', 'mysql', 'redis')),
    received_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    stored_bytes INTEGER NOT NULL CHECK (stored_bytes > 0),
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
    origin TEXT NOT NULL CHECK (origin IN ('local_service', 'tnl')),
    capture_mode TEXT NOT NULL CHECK (capture_mode IN ('summary', 'detailed')),
    detail_json TEXT CHECK (detail_json IS NULL OR json_valid(detail_json)),
    database_operation TEXT NOT NULL DEFAULT '' CHECK (database_operation IN ('', 'query', 'execute')),
    database_result TEXT NOT NULL DEFAULT '' CHECK (database_result IN ('', 'ok', 'error')),
    sql_state TEXT NOT NULL DEFAULT '' CHECK (length(sql_state) IN (0, 5)),
    database_rows INTEGER NOT NULL DEFAULT 0 CHECK (database_rows >= 0),
    database_result_sets INTEGER NOT NULL DEFAULT 0 CHECK (database_result_sets >= 0),
    mysql_error_code INTEGER NOT NULL DEFAULT 0 CHECK (mysql_error_code BETWEEN 0 AND 65535),
    redis_command TEXT NOT NULL DEFAULT '' CHECK (length(redis_command) <= 64),
    CHECK (
        (service_protocol = 'http' AND method != '' AND status BETWEEN 100 AND 599
            AND database_operation = '' AND database_result = '' AND redis_command = '')
        OR (service_protocol IN ('postgres', 'mysql') AND method = '' AND path = '' AND status = 0
            AND database_operation != '' AND database_result != '' AND redis_command = '')
        OR (service_protocol = 'redis' AND method = '' AND path = '' AND status = 0
            AND origin = 'tnl' AND capture_mode = 'summary' AND detail_json IS NULL
            AND database_operation = '' AND database_result != '' AND redis_command != '')
    ),
    UNIQUE (primary_checkout_root, number)
) STRICT;

INSERT INTO local_inspections (
    row_id, number, primary_checkout_root, tunnel_id, project_root, shared_project_root,
    service, service_protocol, received_at, expires_at, stored_bytes,
    method, path, status, duration_ms, origin, capture_mode, detail_json,
    database_operation, database_result, sql_state, database_rows, database_result_sets,
    mysql_error_code
) SELECT
    row_id, number, primary_checkout_root, tunnel_id, project_root, shared_project_root,
    service, service_protocol, received_at, expires_at, stored_bytes,
    method, path, status, duration_ms, origin, capture_mode, detail_json,
    database_operation, database_result, sql_state, database_rows, database_result_sets,
    mysql_error_code
FROM local_inspections_previous;
DROP TABLE local_inspections_previous;

-- +goose StatementBegin
CREATE TRIGGER local_inspections_added AFTER INSERT ON local_inspections BEGIN
    INSERT INTO local_inspection_usage (project_root, service, used_bytes)
        VALUES (NEW.project_root, NEW.service, NEW.stored_bytes)
        ON CONFLICT (project_root, service) DO UPDATE SET used_bytes = used_bytes + excluded.used_bytes;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER local_inspections_removed AFTER DELETE ON local_inspections BEGIN
    UPDATE local_inspection_usage SET used_bytes = used_bytes - OLD.stored_bytes
        WHERE project_root = OLD.project_root AND service = OLD.service;
END;
-- +goose StatementEnd

CREATE INDEX local_inspections_project_idx ON local_inspections (project_root, service, received_at DESC, row_id DESC);
CREATE INDEX local_inspections_shared_project_idx ON local_inspections (shared_project_root, received_at DESC, row_id DESC);
CREATE INDEX local_inspections_expiry_idx ON local_inspections (expires_at);

-- +goose Down
-- this local history shape requires a fresh database to revert.
