-- +goose Up
-- client inspection history is local and is reset rather than migrated.
DROP TABLE local_requests;
DROP TABLE local_request_counters;

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
    sql_operation TEXT NOT NULL DEFAULT '' CHECK (sql_operation IN ('', 'query', 'execute')),
    result TEXT NOT NULL DEFAULT '' CHECK (result IN ('', 'ok', 'error')),
    redis_command TEXT NOT NULL DEFAULT '' CHECK (length(redis_command) <= 64),
    sql_state TEXT NOT NULL DEFAULT '' CHECK (length(sql_state) IN (0, 5)),
    sql_rows INTEGER NOT NULL DEFAULT 0 CHECK (sql_rows >= 0),
    mysql_result_sets INTEGER NOT NULL DEFAULT 0 CHECK (mysql_result_sets >= 0),
    mysql_error_code INTEGER NOT NULL DEFAULT 0 CHECK (mysql_error_code BETWEEN 0 AND 65535),
    CHECK (
      (service_protocol = 'http' AND method != '' AND status BETWEEN 100 AND 599 AND sql_operation = '' AND result = '' AND redis_command = '')
      OR (service_protocol IN ('postgres', 'mysql') AND method = '' AND path = '' AND status = 0
          AND sql_operation != '' AND result != '' AND redis_command = '')
      OR (service_protocol = 'redis' AND method = '' AND path = '' AND status = 0
          AND sql_operation = '' AND result != '' AND redis_command != '' AND sql_state = ''
          AND sql_rows = 0 AND mysql_result_sets = 0 AND mysql_error_code = 0)
    ),
    UNIQUE (primary_checkout_root, number)
) STRICT;

CREATE TABLE local_inspection_counters (
    primary_checkout_root TEXT PRIMARY KEY,
    last_number INTEGER NOT NULL CHECK (last_number > 0)
) STRICT;

CREATE TABLE local_inspection_usage (
    project_root TEXT NOT NULL,
    service TEXT NOT NULL,
    used_bytes INTEGER NOT NULL CHECK (used_bytes >= 0),
    PRIMARY KEY (project_root, service)
) STRICT;

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
DROP TABLE local_inspections;
DROP TABLE local_inspection_counters;
DROP TABLE local_inspection_usage;
