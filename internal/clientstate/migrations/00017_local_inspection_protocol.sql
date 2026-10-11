-- +goose Up
ALTER TABLE local_requests ADD COLUMN service_protocol TEXT NOT NULL DEFAULT 'http'
    CHECK (service_protocol IN ('http', 'postgres'));
ALTER TABLE local_requests ADD COLUMN database_operation TEXT NOT NULL DEFAULT ''
    CHECK (database_operation IN ('', 'query', 'execute'));
ALTER TABLE local_requests ADD COLUMN database_result TEXT NOT NULL DEFAULT ''
    CHECK (database_result IN ('', 'ok', 'error'));
ALTER TABLE local_requests ADD COLUMN sql_state TEXT NOT NULL DEFAULT ''
    CHECK (length(sql_state) IN (0, 5));
ALTER TABLE local_requests ADD COLUMN database_rows INTEGER NOT NULL DEFAULT 0
    CHECK (database_rows >= 0);

-- +goose Down
ALTER TABLE local_requests DROP COLUMN database_rows;
ALTER TABLE local_requests DROP COLUMN sql_state;
ALTER TABLE local_requests DROP COLUMN database_result;
ALTER TABLE local_requests DROP COLUMN database_operation;
ALTER TABLE local_requests DROP COLUMN service_protocol;
