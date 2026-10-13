-- +goose Up
-- a separate table keeps older control queries using SELECT * on publish_runs
-- compatible while the new controls are rolled out.
CREATE TABLE control.publish_run_traffic_limits (
    publish_run_id text PRIMARY KEY REFERENCES control.publish_runs(id) ON DELETE CASCADE,
    limits jsonb NOT NULL CHECK (jsonb_typeof(limits) = 'object')
);

-- +goose Down
DROP TABLE control.publish_run_traffic_limits;
