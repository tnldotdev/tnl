-- +goose Up
-- Each bounded cleanup candidate probes for a newer snapshot anchor without
-- scanning retained payloads. Entry-revision anchors use the existing route index.
CREATE INDEX ingress_routing_table_events_snapshot_anchor
    ON control.ingress_routing_table_events (
        canonical_hostname,
        (event_kind IN ('route_upsert', 'route_tombstone')),
        routing_table_revision
    );

-- +goose Down
DROP INDEX control.ingress_routing_table_events_snapshot_anchor;
