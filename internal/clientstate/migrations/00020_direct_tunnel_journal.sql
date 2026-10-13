-- +goose Up
-- direct publisher invocations append to the same project journal as configured services.
ALTER TABLE local_runtime_snapshots ADD COLUMN event_bytes INTEGER NOT NULL DEFAULT 0 CHECK (event_bytes >= 0);

-- +goose StatementBegin
CREATE TRIGGER local_runtime_event_bytes_removed AFTER DELETE ON local_runtime_events BEGIN
    UPDATE local_runtime_snapshots SET event_bytes = event_bytes - length(OLD.event_json)
    WHERE project_root = OLD.project_root;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER local_runtime_event_bytes_bounded AFTER UPDATE OF event_bytes ON local_runtime_snapshots
WHEN NEW.event_bytes > 8388608 BEGIN
    DELETE FROM local_runtime_events
    WHERE project_root = NEW.project_root AND cursor < COALESCE((
        SELECT MIN(cursor) FROM (
            SELECT cursor, SUM(length(event_json)) OVER (ORDER BY cursor DESC) AS bytes
            FROM local_runtime_events WHERE project_root = NEW.project_root
        ) WHERE bytes <= 8388608
    ), NEW.cursor);
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER local_runtime_events_bounded AFTER INSERT ON local_runtime_events BEGIN
    UPDATE local_runtime_snapshots SET event_bytes = event_bytes + length(NEW.event_json)
    WHERE project_root = NEW.project_root;
    DELETE FROM local_runtime_events
    WHERE project_root = NEW.project_root AND cursor <= NEW.cursor - 2048;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER local_direct_tunnel_started AFTER INSERT ON local_tunnels
WHEN NEW.command = 'publish' AND NEW.service = '' BEGIN
    INSERT OR IGNORE INTO local_runtime_snapshots (project_root, cursor, snapshot_json)
    VALUES (NEW.project_root, 0, json_object('schema_version', 1, 'project', NEW.project_root,
        'cursor', '0', 'observed_at', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'services', json('[]')));
    UPDATE local_runtime_snapshots
    SET cursor = cursor + 1,
        snapshot_json = json_set(snapshot_json, '$.cursor', CAST(cursor + 1 AS TEXT),
            '$.observed_at', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    WHERE project_root = NEW.project_root;
    INSERT INTO local_runtime_events (project_root, cursor, event_json)
    VALUES (NEW.project_root, (SELECT cursor FROM local_runtime_snapshots WHERE project_root = NEW.project_root),
        json_object('cursor', CAST((SELECT cursor FROM local_runtime_snapshots WHERE project_root = NEW.project_root) AS TEXT),
            'type', 'tunnel.' || NEW.state, 'at', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
            'tunnel', json_object('tunnel_id', NEW.id, 'state', NEW.state,
                'service_protocol', NEW.service_protocol, 'target', NEW.target, 'public_url', '',
                'publish_run_number', NEW.publish_run_number)));
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER local_direct_tunnel_changed AFTER UPDATE ON local_tunnels
WHEN NEW.command = 'publish' AND NEW.service = '' AND
    (NEW.state <> OLD.state OR NEW.hostname <> OLD.hostname OR NEW.public_port <> OLD.public_port
     OR NEW.target <> OLD.target OR NEW.publish_run_number <> OLD.publish_run_number) BEGIN
    UPDATE local_runtime_snapshots
    SET cursor = cursor + 1,
        snapshot_json = json_set(snapshot_json, '$.cursor', CAST(cursor + 1 AS TEXT),
            '$.observed_at', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    WHERE project_root = NEW.project_root;
    INSERT INTO local_runtime_events (project_root, cursor, event_json)
    VALUES (NEW.project_root, (SELECT cursor FROM local_runtime_snapshots WHERE project_root = NEW.project_root),
        json_object('cursor', CAST((SELECT cursor FROM local_runtime_snapshots WHERE project_root = NEW.project_root) AS TEXT),
            'type', 'tunnel.' || NEW.state, 'at', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
            'tunnel', json_object('tunnel_id', NEW.id, 'state', NEW.state,
                'service_protocol', NEW.service_protocol, 'target', NEW.target,
                'public_url', CASE WHEN NEW.hostname = '' THEN '' WHEN NEW.public_port > 0
                    THEN NEW.hostname || ':' || NEW.public_port ELSE 'https://' || NEW.hostname END,
                'publish_run_number', NEW.publish_run_number)));
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER local_direct_tunnel_changed;
DROP TRIGGER local_direct_tunnel_started;
DROP TRIGGER local_runtime_events_bounded;
DROP TRIGGER local_runtime_event_bytes_bounded;
DROP TRIGGER local_runtime_event_bytes_removed;
ALTER TABLE local_runtime_snapshots DROP COLUMN event_bytes;
