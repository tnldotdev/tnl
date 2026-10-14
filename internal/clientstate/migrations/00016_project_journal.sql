-- +goose Up
CREATE TABLE local_runtime_snapshots (
    project_root TEXT PRIMARY KEY,
    cursor INTEGER NOT NULL CHECK (cursor >= 0),
    snapshot_json TEXT NOT NULL CHECK (json_valid(snapshot_json)),
    event_bytes INTEGER NOT NULL DEFAULT 0 CHECK (event_bytes >= 0)
) STRICT;

CREATE TABLE local_runtime_events (
    project_root TEXT NOT NULL REFERENCES local_runtime_snapshots(project_root) ON DELETE CASCADE,
    cursor INTEGER NOT NULL CHECK (cursor > 0),
    event_json TEXT NOT NULL CHECK (json_valid(event_json)),
    PRIMARY KEY (project_root, cursor)
) STRICT;

-- +goose StatementBegin
CREATE TRIGGER local_runtime_event_removed AFTER DELETE ON local_runtime_events BEGIN
    UPDATE local_runtime_snapshots SET event_bytes = event_bytes - length(OLD.event_json)
    WHERE project_root = OLD.project_root;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER local_runtime_event_added AFTER INSERT ON local_runtime_events BEGIN
    UPDATE local_runtime_snapshots SET event_bytes = event_bytes + length(NEW.event_json)
    WHERE project_root = NEW.project_root;
    DELETE FROM local_runtime_events
    WHERE project_root = NEW.project_root AND cursor <= NEW.cursor - 2048;
    DELETE FROM local_runtime_events WHERE project_root = NEW.project_root AND cursor < COALESCE((
        SELECT MIN(cursor) FROM (
            SELECT cursor, SUM(length(event_json)) OVER (ORDER BY cursor DESC) AS bytes
            FROM local_runtime_events WHERE project_root = NEW.project_root
        ) WHERE bytes <= 8388608
    ), NEW.cursor);
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER local_project_tunnel_started AFTER INSERT ON local_tunnels
WHEN NEW.command = 'publish' BEGIN
    INSERT OR IGNORE INTO local_runtime_snapshots (project_root, cursor, snapshot_json)
    VALUES (NEW.project_root, 0, json_object('schema_version', 1, 'project', NEW.project_root,
        'cursor', '0', 'observed_at', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'services', json('[]')));
    UPDATE local_runtime_snapshots
    SET cursor = cursor + 1, snapshot_json = json_set(snapshot_json, '$.cursor', CAST(cursor + 1 AS TEXT))
    WHERE project_root = NEW.project_root;
    INSERT INTO local_runtime_events (project_root, cursor, event_json)
    VALUES (NEW.project_root, (SELECT cursor FROM local_runtime_snapshots WHERE project_root = NEW.project_root),
        json_object('cursor', CAST((SELECT cursor FROM local_runtime_snapshots WHERE project_root = NEW.project_root) AS TEXT),
            'type', CASE WHEN NEW.service = '' THEN 'tunnel.' ELSE 'service.' END || NEW.state,
            'at', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
            CASE WHEN NEW.service = '' THEN 'tunnel' ELSE 'service' END,
            CASE WHEN NEW.service = '' THEN json_object('tunnel_id', NEW.id, 'state', NEW.state,
                'service_protocol', NEW.service_protocol, 'target', NEW.target, 'public_url', '',
                'publish_run_number', NEW.publish_run_number)
            ELSE json_object('service', NEW.service, 'directory', '', 'service_protocol', NEW.service_protocol,
                'tunnel_id', NEW.id, 'target', NEW.target, 'registered', json('true'), 'routable', json('false'),
                'ready', json('false'), 'readiness', json_object('path', '/')) END));
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER local_project_tunnel_changed AFTER UPDATE ON local_tunnels
WHEN NEW.command = 'publish' AND
    (NEW.state <> OLD.state OR NEW.hostname <> OLD.hostname OR NEW.public_port <> OLD.public_port
     OR NEW.target <> OLD.target OR NEW.publish_run_number <> OLD.publish_run_number) BEGIN
    UPDATE local_runtime_snapshots
    SET cursor = cursor + 1, snapshot_json = json_set(snapshot_json, '$.cursor', CAST(cursor + 1 AS TEXT))
    WHERE project_root = NEW.project_root;
    INSERT INTO local_runtime_events (project_root, cursor, event_json)
    VALUES (NEW.project_root, (SELECT cursor FROM local_runtime_snapshots WHERE project_root = NEW.project_root),
        json_object('cursor', CAST((SELECT cursor FROM local_runtime_snapshots WHERE project_root = NEW.project_root) AS TEXT),
            'type', CASE WHEN NEW.service = '' THEN 'tunnel.' || NEW.state
                WHEN NEW.state = 'ready' THEN 'service.publication' ELSE 'service.' || NEW.state END,
            'at', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
            CASE WHEN NEW.service = '' THEN 'tunnel' ELSE 'service' END,
            CASE WHEN NEW.service = '' THEN json_object('tunnel_id', NEW.id, 'state', NEW.state,
                'service_protocol', NEW.service_protocol, 'target', NEW.target,
                'public_url', CASE WHEN NEW.hostname = '' THEN '' WHEN NEW.public_port > 0
                    THEN NEW.hostname || ':' || NEW.public_port ELSE 'https://' || NEW.hostname END,
                'publish_run_number', NEW.publish_run_number)
            ELSE json_object('service', NEW.service, 'directory', '', 'service_protocol', NEW.service_protocol,
                'tunnel_id', NEW.id, 'target', NEW.target,
                'public_url', CASE WHEN NEW.hostname = '' THEN '' WHEN NEW.public_port > 0
                    THEN NEW.hostname || ':' || NEW.public_port ELSE 'https://' || NEW.hostname END,
                'publish_run_number', NEW.publish_run_number,
                'registered', CASE WHEN NEW.state NOT IN ('stopped', 'failed', 'draining') THEN json('true') ELSE json('false') END,
                'routable', CASE WHEN NEW.state = 'ready' THEN json('true') ELSE json('false') END,
                'ready', json('false'), 'readiness', json_object('path', '/')) END));
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER local_project_tunnel_changed;
DROP TRIGGER local_project_tunnel_started;
DROP TRIGGER local_runtime_event_added;
DROP TRIGGER local_runtime_event_removed;
DROP TABLE local_runtime_events;
DROP TABLE local_runtime_snapshots;
