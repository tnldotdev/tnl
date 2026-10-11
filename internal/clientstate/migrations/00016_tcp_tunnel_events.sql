-- +goose Up
CREATE TABLE local_tunnel_event_cursors (
    project_root TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL CHECK (sequence > 0)
) STRICT;

CREATE TABLE local_tunnel_events (
    project_root TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    tunnel_id TEXT NOT NULL,
    service TEXT NOT NULL,
    service_protocol TEXT NOT NULL CHECK (service_protocol IN ('postgres', 'mysql', 'redis', 'ssh', 'mongodb')),
    state TEXT NOT NULL,
    target TEXT NOT NULL,
    hostname TEXT NOT NULL,
    public_port INTEGER NOT NULL CHECK (public_port BETWEEN 0 AND 65535),
    publish_run_number INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (project_root, sequence)
) STRICT;

-- +goose StatementBegin
CREATE TRIGGER local_tunnel_event_started AFTER INSERT ON local_tunnels
WHEN NEW.service <> '' AND NEW.service_protocol <> 'http'
BEGIN
    INSERT INTO local_tunnel_event_cursors (project_root, sequence) VALUES (NEW.project_root, 1)
        ON CONFLICT (project_root) DO UPDATE SET sequence = sequence + 1;
    INSERT INTO local_tunnel_events
        (project_root, sequence, tunnel_id, service, service_protocol, state, target, hostname, public_port, publish_run_number, created_at)
    VALUES (NEW.project_root, (SELECT sequence FROM local_tunnel_event_cursors WHERE project_root = NEW.project_root),
        NEW.id, NEW.service, NEW.service_protocol, NEW.state, NEW.target, NEW.hostname, NEW.public_port, NEW.publish_run_number, NEW.updated_at);
    DELETE FROM local_tunnel_events
    WHERE project_root = NEW.project_root
      AND sequence <= (SELECT sequence - 2048 FROM local_tunnel_event_cursors WHERE project_root = NEW.project_root);
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER local_tunnel_event_changed AFTER UPDATE ON local_tunnels
WHEN NEW.service <> '' AND NEW.service_protocol <> 'http'
 AND (NEW.state <> OLD.state OR NEW.hostname <> OLD.hostname OR NEW.public_port <> OLD.public_port
      OR NEW.target <> OLD.target OR NEW.publish_run_number <> OLD.publish_run_number)
BEGIN
    INSERT INTO local_tunnel_event_cursors (project_root, sequence) VALUES (NEW.project_root, 1)
        ON CONFLICT (project_root) DO UPDATE SET sequence = sequence + 1;
    INSERT INTO local_tunnel_events
        (project_root, sequence, tunnel_id, service, service_protocol, state, target, hostname, public_port, publish_run_number, created_at)
    VALUES (NEW.project_root, (SELECT sequence FROM local_tunnel_event_cursors WHERE project_root = NEW.project_root),
        NEW.id, NEW.service, NEW.service_protocol, NEW.state, NEW.target, NEW.hostname, NEW.public_port, NEW.publish_run_number, NEW.updated_at);
    DELETE FROM local_tunnel_events
    WHERE project_root = NEW.project_root
      AND sequence <= (SELECT sequence - 2048 FROM local_tunnel_event_cursors WHERE project_root = NEW.project_root);
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER local_tunnel_event_changed;
DROP TRIGGER local_tunnel_event_started;
DROP TABLE local_tunnel_events;
DROP TABLE local_tunnel_event_cursors;
