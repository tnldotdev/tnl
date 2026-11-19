-- +goose Up
DROP TRIGGER local_project_service_seen;

-- +goose StatementBegin
CREATE TRIGGER local_project_service_seen AFTER INSERT ON local_tunnels
WHEN NEW.service_id IS NOT NULL BEGIN
    INSERT INTO project_service_inventory (project_root, server_origin, service_id, last_seen_at)
    VALUES (NEW.project_root, NEW.server_origin, NEW.service_id, NEW.updated_at)
    ON CONFLICT (project_root, server_origin, service_id)
    DO UPDATE SET last_seen_at = excluded.last_seen_at;
    DELETE FROM project_service_inventory
    WHERE project_root = NEW.project_root AND server_origin = NEW.server_origin
      AND last_seen_at < NEW.updated_at - 2592000000000000;
END;
-- +goose StatementEnd
