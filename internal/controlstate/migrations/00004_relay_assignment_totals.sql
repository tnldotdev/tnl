-- +goose Up
-- Install and backfill atomically with respect to assignment/session writers.
LOCK TABLE control.relay_services, control.route_sessions, control.route_session_connections
    IN SHARE ROW EXCLUSIVE MODE;

-- Make parent eligibility part of each assignment's stored contribution. The
-- foreign key propagates closure/reopening, including compound SQL statements,
-- without relying on which table's AFTER trigger runs first. Historical active
-- slots on closed sessions are preserved and remain uncounted.
ALTER TABLE control.route_sessions
    ADD COLUMN assignments_open boolean GENERATED ALWAYS AS (closed_at IS NULL) STORED,
    ADD CONSTRAINT route_sessions_assignment_parent UNIQUE (id, assignments_open);
ALTER TABLE control.route_session_connections
    ADD COLUMN session_open boolean NOT NULL DEFAULT true;
UPDATE control.route_session_connections AS connections
SET session_open = sessions.assignments_open
FROM control.route_sessions AS sessions
WHERE sessions.id = connections.route_session_id;
ALTER TABLE control.route_session_connections
    ADD CONSTRAINT route_session_connections_assignment_parent
    FOREIGN KEY (route_session_id, session_open)
    REFERENCES control.route_sessions (id, assignments_open) ON UPDATE CASCADE
    DEFERRABLE INITIALLY DEFERRED;
-- CASCADE runs immediately; deferring only the final FK check allows a compound
-- statement to close both tables regardless of its AFTER-trigger execution order.

-- Keep reservation writes separate from relay_services: claims hold shared
-- service locks and must never upgrade those locks when changing connection state.
CREATE TABLE control.relay_service_assignment_totals (
    relay_service_id text PRIMARY KEY REFERENCES control.relay_services(relay_service_id) ON DELETE CASCADE,
    assignment_count bigint NOT NULL DEFAULT 0 CHECK (assignment_count >= 0)
);

INSERT INTO control.relay_service_assignment_totals (relay_service_id, assignment_count)
SELECT services.relay_service_id, count(connections.route_session_id)
FROM control.relay_services AS services
LEFT JOIN (
    SELECT connections.route_session_id, connections.relay_service_id
    FROM control.route_session_connections AS connections
    JOIN control.route_sessions AS sessions ON sessions.id = connections.route_session_id
    WHERE sessions.closed_at IS NULL
      AND connections.state IN ('assigned', 'connected', 'ready', 'draining')
) AS connections USING (relay_service_id)
GROUP BY services.relay_service_id;

-- +goose StatementBegin
CREATE FUNCTION control.initialize_relay_assignment_total() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO control.relay_service_assignment_totals (relay_service_id)
    VALUES (NEW.relay_service_id);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER initialize_relay_assignment_total
AFTER INSERT ON control.relay_services
FOR EACH ROW EXECUTE FUNCTION control.initialize_relay_assignment_total();

-- Reservation writers use one transaction guard, not incrementally acquired
-- per-service locks: expiry followed by placement and multi-session revocation
-- can touch services in different orders across statements. Placement takes this
-- guard BEFORE service guards/rows and leases. Claims/readiness have zero delta
-- and never take it. Registration only initializes a NEW service's total.
--
-- Lifecycle callers lock ALL affected routes before their first reservation
-- change and keep route-local session/connection work under those route locks.
-- If placing, they take this guard before services and leases; claim/readiness
-- callers holding service locks may only make zero-delta changes. Routing events
-- are published last. No reservation writer may acquire another route after the
-- guard. Bulk closure already locks its entire route set.
-- Parent eligibility changes cascade to only that session's (at most two) slots.
-- The counter trigger never locks service rows or looks up/locks a parent row.
-- +goose StatementBegin
CREATE FUNCTION control.update_relay_assignment_totals() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    old_service text;
    new_service text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        IF OLD.session_open AND OLD.state IN ('assigned', 'connected', 'ready', 'draining') THEN
            old_service := OLD.relay_service_id;
        END IF;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        IF NEW.session_open AND NEW.state IN ('assigned', 'connected', 'ready', 'draining') THEN
            new_service := NEW.relay_service_id;
        END IF;
    END IF;
    IF old_service IS NOT DISTINCT FROM new_service THEN
        RETURN NULL;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('tnl:relay-assignment-totals', 0));
    IF old_service IS NOT NULL THEN
        UPDATE control.relay_service_assignment_totals
        SET assignment_count = assignment_count - 1 WHERE relay_service_id = old_service;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'missing relay assignment total for %', old_service USING ERRCODE = '23514';
        END IF;
    END IF;
    IF new_service IS NOT NULL THEN
        UPDATE control.relay_service_assignment_totals
        SET assignment_count = assignment_count + 1 WHERE relay_service_id = new_service;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'missing relay assignment total for %', new_service USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER update_relay_assignment_totals
AFTER INSERT OR UPDATE OR DELETE ON control.route_session_connections
FOR EACH ROW EXECUTE FUNCTION control.update_relay_assignment_totals();

-- +goose Down
DROP TRIGGER update_relay_assignment_totals ON control.route_session_connections;
DROP FUNCTION control.update_relay_assignment_totals();
DROP TRIGGER initialize_relay_assignment_total ON control.relay_services;
DROP FUNCTION control.initialize_relay_assignment_total();
DROP TABLE control.relay_service_assignment_totals;
ALTER TABLE control.route_session_connections
    DROP CONSTRAINT route_session_connections_assignment_parent,
    DROP COLUMN session_open;
ALTER TABLE control.route_sessions
    DROP CONSTRAINT route_sessions_assignment_parent,
    DROP COLUMN assignments_open;
