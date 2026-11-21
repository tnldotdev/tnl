-- +goose Up
CREATE TABLE control.connector_peer_watch_versions (
    service_run_id text PRIMARY KEY REFERENCES control.service_runs(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0)
);

-- +goose StatementBegin
CREATE FUNCTION control.record_connector_peer_watch_change(changed_run text)
RETURNS void LANGUAGE sql AS $$
    INSERT INTO control.connector_peer_watch_versions AS versions(service_run_id,revision)
    VALUES (changed_run,1)
    ON CONFLICT (service_run_id) DO UPDATE SET revision=versions.revision+1;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION control.connector_peer_pair_watch_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- a replacement inserts its successor in the same transaction. ordinary
    -- cleanup deletes only after the pair and its local retention fence expire.
    -- publisher installation reports must not wake the same publisher again.
    IF TG_OP='INSERT' OR ROW(NEW.owner_revision,NEW.delivery_generation,NEW.rebind_status,
        NEW.high_water_generation,NEW.expires_at) IS DISTINCT FROM
        ROW(OLD.owner_revision,OLD.delivery_generation,OLD.rebind_status,OLD.high_water_generation,OLD.expires_at) THEN
        PERFORM control.record_connector_peer_watch_change(NEW.service_run_id);
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER connector_peer_pair_watch_change
    AFTER INSERT OR UPDATE OF owner_revision,delivery_generation,rebind_status,high_water_generation,expires_at
    ON control.connector_peer_pairs
    FOR EACH ROW EXECUTE FUNCTION control.connector_peer_pair_watch_change();

-- +goose StatementBegin
CREATE FUNCTION control.connector_peer_leg_watch_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- creation alone is not enough: a publisher may fetch before the relay legs
    -- are claimed. a later claim can make that same candidate deliverable.
    PERFORM control.record_connector_peer_watch_change(pair.service_run_id)
    FROM control.connector_peer_pairs pair WHERE pair.id=NEW.pair_id;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER connector_peer_leg_watch_change
    AFTER INSERT OR UPDATE OF checked_at,confirmed_until ON control.connector_peer_pair_leg_claims
    FOR EACH ROW EXECUTE FUNCTION control.connector_peer_leg_watch_change();

-- +goose Down
DROP TRIGGER connector_peer_leg_watch_change ON control.connector_peer_pair_leg_claims;
DROP FUNCTION control.connector_peer_leg_watch_change();
DROP TRIGGER connector_peer_pair_watch_change ON control.connector_peer_pairs;
DROP FUNCTION control.connector_peer_pair_watch_change();
DROP FUNCTION control.record_connector_peer_watch_change(text);
DROP TABLE control.connector_peer_watch_versions;
