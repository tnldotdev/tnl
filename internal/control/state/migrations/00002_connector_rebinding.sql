-- +goose Up
ALTER TABLE control.connector_peer_pairs
    ADD COLUMN session_key_ciphertext bytea,
    ADD COLUMN session_key_digest bytea CHECK (session_key_digest IS NULL OR octet_length(session_key_digest)=32),
    ADD COLUMN session_key_storage_key_id text,
    ADD COLUMN trust_revision bigint NOT NULL DEFAULT 1 CHECK (trust_revision>0),
    ADD COLUMN high_water_generation bigint NOT NULL DEFAULT 1 CHECK (high_water_generation>0),
    ADD COLUMN binding_operation_id text NOT NULL DEFAULT '',
    ADD COLUMN binding_challenge bytea,
    ADD COLUMN publisher_proved_until timestamptz,
    ADD COLUMN publisher_proof_digest bytea,
    ADD COLUMN rebind_operation_id text NOT NULL DEFAULT '',
    ADD COLUMN rebind_generation bigint,
    ADD COLUMN rebind_status text CHECK (rebind_status IN ('pending','active','aborted','expired')),
    ADD COLUMN rebind_prepare_digest bytea,
    ADD COLUMN rebind_activate_digest bytea,
    ADD COLUMN rebind_abort_digest bytea;

-- existing process-local sessions cannot be reconstructed by a schema upgrade.
-- retain their owner/replay records, but never invent a frame key or installation.
UPDATE control.connector_peer_pairs SET high_water_generation=delivery_generation,publisher_prepared_until=NULL;

-- +goose StatementBegin
CREATE FUNCTION control.connector_peer_generation_defaults() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' THEN
        NEW.high_water_generation=GREATEST(OLD.high_water_generation,NEW.high_water_generation);
    END IF;
    NEW.high_water_generation=GREATEST(NEW.high_water_generation,NEW.delivery_generation);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER connector_peer_generation_defaults BEFORE INSERT OR UPDATE ON control.connector_peer_pairs
    FOR EACH ROW EXECUTE FUNCTION control.connector_peer_generation_defaults();

CREATE TABLE control.connector_peer_pending_bindings (
    pair_id text PRIMARY KEY REFERENCES control.connector_peer_pairs(id) ON DELETE CASCADE,
    delivery_generation bigint NOT NULL CHECK (delivery_generation>0),
    operation_id text NOT NULL CHECK (operation_id ~ '^ik_[A-Za-z0-9]{22}$'),
    challenge bytea NOT NULL CHECK (octet_length(challenge)=32),
    slots jsonb NOT NULL CHECK (jsonb_typeof(slots)='array' AND jsonb_array_length(slots)=2),
    key_ciphertext bytea NOT NULL,
    key_digest bytea NOT NULL CHECK (octet_length(key_digest)=32),
    storage_key_id text NOT NULL,
    created_at timestamptz NOT NULL,
    pending_until timestamptz NOT NULL,
    publisher_prepared_until timestamptz,
    publisher_proved_until timestamptz,
    publisher_proof_digest bytea,
    CHECK (pending_until>created_at AND pending_until<=created_at+interval '10 seconds')
);

ALTER TABLE control.connector_peer_pair_leg_claims ADD COLUMN delivery_generation bigint NOT NULL DEFAULT 0;
UPDATE control.connector_peer_pair_leg_claims c SET delivery_generation=p.delivery_generation
    FROM control.connector_peer_pairs p WHERE c.pair_id=p.id;
ALTER TABLE control.connector_peer_pair_leg_claims DROP CONSTRAINT connector_peer_pair_leg_claims_pkey,
    ADD PRIMARY KEY(pair_id,delivery_generation,connection_slot),
    ADD CHECK (delivery_generation>0);
-- +goose StatementBegin
CREATE FUNCTION control.connector_peer_claim_generation_default() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.delivery_generation=0 THEN
        SELECT delivery_generation INTO NEW.delivery_generation FROM control.connector_peer_pairs WHERE id=NEW.pair_id;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER connector_peer_claim_generation_default BEFORE INSERT ON control.connector_peer_pair_leg_claims
    FOR EACH ROW EXECUTE FUNCTION control.connector_peer_claim_generation_default();

ALTER TABLE control.connector_peer_audit_bindings ADD COLUMN delivery_generation bigint NOT NULL DEFAULT 0,
    ADD COLUMN retired_at timestamptz;
UPDATE control.connector_peer_audit_bindings a SET delivery_generation=p.delivery_generation
    FROM control.connector_peer_pairs p WHERE a.pair_id=p.id;
ALTER TABLE control.connector_peer_audit_bindings DROP CONSTRAINT connector_peer_audit_bindings_pkey,
    ADD PRIMARY KEY(pair_id,delivery_generation);
