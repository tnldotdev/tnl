-- +goose Up
-- let the native publisher create a run-scoped identity from a current human
-- decision without changing the enrollment row shape read by serving controls.
ALTER TABLE control.publisher_enrollment_keys
    DROP CONSTRAINT publisher_enrollment_keys_identity_kind_check,
    ADD CONSTRAINT publisher_enrollment_keys_identity_kind_check
        CHECK (identity_kind IN ('installed', 'automation', 'run'));

CREATE TABLE control.publisher_namespace_allocations (
    public_url_id text PRIMARY KEY REFERENCES control.public_urls(id) ON DELETE RESTRICT,
    publisher_identity_id text NOT NULL REFERENCES control.publisher_identities(id) ON DELETE RESTRICT,
    publisher_grant_id text NOT NULL REFERENCES control.publisher_identity_grants(id) ON DELETE RESTRICT,
    invocation_id text NOT NULL CHECK (invocation_id <> ''),
    created_at timestamptz NOT NULL,
    UNIQUE (publisher_grant_id, invocation_id)
);

-- guest trial team IDs are trial-owned and have no control.teams row. keep the
-- same publisher identity/key/grant/token model while binding guest identities
-- to their existing trial and usage counters instead of team administration.
ALTER TABLE control.publisher_identities DROP CONSTRAINT publisher_identities_team_id_fkey;
CREATE TABLE control.guest_publisher_identities (
    publisher_identity_id text PRIMARY KEY REFERENCES control.publisher_identities(id) ON DELETE RESTRICT,
    guest_id text NOT NULL REFERENCES control.guest_trials(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL
);
CREATE INDEX guest_publisher_identities_trial
    ON control.guest_publisher_identities(guest_id, publisher_identity_id);

-- +goose Down
DROP TABLE control.guest_publisher_identities;
ALTER TABLE control.publisher_identities
    ADD CONSTRAINT publisher_identities_team_id_fkey FOREIGN KEY (team_id) REFERENCES control.teams(id) NOT VALID;
DROP TABLE control.publisher_namespace_allocations;
ALTER TABLE control.publisher_enrollment_keys
    DROP CONSTRAINT publisher_enrollment_keys_identity_kind_check,
    ADD CONSTRAINT publisher_enrollment_keys_identity_kind_check
        CHECK (identity_kind IN ('installed', 'automation'));
