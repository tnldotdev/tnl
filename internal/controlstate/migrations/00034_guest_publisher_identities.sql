-- +goose Up
-- guest teams are trial-owned, not rows in control.teams. keep existing
-- publisher rows and use the trial link to validate guest identities.
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
