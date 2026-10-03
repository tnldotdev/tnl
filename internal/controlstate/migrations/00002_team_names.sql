-- +goose Up
-- previously created teams can use their already-reserved DNS labels as names.
UPDATE control.teams SET display_name = managed_label;
CREATE UNIQUE INDEX teams_name_unique ON control.teams (display_name);
ALTER TABLE control.teams ADD CONSTRAINT teams_name_label CHECK (
    char_length(display_name) BETWEEN 1 AND 63
    AND display_name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
);

-- an older serving process may still create a personal or organization team
-- with an arbitrary display name. its generated label remains a valid name.
-- +goose StatementBegin
CREATE FUNCTION control.normalize_team_name() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF char_length(NEW.display_name) NOT BETWEEN 1 AND 63
        OR NEW.display_name !~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$' THEN
        NEW.display_name := NEW.managed_label;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER normalize_team_name BEFORE INSERT ON control.teams
FOR EACH ROW EXECUTE FUNCTION control.normalize_team_name();

-- +goose Down
DROP TRIGGER normalize_team_name ON control.teams;
DROP FUNCTION control.normalize_team_name();
ALTER TABLE control.teams DROP CONSTRAINT teams_name_label;
DROP INDEX control.teams_name_unique;
