-- +goose Up
-- a member wildcard can name only one ingress address set. an existing
-- public URL keeps its pool, so never switch the team while one is saved.
-- +goose StatementBegin
CREATE FUNCTION control.reject_team_ingress_pool_move() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.ingress_pool_id <> OLD.ingress_pool_id AND EXISTS (
        SELECT 1 FROM control.public_urls
        WHERE team_id = OLD.id AND lifecycle_state <> 'deleted'
    ) THEN
        RAISE EXCEPTION 'cannot change ingress pool while a team has saved public urls'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER teams_ingress_pool_pinned
    BEFORE UPDATE OF ingress_pool_id ON control.teams
    FOR EACH ROW EXECUTE FUNCTION control.reject_team_ingress_pool_move();

-- +goose Down
DROP TRIGGER teams_ingress_pool_pinned ON control.teams;
DROP FUNCTION control.reject_team_ingress_pool_move();
