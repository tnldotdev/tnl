-- +goose Up
CREATE INDEX visitor_access_grants_by_team
    ON control.visitor_access_grants (team_id, id)
    WHERE kind = 'team_url';

-- +goose Down
DROP INDEX control.visitor_access_grants_by_team;
