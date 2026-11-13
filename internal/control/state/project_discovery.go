package state

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrDiscoveryCursor = errors.New("invalid discovery cursor")

// discovery cursors bind the full query, not just the last returned key.
// authorization is checked again on every page, before applying the limit.
type discoveryCursor struct {
	Kind  string `json:"kind"`
	Team  string `json:"team"`
	Actor string `json:"actor"`
	After string `json:"after"`
}

func decodeDiscoveryCursor(token, kind, team, actor string) (string, error) {
	if token == "" {
		return "", nil
	}
	if len(token) > 2048 {
		return "", ErrDiscoveryCursor
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	var c discoveryCursor
	if err != nil || json.Unmarshal(data, &c) != nil || c.Kind != kind || c.Team != team || c.Actor != actor || c.After == "" || encodeDiscoveryCursor(c) != token {
		return "", ErrDiscoveryCursor
	}
	if kind == "projects/v1" && !naming.ValidProjectKey(c.After) || kind == "previews/v1" && !opaqueid.Valid(c.After, opaqueid.PreviewPrefix) {
		return "", ErrDiscoveryCursor
	}
	return c.After, nil
}

func encodeDiscoveryCursor(c discoveryCursor) string {
	data, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(data)
}

type ProjectSummary struct {
	TeamID       string    `json:"team_id"`
	ProjectKey   string    `json:"project_key"`
	ProjectLabel string    `json:"project_label"`
	Revision     int64     `json:"revision,string"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ProjectPage struct {
	Projects   []ProjectSummary `json:"projects"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

func (d *Database) ListProjects(ctx context.Context, team, actor, cursor string) (result ProjectPage, retErr error) {
	after, err := decodeDiscoveryCursor(cursor, "projects/v1", team, actor)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "list projects", &retErr)()
	if err = serviceManager(ctx, tx, team, actor); err != nil {
		return result, err
	}
	rows, err := controlstatedb.New(tx).ListDiscoverableProjects(ctx, controlstatedb.ListDiscoverableProjectsParams{TeamID: team, AfterKey: after})
	if err != nil {
		return result, err
	}
	result.Projects = make([]ProjectSummary, 0, min(len(rows), 100))
	for i, row := range rows {
		if i == 100 {
			result.NextCursor = encodeDiscoveryCursor(discoveryCursor{Kind: "projects/v1", Team: team, Actor: actor, After: rows[i-1].ProjectKey})
			break
		}
		result.Projects = append(result.Projects, ProjectSummary{TeamID: team, ProjectKey: row.ProjectKey, ProjectLabel: row.ProjectLabel, Revision: row.Revision, UpdatedAt: row.UpdatedAt.Time})
	}
	return result, tx.Commit(ctx)
}

type PreviewSummary struct {
	ID        string    `json:"id"`
	TeamID    string    `json:"team_id"`
	CreatedAt time.Time `json:"created_at"`
}

type PreviewPage struct {
	Previews   []PreviewSummary `json:"previews"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

func (d *Database) ListPreviews(ctx context.Context, team, actor, cursor string) (result PreviewPage, retErr error) {
	after, err := decodeDiscoveryCursor(cursor, "previews/v1", team, actor)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "list previews", &retErr)()
	q := controlstatedb.New(tx)
	if err = requireTeamSession(ctx, q, team, actor, time.Now()); err != nil {
		return result, errors.Join(ErrPreviewAccess, err)
	}
	rows, err := q.ListDiscoverablePreviews(ctx, controlstatedb.ListDiscoverablePreviewsParams{TeamID: team, CreatedByIdentityID: actor, AfterID: after})
	if err != nil {
		return result, err
	}
	result.Previews = make([]PreviewSummary, 0, min(len(rows), 100))
	for i, row := range rows {
		if i == 100 {
			result.NextCursor = encodeDiscoveryCursor(discoveryCursor{Kind: "previews/v1", Team: team, Actor: actor, After: rows[i-1].ID})
			break
		}
		result.Previews = append(result.Previews, PreviewSummary{ID: row.ID, TeamID: team, CreatedAt: row.CreatedAt.Time})
	}
	return result, tx.Commit(ctx)
}
