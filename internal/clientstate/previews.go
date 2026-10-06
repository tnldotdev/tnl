package clientstate

import (
	"context"
	"database/sql"
	"errors"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

// PreviewID returns the preview identity saved for this checkout and team.
func (s *Store) PreviewID(ctx context.Context, teamID, projectRoot string) (string, bool, error) {
	if teamID == "" || projectRoot == "" {
		return "", false, failure.Wrap("validate preview identity", failure.InvalidCommand, errors.New("clientstate: team and project root are required"))
	}
	id, err := s.database.queries.GetPreviewID(ctx, clientstatedb.GetPreviewIDParams{
		ServerOrigin: s.controlEndpoint, TeamID: teamID, ProjectRoot: projectRoot,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, failure.Wrap("read preview ID", failure.ClientStateUnavailable, err)
	}
	if !opaqueid.Valid(id, opaqueid.PreviewPrefix) {
		return "", false, failure.Wrap("read preview ID", failure.ClientStateUnavailable, errors.New("clientstate: saved preview ID is invalid"))
	}
	return id, true, nil
}

// SavePreviewID records the preview identity returned by control.
func (s *Store) SavePreviewID(ctx context.Context, teamID, projectRoot, id string) error {
	if teamID == "" || projectRoot == "" || !opaqueid.Valid(id, opaqueid.PreviewPrefix) {
		return failure.Wrap("validate preview identity", failure.InvalidCommand, errors.New("clientstate: invalid preview identity"))
	}
	if err := s.database.queries.SavePreviewID(ctx, clientstatedb.SavePreviewIDParams{
		ServerOrigin: s.controlEndpoint, TeamID: teamID, ProjectRoot: projectRoot,
		PreviewID: id, UpdatedAt: s.database.now().UTC().UnixNano(),
	}); err != nil {
		return failure.Wrap("save preview ID", failure.ClientStateUnavailable, err)
	}
	return nil
}
