package clientstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

// WorktreePreviewID returns the preview identity saved for this checkout and team.
func (s *Store) WorktreePreviewID(ctx context.Context, teamID, projectRoot string) (string, bool, error) {
	if teamID == "" || projectRoot == "" {
		return "", false, errors.New("clientstate: team and project root are required")
	}
	id, err := s.database.queries.GetWorktreePreviewID(ctx, clientstatedb.GetWorktreePreviewIDParams{
		ServerOrigin: s.controlEndpoint, TeamID: teamID, ProjectRoot: projectRoot,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("clientstate: read worktree preview ID: %w", err)
	}
	if !opaqueid.Valid(id, opaqueid.WorktreePreviewPrefix) {
		return "", false, errors.New("clientstate: saved worktree preview ID is invalid")
	}
	return id, true, nil
}

// SaveWorktreePreviewID records the preview identity returned by control.
func (s *Store) SaveWorktreePreviewID(ctx context.Context, teamID, projectRoot, id string) error {
	if teamID == "" || projectRoot == "" || !opaqueid.Valid(id, opaqueid.WorktreePreviewPrefix) {
		return errors.New("clientstate: invalid worktree preview identity")
	}
	if err := s.database.queries.SaveWorktreePreviewID(ctx, clientstatedb.SaveWorktreePreviewIDParams{
		ServerOrigin: s.controlEndpoint, TeamID: teamID, ProjectRoot: projectRoot,
		WorktreePreviewID: id, UpdatedAt: s.database.now().UTC().UnixNano(),
	}); err != nil {
		return fmt.Errorf("clientstate: save worktree preview ID: %w", err)
	}
	return nil
}
