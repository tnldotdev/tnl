package controlstate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type SetPreviewTeamAccessRequest struct {
	PreviewID      string
	TeamID         string
	IdentityID     string
	Enabled        bool
	PolicyRevision uint64
	PublicURLs     []AuthorizedSharePublicURL
}

func (d *Database) SetPreviewTeamAccess(ctx context.Context, request SetPreviewTeamAccessRequest, now time.Time) (result Preview, retErr error) {
	if !opaqueid.Valid(request.PreviewID, opaqueid.PreviewPrefix) || request.TeamID == "" || request.IdentityID == "" ||
		request.Enabled && (request.PolicyRevision == 0 || len(request.PublicURLs) == 0 || len(request.PublicURLs) > 32) {
		return Preview{}, ErrPreviewAccess
	}
	if err := d.requireOpen(); err != nil {
		return Preview{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Preview{}, fmt.Errorf("controlstate: set preview team access: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "set preview team access", &retErr)()
	queries := controlstatedb.New(tx)
	var membership controlstatedb.GetActivePublishRunMembershipRow
	{
		if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return Preview{}, ErrPreviewAccess
		} else if err != nil {
			return Preview{}, fmt.Errorf("controlstate: lock team: %w", err)
		}
		membership, err = queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
			TeamID: request.TeamID, IdentityID: request.IdentityID,
		})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && request.Enabled && membership.PolicyRevision != positive(request.PolicyRevision) {
			return Preview{}, ErrPreviewAccess
		}
		if err != nil {
			return Preview{}, fmt.Errorf("controlstate: read membership: %w", err)
		}
	}
	preview, err := queries.LockPreviewForTeamAccess(ctx, request.PreviewID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, ErrPreviewNotFound
	}
	if err != nil {
		return Preview{}, fmt.Errorf("controlstate: lock preview: %w", err)
	}
	if preview.TeamID != request.TeamID || preview.CreatedByIdentityID != request.IdentityID {
		return Preview{}, ErrPreviewAccess
	}
	if request.Enabled {
		ids, err := queries.ListPreviewPublicURLs(ctx, preview.ID)
		if err != nil {
			return Preview{}, fmt.Errorf("controlstate: list preview public URLs: %w", err)
		}
		urls := slices.Clone(request.PublicURLs)
		slices.SortFunc(urls, func(left, right AuthorizedSharePublicURL) int {
			if left.PublicURLID < right.PublicURLID {
				return -1
			}
			if left.PublicURLID > right.PublicURLID {
				return 1
			}
			return 0
		})
		if len(ids) != len(urls) {
			return Preview{}, ErrPreviewStale
		}
		for index, selected := range urls {
			if selected.PublicURLID != ids[index] || selected.ExpectedMutationRevision == 0 || selected.ExpectedMutationRevision > 1<<63-1 {
				return Preview{}, ErrPreviewStale
			}
			route, err := queries.LockPublicURLForRun(ctx, selected.PublicURLID)
			if errors.Is(err, pgx.ErrNoRows) {
				return Preview{}, ErrPreviewStale
			}
			if err != nil {
				return Preview{}, fmt.Errorf("controlstate: lock team public URL: %w", err)
			}
			if route.TeamID != request.TeamID || route.LifecycleState != string(PublicURLLifecycleEnabled) ||
				route.MutationRevision != int64(selected.ExpectedMutationRevision) || route.PolicyRevision > positive(request.PolicyRevision) {
				return Preview{}, ErrPreviewStale
			}
			if route.PublicURLScope == string(PublicURLScopeMember) &&
				(!route.MembershipID.Valid || route.MembershipID.String != membership.ID) ||
				route.PublicURLScope == string(PublicURLScopeShared) && membership.Role != string(TeamRoleAdmin) && membership.Role != string(TeamRoleOwner) {
				return Preview{}, ErrPreviewAccess
			}
			if _, err := queries.OtherPreviewForTeamAccess(ctx, controlstatedb.OtherPreviewForTeamAccessParams{
				PublicURLID: selected.PublicURLID, PreviewID: request.PreviewID,
			}); err == nil {
				return Preview{}, ErrPreviewStale
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return Preview{}, fmt.Errorf("controlstate: check other preview: %w", err)
			}
		}
	}
	if err := queries.SetPreviewTeamAccess(ctx, controlstatedb.SetPreviewTeamAccessParams{
		PreviewID: preview.ID, Enabled: request.Enabled,
	}); err != nil {
		return Preview{}, fmt.Errorf("controlstate: save preview team access: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Preview{}, fmt.Errorf("controlstate: commit preview team access: %w", err)
	}
	return d.GetPreview(ctx, request.PreviewID)
}
