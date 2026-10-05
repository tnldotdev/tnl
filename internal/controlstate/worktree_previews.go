package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var (
	ErrWorktreePreviewNotFound = errors.New("controlstate: worktree preview not found")
	ErrWorktreePreviewAccess   = errors.New("controlstate: worktree preview access denied")
	ErrWorktreePreviewStale    = errors.New("controlstate: worktree preview membership changed")
)

type WorktreePreview struct {
	ID                  string
	TeamID              string
	CreatedByIdentityID string
	PublicURLIDs        []string
	CreatedAt           time.Time
}

type AddWorktreePreviewPublicURLRequest struct {
	PreviewID                string
	PublicURLID              string
	TeamID                   string
	IdentityID               string
	AuthorityIssuer          string
	PolicyRevision           uint64
	ExpectedMutationRevision uint64
}

func (d *Database) CreateWorktreePreview(ctx context.Context, teamID, identityID, key string, now time.Time) (WorktreePreview, error) {
	if teamID == "" || identityID == "" || key == "" || len(key) > 128 {
		return WorktreePreview{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return WorktreePreview{}, err
	}
	id, err := opaqueid.New(opaqueid.WorktreePreviewPrefix)
	if err != nil {
		return WorktreePreview{}, fmt.Errorf("controlstate: create worktree preview ID: %w", err)
	}
	row, err := controlstatedb.New(d.pool).CreateWorktreePreview(ctx, controlstatedb.CreateWorktreePreviewParams{
		ID: id, TeamID: teamID, CreatedByIdentityID: identityID, IdempotencyKey: key, CreatedAt: timestamp(now),
	})
	if err != nil {
		return WorktreePreview{}, fmt.Errorf("controlstate: create worktree preview: %w", err)
	}
	return d.GetWorktreePreview(ctx, row.ID)
}

func (d *Database) GetWorktreePreview(ctx context.Context, id string) (WorktreePreview, error) {
	if !opaqueid.Valid(id, opaqueid.WorktreePreviewPrefix) {
		return WorktreePreview{}, ErrWorktreePreviewNotFound
	}
	if err := d.requireOpen(); err != nil {
		return WorktreePreview{}, err
	}
	queries := controlstatedb.New(d.pool)
	row, err := queries.GetWorktreePreview(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return WorktreePreview{}, ErrWorktreePreviewNotFound
	}
	if err != nil {
		return WorktreePreview{}, fmt.Errorf("controlstate: read worktree preview: %w", err)
	}
	ids, err := queries.ListWorktreePreviewPublicURLs(ctx, id)
	if err != nil {
		return WorktreePreview{}, fmt.Errorf("controlstate: list worktree preview public URLs: %w", err)
	}
	if ids == nil {
		ids = []string{}
	}
	return WorktreePreview{
		ID: row.ID, TeamID: row.TeamID, CreatedByIdentityID: row.CreatedByIdentityID,
		PublicURLIDs: ids, CreatedAt: row.CreatedAt.Time,
	}, nil
}

func (d *Database) AddWorktreePreviewPublicURL(ctx context.Context, request AddWorktreePreviewPublicURLRequest, now time.Time) (result WorktreePreview, retErr error) {
	if !opaqueid.Valid(request.PreviewID, opaqueid.WorktreePreviewPrefix) || request.PublicURLID == "" || request.IdentityID == "" || request.TeamID == "" || request.PolicyRevision == 0 || request.ExpectedMutationRevision == 0 || request.ExpectedMutationRevision > 1<<63-1 {
		return WorktreePreview{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return WorktreePreview{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return WorktreePreview{}, fmt.Errorf("controlstate: add worktree preview public URL: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "add worktree preview public URL", &retErr)()
	queries := controlstatedb.New(tx)
	group, err := queries.GetWorktreePreview(ctx, request.PreviewID)
	if errors.Is(err, pgx.ErrNoRows) {
		return WorktreePreview{}, ErrWorktreePreviewNotFound
	}
	if err != nil {
		return WorktreePreview{}, fmt.Errorf("controlstate: read worktree preview: %w", err)
	}
	if group.TeamID != request.TeamID || group.CreatedByIdentityID != request.IdentityID {
		return WorktreePreview{}, ErrWorktreePreviewAccess
	}
	policyRevision := positive(request.PolicyRevision)
	if request.AuthorityIssuer == "" {
		if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return WorktreePreview{}, ErrWorktreePreviewAccess
		} else if err != nil {
			return WorktreePreview{}, fmt.Errorf("controlstate: lock worktree preview team: %w", err)
		}
	} else if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
		Issuer: request.AuthorityIssuer, TeamID: request.TeamID,
		PolicyRevision: policyRevision, UpdatedAt: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return WorktreePreview{}, ErrPublicURLAuthority
	} else if err != nil {
		return WorktreePreview{}, fmt.Errorf("controlstate: observe worktree preview authority: %w", err)
	}
	route, err := queries.LockPublicURLForRun(ctx, request.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && route.TeamID != request.TeamID {
		return WorktreePreview{}, ErrPublicURLNotFound
	}
	if err != nil {
		return WorktreePreview{}, fmt.Errorf("controlstate: lock worktree preview public URL: %w", err)
	}
	if route.LifecycleState != string(PublicURLLifecycleEnabled) || route.MutationRevision != int64(request.ExpectedMutationRevision) {
		return WorktreePreview{}, ErrWorktreePreviewStale
	}
	if route.PolicyRevision > policyRevision {
		return WorktreePreview{}, ErrPublicURLAuthority
	}
	if request.AuthorityIssuer == "" {
		membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
			TeamID: request.TeamID, IdentityID: request.IdentityID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return WorktreePreview{}, ErrWorktreePreviewAccess
		}
		if err != nil {
			return WorktreePreview{}, fmt.Errorf("controlstate: read worktree preview membership: %w", err)
		}
		if membership.PolicyRevision != policyRevision ||
			route.PublicURLScope == string(PublicURLScopeMember) && (!route.MembershipID.Valid || route.MembershipID.String != membership.ID) ||
			route.PublicURLScope == string(PublicURLScopeShared) && membership.Role != "admin" && membership.Role != "owner" {
			return WorktreePreview{}, ErrWorktreePreviewAccess
		}
	}
	_, err = queries.AddWorktreePreviewPublicURL(ctx, controlstatedb.AddWorktreePreviewPublicURLParams{
		WorktreePreviewID: request.PreviewID, PublicURLID: request.PublicURLID, IdentityID: request.IdentityID,
		ExpectedMutationRevision: int64(request.ExpectedMutationRevision), AddedAt: pgtype.Timestamptz{Time: now.UTC(), Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return WorktreePreview{}, ErrWorktreePreviewStale
	}
	if err != nil {
		return WorktreePreview{}, fmt.Errorf("controlstate: add worktree preview public URL: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return WorktreePreview{}, fmt.Errorf("controlstate: commit worktree preview public URL: %w", err)
	}
	return d.GetWorktreePreview(ctx, request.PreviewID)
}
