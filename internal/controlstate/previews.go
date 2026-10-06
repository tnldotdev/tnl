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
	ErrPreviewNotFound = errors.New("controlstate: preview not found")
	ErrPreviewAccess   = errors.New("controlstate: preview access denied")
	ErrPreviewStale    = errors.New("controlstate: preview membership changed")
)

type Preview struct {
	SchemaVersion       int
	ID                  string
	TeamID              string
	CreatedByIdentityID string
	PublicURLIDs        []string
	TeamAccessEnabled   bool
	CreatedAt           time.Time
}

type AddPreviewPublicURLRequest struct {
	PreviewID                string
	PublicURLID              string
	TeamID                   string
	IdentityID               string
	AuthorityIssuer          string
	PolicyRevision           uint64
	ExpectedMutationRevision uint64
}

func (d *Database) CreatePreview(ctx context.Context, teamID, identityID, key string, now time.Time) (Preview, error) {
	if teamID == "" || identityID == "" || key == "" || len(key) > 128 {
		return Preview{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Preview{}, err
	}
	id, err := opaqueid.New(opaqueid.PreviewPrefix)
	if err != nil {
		return Preview{}, fmt.Errorf("controlstate: create preview ID: %w", err)
	}
	row, err := controlstatedb.New(d.pool).CreatePreview(ctx, controlstatedb.CreatePreviewParams{
		ID: id, TeamID: teamID, CreatedByIdentityID: identityID, IdempotencyKey: key, CreatedAt: timestamp(now),
	})
	if err != nil {
		return Preview{}, fmt.Errorf("controlstate: create preview: %w", err)
	}
	return d.GetPreview(ctx, row.ID)
}

func (d *Database) GetPreview(ctx context.Context, id string) (Preview, error) {
	if !opaqueid.Valid(id, opaqueid.PreviewPrefix) {
		return Preview{}, ErrPreviewNotFound
	}
	if err := d.requireOpen(); err != nil {
		return Preview{}, err
	}
	queries := controlstatedb.New(d.pool)
	row, err := queries.GetPreview(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, ErrPreviewNotFound
	}
	if err != nil {
		return Preview{}, fmt.Errorf("controlstate: read preview: %w", err)
	}
	ids, err := queries.ListPreviewPublicURLs(ctx, id)
	if err != nil {
		return Preview{}, fmt.Errorf("controlstate: list preview public URLs: %w", err)
	}
	if ids == nil {
		ids = []string{}
	}
	return Preview{
		SchemaVersion: int(row.SchemaVersion),
		ID:            row.ID, TeamID: row.TeamID, CreatedByIdentityID: row.CreatedByIdentityID,
		PublicURLIDs: ids, CreatedAt: row.CreatedAt.Time,
		TeamAccessEnabled: row.TeamAccessEnabled,
	}, nil
}

func (d *Database) AddPreviewPublicURL(ctx context.Context, request AddPreviewPublicURLRequest, now time.Time) (result Preview, retErr error) {
	if !opaqueid.Valid(request.PreviewID, opaqueid.PreviewPrefix) || request.PublicURLID == "" || request.IdentityID == "" || request.TeamID == "" || request.PolicyRevision == 0 || request.ExpectedMutationRevision == 0 || request.ExpectedMutationRevision > 1<<63-1 {
		return Preview{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Preview{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Preview{}, fmt.Errorf("controlstate: add preview public URL: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "add preview public URL", &retErr)()
	queries := controlstatedb.New(tx)
	group, err := queries.GetPreview(ctx, request.PreviewID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, ErrPreviewNotFound
	}
	if err != nil {
		return Preview{}, fmt.Errorf("controlstate: read preview: %w", err)
	}
	if group.TeamID != request.TeamID || group.CreatedByIdentityID != request.IdentityID {
		return Preview{}, ErrPreviewAccess
	}
	policyRevision := positive(request.PolicyRevision)
	if request.AuthorityIssuer == "" {
		if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return Preview{}, ErrPreviewAccess
		} else if err != nil {
			return Preview{}, fmt.Errorf("controlstate: lock preview team: %w", err)
		}
	} else if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
		Issuer: request.AuthorityIssuer, TeamID: request.TeamID,
		PolicyRevision: policyRevision, UpdatedAt: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, ErrPublicURLAuthority
	} else if err != nil {
		return Preview{}, fmt.Errorf("controlstate: observe preview authority: %w", err)
	}
	if _, err := queries.LockPreviewForTeamAccess(ctx, request.PreviewID); err != nil {
		return Preview{}, fmt.Errorf("controlstate: lock preview: %w", err)
	}
	route, err := queries.LockPublicURLForRun(ctx, request.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && route.TeamID != request.TeamID {
		return Preview{}, ErrPublicURLNotFound
	}
	if err != nil {
		return Preview{}, fmt.Errorf("controlstate: lock preview public URL: %w", err)
	}
	if route.LifecycleState != string(PublicURLLifecycleEnabled) || route.MutationRevision != int64(request.ExpectedMutationRevision) {
		return Preview{}, ErrPreviewStale
	}
	if route.PolicyRevision > policyRevision {
		return Preview{}, ErrPublicURLAuthority
	}
	if _, err := queries.OtherTeamAccessForPublicURL(ctx, controlstatedb.OtherTeamAccessForPublicURLParams{
		PublicURLID: request.PublicURLID, PreviewID: request.PreviewID,
	}); err == nil {
		return Preview{}, ErrPreviewStale
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, fmt.Errorf("controlstate: check team access: %w", err)
	}
	if request.AuthorityIssuer == "" {
		membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
			TeamID: request.TeamID, IdentityID: request.IdentityID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return Preview{}, ErrPreviewAccess
		}
		if err != nil {
			return Preview{}, fmt.Errorf("controlstate: read preview membership: %w", err)
		}
		if membership.PolicyRevision != policyRevision ||
			route.PublicURLScope == string(PublicURLScopeMember) && (!route.MembershipID.Valid || route.MembershipID.String != membership.ID) ||
			route.PublicURLScope == string(PublicURLScopeShared) && membership.Role != "admin" && membership.Role != "owner" {
			return Preview{}, ErrPreviewAccess
		}
	}
	_, err = queries.AddPreviewPublicURL(ctx, controlstatedb.AddPreviewPublicURLParams{
		PreviewID: request.PreviewID, PublicURLID: request.PublicURLID, IdentityID: request.IdentityID,
		ExpectedMutationRevision: int64(request.ExpectedMutationRevision), AddedAt: pgtype.Timestamptz{Time: now.UTC(), Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, ErrPreviewStale
	}
	if err != nil {
		return Preview{}, fmt.Errorf("controlstate: add preview public URL: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Preview{}, fmt.Errorf("controlstate: commit preview public URL: %w", err)
	}
	return d.GetPreview(ctx, request.PreviewID)
}
