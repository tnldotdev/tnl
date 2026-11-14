package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type SetPreviewTeamAccessRequest struct {
	PreviewID, TeamID, IdentityID string
	Enabled                       bool
}

func (d *Database) SetPreviewTeamAccess(ctx context.Context, request SetPreviewTeamAccessRequest, now time.Time) (result Preview, retErr error) {
	if !opaqueid.Valid(request.PreviewID, opaqueid.PreviewPrefix) || request.TeamID == "" || request.IdentityID == "" {
		return result, ErrPreviewAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "set preview team access", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, request.TeamID); err != nil {
		return result, publisherLookupError(err, ErrPreviewAccess)
	}
	member, err := serviceMembershipForActor(ctx, tx, request.TeamID, request.IdentityID, now)
	if err != nil {
		return result, err
	}
	preview, err := q.LockPreviewForTeamAccess(ctx, request.PreviewID)
	if err != nil {
		return result, publisherLookupError(err, ErrPreviewNotFound)
	}
	if preview.TeamID != request.TeamID || preview.CreatedByIdentityID != request.IdentityID || preview.DemoServiceRunID.Valid {
		return result, ErrPreviewAccess
	}
	ids, err := q.ListPreviewServices(ctx, preview.ID)
	if err != nil {
		return result, err
	}
	if request.Enabled && (len(ids) == 0 || len(ids) > 32) {
		return result, ErrPreviewAccess
	}
	// SQL supplies sorted IDs, so every multi-service mutation takes service
	// locks in the same order and consumes its actor assertion only once.
	for _, id := range ids {
		service, err := q.LockService(ctx, id)
		if err != nil {
			return result, publisherLookupError(err, ErrPreviewStale)
		}
		if service.Protocol != "http" || !service.Enabled {
			return result, ErrPreviewStale
		}
		if err = requireServiceManagement(ctx, tx, service, member); err != nil {
			return result, err
		}
		if request.Enabled {
			if _, err = q.OtherPreviewForTeamAccess(ctx, controlstatedb.OtherPreviewForTeamAccessParams{ServiceID: id, PreviewID: preview.ID}); err == nil {
				return result, ErrPreviewStale
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return result, err
			}
		}
	}
	if err = q.SetPreviewTeamAccess(ctx, controlstatedb.SetPreviewTeamAccessParams{PreviewID: preview.ID, Enabled: request.Enabled}); err != nil {
		return result, err
	}
	if preview.TeamAccessEnabled != request.Enabled {
		operation := "grant.revoke"
		if request.Enabled {
			operation = "grant.create"
		}
		for _, id := range ids {
			if err = auditPrivateMutation(ctx, tx, id, request.IdentityID, operation, preview.ID+"/"+now.UTC().Format(time.RFC3339Nano), now); err != nil {
				return result, err
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return d.GetPreview(ctx, preview.ID)
}
