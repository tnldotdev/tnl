package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
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
	ServiceIDs          []string
	TeamAccessEnabled   bool
	CreatedAt           time.Time
}

type AddPreviewServiceRequest struct {
	PreviewID, ServiceID, TeamID, IdentityID string
}

func (d *Database) CreatePreview(ctx context.Context, teamID, identityID, key string, now time.Time) (result Preview, retErr error) {
	if teamID == "" || identityID == "" || key == "" || len(key) > 128 {
		return result, ErrPreviewAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create preview", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, teamID); err != nil {
		return result, publisherLookupError(err, ErrPreviewAccess)
	}
	if _, err = serviceMembershipForActor(ctx, tx, teamID, identityID, now); err != nil {
		return result, err
	}
	id, err := opaqueid.New(opaqueid.PreviewPrefix)
	if err != nil {
		return result, err
	}
	row, err := q.CreatePreview(ctx, controlstatedb.CreatePreviewParams{
		ID: id, TeamID: teamID, CreatedByIdentityID: identityID, IdempotencyKey: key, CreatedAt: timestamp(now),
	})
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
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
	q := controlstatedb.New(d.pool)
	row, err := q.GetPreview(ctx, id)
	if err != nil {
		return Preview{}, publisherLookupError(err, ErrPreviewNotFound)
	}
	ids, err := q.ListPreviewServices(ctx, id)
	if err != nil {
		return Preview{}, err
	}
	if ids == nil {
		ids = []string{}
	}
	return Preview{SchemaVersion: int(row.SchemaVersion), ID: row.ID, TeamID: row.TeamID,
		CreatedByIdentityID: row.CreatedByIdentityID, ServiceIDs: ids,
		TeamAccessEnabled: row.TeamAccessEnabled, CreatedAt: row.CreatedAt.Time}, nil
}

func (d *Database) AddPreviewService(ctx context.Context, request AddPreviewServiceRequest, now time.Time) (result Preview, retErr error) {
	if !opaqueid.Valid(request.PreviewID, opaqueid.PreviewPrefix) ||
		!opaqueid.Valid(request.ServiceID, opaqueid.ServicePrefix) || request.IdentityID == "" || request.TeamID == "" {
		return result, ErrPreviewAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "add preview service", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, request.TeamID); err != nil {
		return result, publisherLookupError(err, ErrPreviewAccess)
	}
	member, err := serviceMembershipForActor(ctx, tx, request.TeamID, request.IdentityID, now)
	if err != nil {
		return result, err
	}
	group, err := q.LockPreviewForTeamAccess(ctx, request.PreviewID)
	if err != nil {
		return result, publisherLookupError(err, ErrPreviewNotFound)
	}
	if group.TeamID != request.TeamID || group.CreatedByIdentityID != request.IdentityID || group.DemoServiceRunID.Valid {
		return result, ErrPreviewAccess
	}
	service, err := q.LockService(ctx, request.ServiceID)
	if err != nil {
		return result, publisherLookupError(err, ErrPreviewStale)
	}
	if !service.Enabled || service.Protocol != "http" {
		return result, ErrPreviewStale
	}
	if err = requireServiceManagement(ctx, tx, service, member); err != nil {
		return result, err
	}
	if _, err = q.OtherTeamAccessForService(ctx, controlstatedb.OtherTeamAccessForServiceParams{
		ServiceID: request.ServiceID, PreviewID: request.PreviewID,
	}); err == nil {
		return result, ErrPreviewStale
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if _, err = q.AddPreviewService(ctx, controlstatedb.AddPreviewServiceParams{
		PreviewID: group.ID, ServiceID: service.ID, IdentityID: request.IdentityID, AddedAt: timestamptz(now),
	}); err != nil {
		return result, publisherLookupError(err, ErrPreviewStale)
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return d.GetPreview(ctx, group.ID)
}
