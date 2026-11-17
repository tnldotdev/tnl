package state

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func (d *Database) CreateServiceRunPreview(ctx context.Context, auth ServiceHTTPRun, now time.Time) (result Preview, retErr error) {
	if !auth.valid() {
		return result, ErrFeedbackAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create demo preview", &retErr)()
	if err = lockServiceAdmission(ctx, tx, auth.Subject.ID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := d.serviceRunAuthorization(ctx, tx, q, auth.Subject.ID, auth.RunID, auth.Token.String(), now)
	if err != nil {
		return result, err
	}
	if run.RunNumber != auth.Number || run.State != "starting" && run.State != "ready" {
		return result, ErrFeedbackAccess
	}
	id, err := opaqueid.New(opaqueid.PreviewPrefix)
	if err != nil {
		return result, err
	}
	row, err := q.CreateServiceRunPreview(ctx, controlstatedb.CreateServiceRunPreviewParams{
		ID: id, ServiceID: auth.Subject.ID, ServiceRunID: auth.RunID, RunNumber: auth.Number, Now: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrFeedbackAccess)
	}
	if err = q.AddServiceRunPreviewService(ctx, controlstatedb.AddServiceRunPreviewServiceParams{PreviewID: row.ID, Now: timestamptz(now)}); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return d.GetPreview(ctx, row.ID)
}
