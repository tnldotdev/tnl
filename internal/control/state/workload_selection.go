package state

import (
	"context"
	"time"
)

// selection authenticates only the workload credential, never a human session.
// the selected run still needs a signed, source-bound native peer pair.
func (d *Database) SelectWorkloadServiceRun(ctx context.Context, credential, service string, now time.Time) (ServiceSelection, error) {
	auth, err := d.CheckWorkloadService(ctx, credential, service, now)
	if err != nil {
		return ServiceSelection{}, err
	}
	return d.SelectVisitorServiceRun(ctx, service, auth.Subject, now)
}
