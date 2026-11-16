package state

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// both connection readiness and heartbeat use this transition under the existing
// owner, service, and run locks. first readiness and the guest clock commit
// together; callers emit the first-ready metric only after that commit succeeds.
func advanceServiceRunReadiness(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, run controlstatedb.ControlServiceRun, clock authorizationClock) (controlstatedb.ControlServiceRun, error) {
	if run.State == string(serviceRunStarting) && run.Healthy &&
		run.CertificateExpiresAt.Valid && run.CertificateExpiresAt.Time.After(clock.current()) {
		ready, err := countReadyServiceConnections(ctx, tx, run.ID, clock.current())
		if err != nil {
			return run, err
		}
		canReady := ready == 2 || run.ReadyAt.Valid && ready >= 1
		if canReady && run.GuestID.Valid && !run.ReadyAt.Valid {
			// guests have no connector access. do not start their fixed serving
			// window before the current public endpoint can receive visitors.
			canReady, err = serviceRunFirstReadyGuestEndpointReady(ctx, tx, q, run, clock)
			if err != nil {
				return run, err
			}
		}
		if canReady {
			run, err = q.ReadyServiceRun(ctx, controlstatedb.ReadyServiceRunParams{
				ID: run.ID, ServiceID: run.ServiceID, RunNumber: run.RunNumber, Now: timestamptz(clock.current()),
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return run, ErrServiceAccess
			}
			if err != nil {
				return run, err
			}
		}
	}
	if run.State == string(serviceRunReady) {
		return markGuestServiceRunReady(ctx, q, run, clock.current())
	}
	return boundGuestServingAuthority(ctx, q, run, clock.current())
}
