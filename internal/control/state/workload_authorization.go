package state

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
)

// authorizationClock keeps the entry-time issuance budget separate from current
// authority checks. elapsed database waits spend that budget on the same clock.
type authorizationClock struct{ entered, started time.Time }

func newAuthorizationClock(now time.Time) authorizationClock {
	return authorizationClock{entered: now, started: time.Now()}
}

func (c authorizationClock) current() time.Time { return c.entered.Add(time.Since(c.started)) }

// workloadAuthority is checked once under the team and source row locks. callers
// check selected-service membership separately, without rereading source clocks.
type workloadAuthority struct {
	ID                                   string
	PublicKey                            []byte
	LeaseExpiresAt, ExpiresAt, CheckedAt time.Time
}

// authentication never creates a ControlPrincipal. the team lock serializes
// authorization with apply, including policy removal and service replacement.
func lockWorkloadCredential(ctx context.Context, tx pgx.Tx, credential string, clock authorizationClock) (source workloadAuthority, err error) {
	if len(credential) < 5 || len(credential) > 256 || credential[:4] != "wlc_" {
		return source, ErrWorkloadDenied
	}
	digest := sha256.Sum256([]byte(credential))
	var team string
	err = tx.QueryRow(ctx, `SELECT id,team_id FROM control.workload_sessions WHERE credential_digest=$1`, digest[:]).Scan(&source.ID, &team)
	if err != nil {
		return workloadAuthority{}, publisherLookupError(err, ErrWorkloadDenied)
	}
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, team); err != nil {
		return workloadAuthority{}, publisherLookupError(err, ErrWorkloadDenied)
	}
	var created, renewed time.Time
	var revoked bool
	var run, attempt, check string
	err = tx.QueryRow(ctx, `SELECT public_key,created_at,renewed_at,lease_expires_at,expires_at,revoked_at IS NOT NULL,
	    COALESCE(run_id,''),COALESCE(run_attempt,''),COALESCE(check_run_id,'')
	    FROM control.workload_sessions WHERE id=$1 AND credential_digest=$2 FOR UPDATE`, source.ID, digest[:]).
		Scan(&source.PublicKey, &created, &renewed, &source.LeaseExpiresAt, &source.ExpiresAt, &revoked, &run, &attempt, &check)
	if err != nil {
		return workloadAuthority{}, publisherLookupError(err, ErrWorkloadDenied)
	}
	source.CheckedAt = clock.current()
	if revoked || source.CheckedAt.Before(created) || source.CheckedAt.Before(renewed) ||
		!source.LeaseExpiresAt.After(source.CheckedAt) || !source.ExpiresAt.After(source.CheckedAt) {
		return workloadAuthority{}, ErrWorkloadDenied
	}
	observability.WorkloadExecution(ctx, source.ID, run, attempt, check)
	return source, nil
}
