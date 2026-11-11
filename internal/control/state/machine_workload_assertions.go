package state

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func machineSessionProof(ctx context.Context, tx pgx.Tx, id string) (r MachineWorkloadProof, err error) {
	err = tx.QueryRow(ctx, `SELECT machine_id,group_id,permission_id FROM control.workload_session_machines WHERE session_id=$1`, id).Scan(&r.MachineID, &r.GroupID, &r.PermissionID)
	return r, publisherLookupError(err, ErrMachineDenied)
}

// lookup authenticates the exact live visitor session before returning the
// server-derived identity needed to verify a rotating machine assertion.
func (d *Database) MachineWorkloadAssertionPolicy(ctx context.Context, id, credential string, now time.Time) (r MachineWorkloadProof, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollback(ctx, tx, "read machine workload assertion policy", &retErr)()
	source, err := lockWorkloadCredential(ctx, tx, credential, newAuthorizationClock(now))
	if err != nil {
		return r, err
	}
	if source.ID != id {
		return r, ErrMachineDenied
	}
	return machineSessionProof(ctx, tx, id)
}

func (d *Database) AttachMachineWorkloadAssertion(ctx context.Context, id, credential string, proof MachineProof, signature []byte, audience string, now time.Time) (result WorkloadSession, retErr error) {
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "attach machine workload assertion", &retErr)()
	source, err := lockWorkloadCredential(ctx, tx, credential, clock)
	if err != nil {
		return result, err
	}
	if source.ID != id {
		return result, ErrMachineDenied
	}
	machine, err := machineSessionProof(ctx, tx, id)
	if err != nil {
		return result, err
	}
	machine.Proof = proof
	machine.Audience = audience
	row, err := controlstatedb.New(tx).GetWorkloadSession(ctx, id)
	if err != nil {
		return result, err
	}
	group, project, c, err := d.lockGroupWorkload(ctx, tx, machine.GroupID)
	if err != nil {
		return result, err
	}
	if project.TeamID != row.TeamID || project.ProjectKey != row.ProjectKey {
		return result, ErrMachineDenied
	}
	p, found := c.Workloads[row.WorkloadName]
	if !found {
		return result, ErrMachineDenied
	}
	execution, authority, err := d.verifyGroupMachine(ctx, tx, group, p, row.WorkloadName, machine, "attach", base64.RawURLEncoding.EncodeToString(source.PublicKey), id, nil, clock.current())
	if err != nil {
		return result, err
	}
	// the common attachment engine checks immutable identity, current policy,
	// ephemeral-key possession, proof expiry and the original hard deadline.
	result, err = d.attachWorkloadAssertion(ctx, tx, id, credential, execution, signature, clock)
	if err != nil {
		return result, err
	}
	if authority.Signed {
		if err = consumeMachineProof(ctx, tx, machine.MachineID, authority.Digest, authority.ProofUntil); err != nil {
			return WorkloadSession{}, err
		}
	}
	result.AssertionExpiresAt = new(time.Unix(execution.ExpiresAt, 0))
	return result, tx.Commit(ctx)
}
