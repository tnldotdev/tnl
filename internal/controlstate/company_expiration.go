package controlstate

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// expireCompanyEligibility makes freshness loss an audited policy change, even
// if no publisher or visitor asks control about the expired subject again.
func (d *Database) expireCompanyEligibility(ctx context.Context, now time.Time) error {
	rows, err := d.pool.Query(ctx, `SELECT DISTINCT team_id FROM control.company_eligibility WHERE eligible AND valid_until<=$1 AND expiration_notified_at IS NULL ORDER BY team_id LIMIT 100`, now)
	if err != nil {
		return err
	}
	var teams []string
	for rows.Next() {
		var team string
		if err = rows.Scan(&team); err != nil {
			rows.Close()
			return err
		}
		teams = append(teams, team)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, team := range teams {
		if err = d.expireCompanyTeam(ctx, team, now); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) expireCompanyTeam(ctx context.Context, team string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "expire company eligibility", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE control.company_eligibility SET expiration_notified_at=$2 WHERE team_id=$1 AND eligible AND valid_until<=$2 AND expiration_notified_at IS NULL`, team, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		if err = companyPolicyChanged(ctx, tx, q, team, "", "", "", "eligibility.expired", companyAccessAuditDetails{State: "eligibility_expired"}, now); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
