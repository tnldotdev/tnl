package controlstate

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

var ErrHostedPolicyRevocationInvalid = errors.New("controlstate: hosted policy revocation is invalid")

// ApplyHostedPolicyRevocation advances one hosted team revision and closes
// older route sessions affected by that revision. Equal and older deliveries
// are successful no-ops.
func (d *Database) ApplyHostedPolicyRevocation(
	ctx context.Context,
	issuer, teamID string,
	policyRevision uint64,
	allSessions bool,
	membershipIDs []string,
	domainIDs []string,
	now time.Time,
) (applied bool, closed int, retErr error) {
	if !validStateText(issuer) || !validStateText(teamID) || policyRevision == 0 || policyRevision > math.MaxInt64 ||
		len(membershipIDs) > 1000 || len(domainIDs) > 1000 {
		return false, 0, ErrHostedPolicyRevocationInvalid
	}
	memberships := make(map[string]struct{}, len(membershipIDs))
	for _, membershipID := range membershipIDs {
		if !validStateText(membershipID) {
			return false, 0, ErrHostedPolicyRevocationInvalid
		}
		if _, duplicate := memberships[membershipID]; duplicate {
			return false, 0, ErrHostedPolicyRevocationInvalid
		}
		memberships[membershipID] = struct{}{}
	}
	domains := make(map[string]struct{}, len(domainIDs))
	for _, domainID := range domainIDs {
		if !validStateText(domainID) {
			return false, 0, ErrHostedPolicyRevocationInvalid
		}
		if _, duplicate := domains[domainID]; duplicate {
			return false, 0, ErrHostedPolicyRevocationInvalid
		}
		domains[domainID] = struct{}{}
	}
	if err := d.requireOpen(); err != nil {
		return false, 0, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, 0, fmt.Errorf("controlstate: apply hosted policy revocation: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "apply hosted policy revocation", &retErr)()
	queries := controlstatedb.New(tx)

	// Route mutations lock a route before observing the authority revision. Lock
	// the team's routes in the same order so an older in-flight mutation either
	// completes before this revocation or observes the newer revision afterward.
	routes, err := queries.LockHostedTeamRoutes(ctx, teamID)
	if err != nil {
		return false, 0, fmt.Errorf("controlstate: apply hosted policy revocation: lock routes: %w", err)
	}
	if _, err := queries.AdvanceAuthorityRevision(ctx, controlstatedb.AdvanceAuthorityRevisionParams{
		Issuer: issuer, TeamID: teamID, PolicyRevision: int64(policyRevision), UpdatedAt: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return false, 0, fmt.Errorf("controlstate: apply hosted policy revocation: commit replay: %w", err)
		}
		return false, 0, nil
	} else if err != nil {
		return false, 0, fmt.Errorf("controlstate: apply hosted policy revocation: advance revision: %w", err)
	}

	for _, route := range routes {
		_, domainAffected := domains[route.DomainID]
		session, err := queries.GetOpenRouteSession(ctx, route.ID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, 0, fmt.Errorf("controlstate: apply hosted policy revocation: read route session: %w", err)
		}
		if err == nil && session.PolicyRevision < int64(policyRevision) {
			_, membershipAffected := memberships[session.MembershipID.String]
			if allSessions || domainAffected || session.MembershipID.Valid && membershipAffected {
				if err := closeRouteSession(ctx, queries, route, session, RouteSessionClosed, now, "hosted_policy_revoked"); err != nil {
					return false, 0, err
				}
				closed++
			}
		}
		if domainAffected {
			updated, err := queries.SuspendAuthorityRoute(ctx, controlstatedb.SuspendAuthorityRouteParams{
				SuspensionReason: text("domain_releasing"), SuspendedAt: timestamptz(now), RouteID: route.ID,
			})
			if err != nil || updated != 1 {
				return false, 0, authorityRowsError("apply hosted policy revocation: suspend route", updated, err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, 0, fmt.Errorf("controlstate: apply hosted policy revocation: commit: %w", err)
	}
	return true, closed, nil
}
