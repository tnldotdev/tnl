package team

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type DomainClaimAPI interface {
	ClaimTeamDomain(context.Context, string, string, string, bool) (authorityv1.Domain, error)
	ListTeamDomains(context.Context, string) (authorityv1.DomainPage, error)
}

// DomainClaimWait leaves the wait budget and polling cadence to the caller.
type DomainClaimWait struct {
	Timeout time.Duration
	Poll    func(context.Context) error
}

func ClaimAndWaitForDomainRecords(ctx context.Context, api DomainClaimAPI, teamID, name, key string, makeDefault bool, wait DomainClaimWait) (authorityv1.Domain, bool, error) {
	claimed, err := api.ClaimTeamDomain(ctx, teamID, name, key, makeDefault)
	if err != nil || claimed.State != authorityv1.DomainStatePending || len(claimed.RequiredRecords) != 0 {
		return claimed, false, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, wait.Timeout)
	defer cancel()
	for {
		if err := wait.Poll(waitCtx); err != nil {
			if ctx.Err() != nil {
				return claimed, false, ctx.Err()
			}
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return claimed, true, nil
			}
			return claimed, false, err
		}
		if err := waitCtx.Err(); err != nil {
			if ctx.Err() != nil {
				return claimed, false, ctx.Err()
			}
			return claimed, true, nil
		}
		page, err := api.ListTeamDomains(waitCtx, teamID)
		if err != nil {
			if ctx.Err() != nil {
				return claimed, false, ctx.Err()
			}
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return claimed, true, nil
			}
			return claimed, false, err
		}
		if err := ctx.Err(); err != nil {
			return claimed, false, err
		}
		if domain, ok := FindDomain(page.Domains, claimed.Id); ok {
			claimed = domain
			if len(domain.RequiredRecords) != 0 || domain.State != authorityv1.DomainStatePending {
				return domain, false, nil
			}
		}
	}
}
