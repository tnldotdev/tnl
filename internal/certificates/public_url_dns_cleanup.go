package certificates

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func certificateCleanupAvailableAt(work *controlstate.ACMEOrderWork, now time.Time) time.Time {
	if hasPendingDNSCleanup(work.Authorizations) {
		return now
	}
	return *work.RenewAt
}

func hasPendingDNSCleanup(authorizations []controlstate.ACMEAuthorizationWork) bool {
	return slices.ContainsFunc(authorizations, func(authorization controlstate.ACMEAuthorizationWork) bool {
		return authorization.ChallengeType == certificateidentity.ChallengeDNS01 &&
			(authorization.State == controlstate.ACMEAuthorizationValid || authorization.State == controlstate.ACMEAuthorizationCleaning)
	})
}

// continueDNSCleanup saves cleaning intent before calling the DNS provider.
// one reconciliation finishes all authorizations sharing a TXT name.
func (w *PublicURLWorker) continueDNSCleanup(
	ctx context.Context,
	work *controlstate.ACMEOrderWork,
	now time.Time,
) (bool, error) {
	changed := false
	for index := range work.Authorizations {
		authorization := &work.Authorizations[index]
		if authorization.ChallengeType != certificateidentity.ChallengeDNS01 || authorization.State == controlstate.ACMEAuthorizationComplete || authorization.State == controlstate.ACMEAuthorizationCanceled {
			continue
		}
		if authorization.State == controlstate.ACMEAuthorizationValid && authorization.PresentedAt == nil {
			authorization.State = controlstate.ACMEAuthorizationComplete
			authorization.CleanupCompletedAt = timePointer(now)
			authorization.AvailableAt = now
			changed = true
			continue
		}
		if authorization.State == controlstate.ACMEAuthorizationValid {
			authorization.State = controlstate.ACMEAuthorizationCleaning
			authorization.AvailableAt = now
			changed = true
			continue
		}
		if authorization.State != controlstate.ACMEAuthorizationCleaning {
			return false, terminalf("cannot clean DNS authorization for %q in state %q", authorization.Identifier, authorization.State)
		}
	}
	if changed {
		work.AvailableAt = now
		return true, nil
	}
	for index := range work.Authorizations {
		authorization := &work.Authorizations[index]
		if authorization.ChallengeType != certificateidentity.ChallengeDNS01 || authorization.State != controlstate.ACMEAuthorizationCleaning {
			continue
		}
		if err := w.config.DNSChallenges.Cleanup(ctx, work.PublicURLID, authorization.ID); err != nil {
			return false, err
		}
		// all authorizations for this identifier share one TXT name. reconcile
		// their combined owned values in one write.
		base := strings.TrimPrefix(authorization.Identifier, "*.")
		for otherIndex := range work.Authorizations {
			other := &work.Authorizations[otherIndex]
			if other.ChallengeType != certificateidentity.ChallengeDNS01 || other.State != controlstate.ACMEAuthorizationCleaning ||
				strings.TrimPrefix(other.Identifier, "*.") != base {
				continue
			}
			other.State = controlstate.ACMEAuthorizationComplete
			other.CleanupCompletedAt = timePointer(now)
			other.AvailableAt = now
		}
		work.AvailableAt = now
		return true, nil
	}
	return false, nil
}
