package dns

import (
	"context"
	"errors"
	"slices"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
)

func (w *Worker) processAuthority(ctx context.Context, now time.Time) (_ bool, retErr error) {
	ctx, finish := observability.WorkerAttempt(ctx, "dns.authority.attempt")
	var attemptErr error
	defer func() { finishDNSAttempt(ctx, finish, errors.Join(retErr, attemptErr)) }()
	started := time.Now()
	work, found, err := w.store.ClaimDNSAuthorityWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if ctx.Err() == nil {
		observeDNS(ctx, w.config.Observer, "authority", "claim", started, found, err)
	}
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	initial := work.State
	advanceStarted := time.Now()
	advanceErr := w.advanceAuthority(ctx, &work, now)
	attemptErr = advanceErr
	if advanceErr != nil {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		w.applyAuthorityFailure(&work, advanceErr, w.now())
	}
	started = time.Now()
	saved, err := w.store.SaveDNSAuthorityWork(ctx, work, w.now())
	if errors.Is(err, controlstate.ErrDNSAuthorityWorkStale) {
		return true, nil
	}
	if ctx.Err() == nil {
		observeDNS(ctx, w.config.Observer, "authority", "save", started, true, err)
	}
	if err != nil {
		return true, err
	}
	if ctx.Err() == nil {
		observeDNS(ctx, w.config.Observer, "authority", "advance", advanceStarted, !saved.AvailableAt.After(now), advanceErr)
	}
	if w.config.Observer != nil && initial != saved.State {
		w.config.Observer.ObserveDNSTransition("authority", string(saved.State))
	}
	return true, nil
}

func (w *Worker) advanceAuthority(ctx context.Context, work *controlstate.DNSAuthorityWork, now time.Time) error {
	work.LastError = ""
	switch work.State {
	case controlstate.DNSAuthorityPending, controlstate.DNSAuthorityFailed:
		if !work.ClaimExpiresAt.IsZero() && !now.Before(work.ClaimExpiresAt) {
			work.State, work.AvailableAt = controlstate.DNSAuthorityReleasing, now
			return nil
		}
		if work.DelegationSetID != "" {
			proceed, err := w.prepareBrandedClaim(ctx, work, now)
			if err != nil || !proceed {
				return err
			}
		}
		if work.ProviderZoneID == "" {
			started := time.Now()
			zone, err := w.provider.EnsureCustomZone(ctx, *work)
			observeDNS(ctx, w.config.Observer, "authority", "provider", started, true, err)
			if err != nil {
				return err
			}
			if zone.ID == "" || len(zone.Nameservers) < 2 {
				return terminalf("provider returned incomplete custom-zone state")
			}
			if work.DelegationSetID != "" {
				if !slices.Equal(zone.Nameservers, work.Nameservers) {
					return terminalf("provisioned nameservers do not match the claim")
				}
				ready, err := w.config.BrandedVerifier.VerifyBrandedZone(ctx, work.CanonicalDomain, work.Nameservers)
				if err != nil || !ready {
					work.AvailableAt = now.Add(w.config.PollInterval)
					return err
				}
			}
			// save the zone before verifying delegation on the next claim.
			work.ProviderZoneID = zone.ID
			work.Nameservers = append([]string(nil), zone.Nameservers...)
			work.AvailableAt = now.Add(w.config.PollInterval)
			return nil
		}
		started := time.Now()
		if work.DelegationSetID != "" {
			delegated, err := w.config.BrandedVerifier.VerifyParentDelegation(ctx, work.CanonicalDomain, work.Nameservers)
			if err != nil || !delegated {
				work.AvailableAt = now.Add(w.config.PollInterval)
				return err
			}
			if err := w.verifyBrandedMapping(ctx, work); err != nil {
				return err
			}
		}
		verified, err := w.verifier.Verify(ctx, work.CanonicalDomain, work.Nameservers)
		observeDNS(ctx, w.config.Observer, "authority", "verify", started, verified, err)
		if err != nil {
			return err
		}
		if verified {
			work.State = controlstate.DNSAuthorityReady
			work.AvailableAt = now
		} else {
			work.AvailableAt = now.Add(w.config.PollInterval)
		}
		return nil
	case controlstate.DNSAuthorityReleasing:
		ready, err := w.store.DNSAuthorityReleaseReady(ctx, work.DomainID, now)
		if err != nil {
			return err
		}
		if !ready {
			work.AvailableAt = now.Add(w.config.PollInterval)
			return nil
		}
		if work.DelegationSetID != "" && !work.ClaimProofVerifiedAt.IsZero() {
			if w.config.BrandedProvider == nil || w.config.BrandedVerifier == nil {
				return errors.New("branded DNS verification is not configured")
			}
			backend, err := w.config.BrandedProvider.DelegationNameservers(ctx, work.DelegationSetID)
			if err != nil {
				return err
			}
			old := append(slices.Clone(work.Nameservers), backend...)
			removed, err := w.config.BrandedVerifier.VerifyDelegationRemoved(ctx, work.CanonicalDomain, old)
			if err != nil || !removed {
				work.AvailableAt = now.Add(w.config.PollInterval)
				return err
			}
		}
		started := time.Now()
		err = w.provider.ReleaseCustomZone(ctx, *work)
		observeDNS(ctx, w.config.Observer, "authority", "provider", started, true, err)
		if err != nil {
			return err
		}
		work.State = controlstate.DNSAuthorityReleased
		work.AvailableAt = now
		return nil
	default:
		return terminalf("cannot process DNS authority in state %q", work.State)
	}
}

func (w *Worker) prepareBrandedClaim(ctx context.Context, work *controlstate.DNSAuthorityWork, now time.Time) (bool, error) {
	if w.config.BrandedProvider == nil || w.config.BrandedVerifier == nil {
		return false, errors.New("branded DNS verification is not configured")
	}
	branded, err := naming.BrandedNameservers(work.NameserverDomain)
	if err != nil {
		return false, err
	}
	if len(work.Nameservers) == 0 {
		work.Nameservers = branded
		if err := w.verifyBrandedMapping(ctx, work); err != nil {
			work.Nameservers = nil
			return false, err
		}
		work.AvailableAt = now
		return false, nil
	}
	if !slices.Equal(work.Nameservers, branded) {
		return false, terminalf("saved branded nameservers do not match the claim")
	}
	if !work.ClaimProofVerifiedAt.IsZero() {
		if work.ProviderZoneID == "" {
			return true, w.verifyBrandedMapping(ctx, work)
		}
		return true, nil
	}
	verified, err := w.config.BrandedVerifier.VerifyClaimProof(ctx, work.CanonicalDomain, work.ClaimProofName, work.ClaimProofValue, branded)
	if err != nil {
		return false, err
	}
	work.AvailableAt = now.Add(w.config.PollInterval)
	if verified {
		work.ClaimProofVerifiedAt, work.AvailableAt = w.now(), now
	}
	return false, nil
}

func (w *Worker) verifyBrandedMapping(ctx context.Context, work *controlstate.DNSAuthorityWork) error {
	backend, err := w.config.BrandedProvider.DelegationNameservers(ctx, work.DelegationSetID)
	if err != nil {
		return err
	}
	err = w.config.BrandedVerifier.VerifyNameserverMapping(ctx, work.Nameservers, backend)
	var setup *nameserverSetupError
	if errors.As(err, &setup) {
		w.config.Logger.WarnContext(ctx, "check branded nameserver", "hostname", setup.host, "problem", setup.check)
	}
	return err
}

func (w *Worker) applyAuthorityFailure(work *controlstate.DNSAuthorityWork, operationErr error, now time.Time) {
	work.LastError = storedFailureReason(operationErr)
	work.AvailableAt = w.retryAvailableAt(work.Attempts, now)
	var terminal *terminalError
	if errors.As(operationErr, &terminal) {
		work.State = controlstate.DNSAuthorityFailed
		work.AvailableAt = now
	}
}
