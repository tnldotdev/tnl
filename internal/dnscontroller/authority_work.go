package dnscontroller

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func (w *Worker) processAuthority(ctx context.Context, now time.Time) (bool, error) {
	started := time.Now()
	work, found, err := w.store.ClaimDNSAuthorityWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if ctx.Err() == nil {
		observeDNS(w.config.Observer, "authority", "claim", started, found, err)
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
	if advanceErr != nil {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		w.applyAuthorityFailure(&work, advanceErr, w.now())
	}
	started = time.Now()
	saved, err := w.store.SaveDNSAuthorityWork(ctx, work, w.now())
	if ctx.Err() == nil {
		observeDNS(w.config.Observer, "authority", "save", started, true, err)
	}
	if err != nil {
		return true, err
	}
	if ctx.Err() == nil {
		observeDNS(w.config.Observer, "authority", "advance", advanceStarted, !saved.AvailableAt.After(now), advanceErr)
	}
	if w.config.Observer != nil && initial != saved.State {
		w.config.Observer.ObserveDNSTransition("authority", string(saved.State))
	}
	return true, nil
}

func (w *Worker) advanceAuthority(ctx context.Context, work *controlstate.DNSAuthorityWork, now time.Time) error {
	work.LastError = ""
	switch work.State {
	case controlstate.DNSAuthorityPending:
		if work.ProviderZoneID == "" {
			started := time.Now()
			zone, err := w.provider.EnsureCustomZone(ctx, *work)
			observeDNS(w.config.Observer, "authority", "provider", started, true, err)
			if err != nil {
				return err
			}
			if zone.ID == "" || len(zone.Nameservers) < 2 {
				return terminalf("provider returned incomplete custom-zone state")
			}
			// save the zone before verifying delegation on the next claim.
			work.ProviderZoneID = zone.ID
			work.Nameservers = append([]string(nil), zone.Nameservers...)
			work.AvailableAt = now.Add(w.config.PollInterval)
			return nil
		}
		started := time.Now()
		verified, err := w.verifier.Verify(ctx, work.CanonicalDomain, work.Nameservers)
		observeDNS(w.config.Observer, "authority", "verify", started, verified, err)
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
		started := time.Now()
		err = w.provider.ReleaseCustomZone(ctx, *work)
		observeDNS(w.config.Observer, "authority", "provider", started, true, err)
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

func (w *Worker) applyAuthorityFailure(work *controlstate.DNSAuthorityWork, operationErr error, now time.Time) {
	work.LastError = storedFailureReason(operationErr)
	work.AvailableAt = w.retryAvailableAt(work.Attempts, now)
	var terminal *terminalError
	if errors.As(operationErr, &terminal) {
		work.State = controlstate.DNSAuthorityFailed
		work.AvailableAt = now
	}
}
