package dns

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/workerloop"
)

type PublisherAliasWildcardRecords struct {
	Zone           Zone
	Settled        bool
	Invalid        bool
	ShadowedLabels []string
}

func wildcardOwnerName(parent string) string { return "_tnl-wildcard." + parent }

func wildcardOwner(work controlstate.PublisherAliasWildcardWork) AddressOwner {
	// pool addresses may change, but a change in team, domain or pool never
	// inherits ownership of the previous binding.
	digest := sha256.Sum256([]byte(work.TeamID + "\x00" + work.DomainID + "\x00" + work.PoolID))
	return AddressOwner{kind: "alias-wildcard", id: fmt.Sprintf("%x", digest)}
}

func (w *Worker) processPublisherAliasWildcard(ctx context.Context, now time.Time) (_ bool, retErr error) {
	ctx, finish := observability.WorkerAttempt(ctx, "dns.alias_wildcard.attempt")
	var attemptErr error
	defer func() { finishDNSAttempt(ctx, finish, errors.Join(retErr, attemptErr)) }()
	started := time.Now()
	work, found, err := w.store.ClaimPublisherAliasWildcard(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	observeDNS(ctx, w.config.Observer, "alias_wildcard", "claim", started, found, err)
	if err != nil || !found {
		return found, err
	}
	err = w.store.WithDNSRecordLock(ctx, "*."+work.Parent, func() error {
		var observation controlstate.PublisherAliasWildcardObservation
		var shadowed []string
		started := time.Now()
		shadowed, observation, attemptErr = w.advancePublisherAliasWildcard(ctx, work)
		ready := observation == controlstate.PublisherAliasWildcardVerified || observation == controlstate.PublisherAliasWildcardRemoved
		observeDNS(ctx, w.config.Observer, "alias_wildcard", "advance", started, ready, attemptErr)
		if errors.Is(attemptErr, controlstate.ErrPublisherAliasWildcardStale) {
			return attemptErr
		}
		saveCtx := ctx
		if ctx.Err() != nil {
			attemptErr = errors.Join(attemptErr, context.Cause(ctx))
			if workerloop.LifetimeEnded(ctx) && observation != controlstate.PublisherAliasWildcardWithdrawn && len(shadowed) == 0 {
				return attemptErr
			}
			if ready {
				observation = controlstate.PublisherAliasWildcardInconclusive
			}
			// even if the last DNS query timed out, save any negative
			// evidence already observed under the original, fenced work lease.
			var cancel context.CancelFunc
			saveCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
		}
		now := w.now()
		var failures int64
		next := now.Add(w.config.PollInterval)
		switch {
		case attemptErr != nil:
			failures = min(work.ConsecutiveErrors+1, 63)
			next = w.retryAvailableAt(uint64(failures), now)
		case ready && !work.Removing:
			next = now.Add(controlstate.PublisherAliasWildcardLifetime / 3)
		}
		started = time.Now()
		err := w.store.SavePublisherAliasWildcard(saveCtx, work, shadowed, observation, failures, now, next)
		observeDNS(ctx, w.config.Observer, "alias_wildcard", "save", started, err == nil, err)
		return err
	})
	if errors.Is(err, controlstate.ErrPublisherAliasWildcardStale) {
		attemptErr = nil
		return true, nil
	}
	if attemptErr != nil && ctx.Err() == nil {
		w.config.Logger.WarnContext(ctx, "reconcile publisher alias wildcard", "parent", work.Parent, "error", attemptErr)
	}
	return true, err
}

func (w *Worker) advancePublisherAliasWildcard(ctx context.Context, work controlstate.PublisherAliasWildcardWork) ([]string, controlstate.PublisherAliasWildcardObservation, error) {
	inconclusive, withdrawn := controlstate.PublisherAliasWildcardInconclusive, controlstate.PublisherAliasWildcardWithdrawn
	if work.Removing && work.ZoneID == "" {
		return nil, controlstate.PublisherAliasWildcardRemoved, nil
	}
	if !work.Removing && (!work.PoolUsable || work.IPv4 == nil && work.IPv6 == nil) {
		return nil, withdrawn, nil
	}
	record := AddressRecord{CanonicalHostname: work.Parent, Owner: wildcardOwner(work), ZoneDomain: work.Domain, TeamID: work.TeamID, DomainID: work.DomainID, AuthorityReference: work.AuthorityReference}
	authority, err := w.store.GetDNSAuthority(ctx, work.AuthorityReference)
	if err != nil {
		if errors.Is(err, controlstate.ErrDNSAuthorityNotFound) || errors.Is(err, controlstate.ErrDNSAuthorityInvalid) {
			return nil, withdrawn, err
		}
		return nil, inconclusive, err
	}
	if authority.DomainID != work.DomainID || authority.TeamID != work.TeamID || authority.CanonicalDomain != work.Domain ||
		authority.State != controlstate.DNSAuthorityReady && !(work.Removing && authority.State == controlstate.DNSAuthorityReleasing) {
		return nil, withdrawn, terminalf("publisher alias wildcard does not match current DNS authority")
	}
	record.ZoneID, record.CustomZone = canonicalZoneID(authority.ProviderZoneID), true
	record.Nameservers, record.DelegationSetID = authority.Nameservers, authority.DelegationSetID
	if record.ZoneID == "" || work.ZoneID != "" && record.ZoneID != work.ZoneID {
		return nil, withdrawn, terminalf("publisher alias wildcard does not match its pinned hosted zone")
	}
	if err := w.store.PinPublisherAliasWildcardZone(ctx, work, record.ZoneID, w.now()); err != nil {
		return nil, inconclusive, err
	}
	if work.IPv4 != nil {
		record.IngressIPv4Addresses = []string{work.IPv4.String()}
	}
	if work.IPv6 != nil {
		record.IngressIPv6Addresses = []string{work.IPv6.String()}
	}
	result, err := w.provider.ReconcilePublisherAliasWildcard(ctx, record, work.Removing)
	var terminal *terminalError
	if result.Invalid || errors.As(err, &terminal) || isRoute53Error(err, "NoSuchHostedZone") {
		return result.ShadowedLabels, withdrawn, err
	}
	if err != nil || !result.Settled {
		return result.ShadowedLabels, inconclusive, err
	}
	if work.Removing {
		removed, err := w.verifier.VerifyPublisherAliasWildcardRemoval(ctx, record, result.Zone.Nameservers)
		if err == nil && removed {
			return nil, controlstate.PublisherAliasWildcardRemoved, nil
		}
		return nil, withdrawn, err
	}
	checks := []func() (bool, error){
		func() (bool, error) {
			return w.verifier.VerifyPublisherAliasWildcardDelegation(ctx, record.ZoneDomain, result.Zone.Nameservers)
		},
		func() (bool, error) {
			return w.verifier.VerifyPublisherAliasWildcardOwnership(ctx, record, result.Zone.Nameservers)
		},
		func() (bool, error) {
			return w.verifier.VerifyPublisherAliasWildcardAddress(ctx, "*."+work.Parent, record.IngressIPv4Addresses, record.IngressIPv6Addresses, result.Zone.Nameservers)
		},
		func() (bool, error) {
			probe, err := naming.RandomHostname(naming.PublisherHostnameKind, work.Parent)
			if err != nil {
				return false, err
			}
			return w.verifier.VerifyPublisherAliasWildcardAddress(ctx, probe, record.IngressIPv4Addresses, record.IngressIPv6Addresses, result.Zone.Nameservers)
		},
	}
	for _, check := range checks {
		if ctx.Err() != nil {
			return result.ShadowedLabels, inconclusive, errors.Join(err, context.Cause(ctx))
		}
		ok, checkErr := check()
		if checkErr == nil && !ok {
			return result.ShadowedLabels, withdrawn, err
		}
		err = errors.Join(err, checkErr)
	}
	if err != nil {
		return result.ShadowedLabels, inconclusive, err
	}
	return result.ShadowedLabels, controlstate.PublisherAliasWildcardVerified, nil
}
