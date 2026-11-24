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
)

type PublisherAliasWildcardRecords struct {
	Zone           Zone
	Settled        bool
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
		var ready bool
		var shadowed []string
		started := time.Now()
		shadowed, ready, attemptErr = w.advancePublisherAliasWildcard(ctx, work)
		observeDNS(ctx, w.config.Observer, "alias_wildcard", "advance", started, ready, attemptErr)
		if errors.Is(attemptErr, controlstate.ErrPublisherAliasWildcardStale) {
			return attemptErr
		}
		if ctx.Err() != nil {
			return errors.Join(attemptErr, context.Cause(ctx))
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
		err := w.store.SavePublisherAliasWildcard(ctx, work, shadowed, ready && !work.Removing, ready && work.Removing, failures, now, next)
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

func (w *Worker) advancePublisherAliasWildcard(ctx context.Context, work controlstate.PublisherAliasWildcardWork) ([]string, bool, error) {
	if work.Removing && work.ZoneID == "" {
		return nil, true, nil
	}
	if !work.Removing && (!work.PoolUsable || work.IPv4 == nil && work.IPv6 == nil) {
		return nil, false, nil
	}
	record := AddressRecord{CanonicalHostname: work.Parent, Owner: wildcardOwner(work), ZoneDomain: work.Domain, TeamID: work.TeamID, DomainID: work.DomainID, AuthorityReference: work.AuthorityReference}
	authority, err := w.store.GetDNSAuthority(ctx, work.AuthorityReference)
	if err != nil {
		return nil, false, err
	}
	if authority.DomainID != work.DomainID || authority.TeamID != work.TeamID || authority.CanonicalDomain != work.Domain ||
		authority.State != controlstate.DNSAuthorityReady && !(work.Removing && authority.State == controlstate.DNSAuthorityReleasing) {
		return nil, false, terminalf("publisher alias wildcard does not match current DNS authority")
	}
	record.ZoneID, record.CustomZone = canonicalZoneID(authority.ProviderZoneID), true
	record.Nameservers, record.DelegationSetID = authority.Nameservers, authority.DelegationSetID
	if record.ZoneID == "" || work.ZoneID != "" && record.ZoneID != work.ZoneID {
		return nil, false, terminalf("publisher alias wildcard does not match its pinned hosted zone")
	}
	if err := w.store.PinPublisherAliasWildcardZone(ctx, work, record.ZoneID, w.now()); err != nil {
		return nil, false, err
	}
	if work.IPv4 != nil {
		record.IngressIPv4Addresses = []string{work.IPv4.String()}
	}
	if work.IPv6 != nil {
		record.IngressIPv6Addresses = []string{work.IPv6.String()}
	}
	result, err := w.provider.ReconcilePublisherAliasWildcard(ctx, record, work.Removing)
	if err != nil || !result.Settled {
		return nil, false, err
	}
	if work.Removing {
		removed, err := w.verifier.VerifyPublisherAliasWildcardRemoval(ctx, record, result.Zone.Nameservers)
		return nil, removed, err
	}
	if ready, err := w.verifier.Verify(ctx, record.ZoneDomain, result.Zone.Nameservers); err != nil || !ready {
		return nil, false, err
	}
	if owned, err := w.verifier.VerifyPublisherAliasWildcardOwnership(ctx, record, result.Zone.Nameservers); err != nil || !owned {
		return nil, false, err
	}
	probe, err := naming.RandomHostname(naming.PublisherHostnameKind, work.Parent)
	if err != nil {
		return nil, false, err
	}
	for _, hostname := range []string{"*." + work.Parent, probe} {
		ready, err := w.verifier.VerifyAddress(ctx, hostname, record.IngressIPv4Addresses, record.IngressIPv6Addresses, result.Zone.Nameservers)
		if err != nil || !ready {
			return nil, false, err
		}
	}
	return result.ShadowedLabels, true, nil
}
