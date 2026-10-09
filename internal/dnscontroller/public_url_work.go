package dnscontroller

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/naming"
)

func (w *Worker) processPublicURL(ctx context.Context, now time.Time) (bool, error) {
	started := time.Now()
	route, found, err := w.store.ClaimDNSPublicURLWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if ctx.Err() == nil {
		observeDNS(w.config.Observer, "public_url", "claim", started, found, err)
	}
	if err != nil || !found {
		return found, err
	}
	initial := route.State
	advanceStarted := time.Now()
	advanceErr := w.advancePublicURL(ctx, &route, now)
	if advanceErr != nil {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		w.applyPublicURLFailure(&route, advanceErr, w.now())
	}
	started = time.Now()
	saved, err := w.store.SaveDNSPublicURLWork(ctx, route, w.now())
	if ctx.Err() == nil {
		observeDNS(w.config.Observer, "public_url", "save", started, true, err)
	}
	if err != nil {
		return true, err
	}
	if ctx.Err() == nil {
		observeDNS(w.config.Observer, "public_url", "advance", advanceStarted, !saved.AvailableAt.After(now), advanceErr)
	}
	if w.config.Observer != nil && initial != saved.State {
		w.config.Observer.ObserveDNSTransition("public_url", string(saved.State))
	}
	return true, nil
}

func (w *Worker) advancePublicURL(ctx context.Context, work *controlstate.DNSPublicURLWork, now time.Time) error {
	work.LastError = ""
	record, nameservers, ready, err := w.publicURLRecord(ctx, *work)
	if err != nil {
		return err
	}
	if !ready {
		work.AvailableAt = now.Add(w.config.PollInterval)
		return nil
	}
	var zone Zone
	var ipv4, ipv6 []string
	var complete controlstate.PublicURLDNSState
	started := time.Now()
	switch work.State {
	case controlstate.PublicURLDNSPending:
		zone, err = w.provider.PublishPublicURL(ctx, record)
		ipv4, ipv6 = record.IngressIPv4Addresses, record.IngressIPv6Addresses
		complete = controlstate.PublicURLDNSPublished
	case controlstate.PublicURLDNSRemoving:
		if record.WildcardHostname != "" {
			// the wildcard belongs to the namespace, not this public URL.
			work.State = controlstate.PublicURLDNSRemoved
			work.AvailableAt = time.Time{}
			return nil
		}
		zone, err = w.provider.RemovePublicURL(ctx, record)
		complete = controlstate.PublicURLDNSRemoved
	default:
		return terminalf("cannot process public URL DNS in state %q", work.State)
	}
	// provider calls are idempotent; repeat them until DNS verification completes.
	observeDNS(w.config.Observer, "public_url", "provider", started, true, err)
	if err != nil {
		return err
	}
	if len(zone.Nameservers) != 0 {
		nameservers = zone.Nameservers
	}
	started = time.Now()
	dnsHostname := record.CanonicalHostname
	if record.WildcardHostname != "" {
		dnsHostname = record.WildcardHostname
	}
	verified, err := w.verifier.VerifyPublicURL(ctx, dnsHostname, ipv4, ipv6, nameservers)
	observeDNS(w.config.Observer, "public_url", "verify", started, verified, err)
	if err != nil {
		return err
	}
	if verified {
		work.State = complete
		work.AvailableAt = time.Time{}
	} else {
		work.AvailableAt = now.Add(w.config.PollInterval)
	}
	return nil
}

func (w *Worker) publicURLRecord(
	ctx context.Context,
	work controlstate.DNSPublicURLWork,
) (PublicURLRecord, []string, bool, error) {
	record := PublicURLRecord{
		PublicURLID: work.PublicURLID, DomainID: work.DomainID, CanonicalHostname: work.CanonicalHostname,
		Namespace:            work.Namespace,
		IngressIPv4Addresses: append([]string(nil), w.config.IngressIPv4Addresses...),
		IngressIPv6Addresses: append([]string(nil), w.config.IngressIPv6Addresses...),
	}
	if work.CanonicalHostname == w.config.ManagedDomain || strings.HasSuffix(work.CanonicalHostname, "."+w.config.ManagedDomain) {
		record.ZoneID, record.ZoneDomain = w.config.ManagedZoneID, w.config.ManagedDomain
		if record.ZoneID == "" {
			return PublicURLRecord{}, nil, false, terminalf("managed Route 53 zone is not configured")
		}
		record.WildcardHostname = naming.PublicURLWildcard(work.CanonicalHostname, work.Namespace)
		return record, nil, true, nil
	}
	if work.DNSAuthorityReference == "" {
		return PublicURLRecord{}, nil, false, terminalf("custom-domain public URL has no DNS authority reference")
	}
	authority, err := w.store.GetDNSAuthority(ctx, work.DNSAuthorityReference)
	if err != nil {
		return PublicURLRecord{}, nil, false, err
	}
	if authority.DomainID != work.DomainID ||
		work.CanonicalHostname != authority.CanonicalDomain && !strings.HasSuffix(work.CanonicalHostname, "."+authority.CanonicalDomain) {
		return PublicURLRecord{}, nil, false, terminalf("public URL does not match its DNS authority")
	}
	if authority.State == controlstate.DNSAuthorityPending {
		return PublicURLRecord{}, nil, false, nil
	}
	if authority.State != controlstate.DNSAuthorityReady && authority.State != controlstate.DNSAuthorityReleasing || authority.ProviderZoneID == "" {
		return PublicURLRecord{}, nil, false, terminalf("DNS authority is not available")
	}
	record.ZoneID, record.ZoneDomain, record.CustomZone = authority.ProviderZoneID, authority.CanonicalDomain, true
	record.AuthorityReference, record.TeamID = authority.Reference, authority.TeamID
	record.WildcardHostname = naming.PublicURLWildcard(work.CanonicalHostname, work.Namespace)
	return record, authority.Nameservers, true, nil
}

func (w *Worker) applyPublicURLFailure(work *controlstate.DNSPublicURLWork, operationErr error, now time.Time) {
	work.LastError = storedFailureReason(operationErr)
	work.AvailableAt = w.retryAvailableAt(work.Attempts, now)
	var terminal *terminalError
	if errors.As(operationErr, &terminal) {
		work.State = controlstate.PublicURLDNSFailed
		work.AvailableAt = time.Time{}
	}
}
