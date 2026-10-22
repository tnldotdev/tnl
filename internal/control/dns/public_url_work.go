package dns

import (
	"context"
	"errors"
	"strings"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
)

func (w *Worker) processPublicURL(ctx context.Context, now time.Time) (_ bool, retErr error) {
	ctx, finish := observability.WorkerAttempt(ctx, "dns.public_url.attempt")
	var attemptErr error
	defer func() { finishDNSAttempt(ctx, finish, errors.Join(retErr, attemptErr)) }()
	started := time.Now()
	route, found, err := w.store.ClaimDNSPublicURLWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if ctx.Err() == nil {
		observeDNS(ctx, w.config.Observer, "public_url", "claim", started, found, err)
	}
	if err != nil || !found {
		return found, err
	}
	initial := route.State
	advanceStarted := time.Now()
	advanceErr := w.advancePublicURL(ctx, &route, now)
	attemptErr = advanceErr
	if advanceErr != nil {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		w.applyPublicURLFailure(&route, advanceErr, w.now())
	}
	started = time.Now()
	saved, err := w.store.SaveDNSPublicURLWork(ctx, route, w.now())
	if ctx.Err() == nil {
		observeDNS(ctx, w.config.Observer, "public_url", "save", started, true, err)
	}
	if err != nil {
		return true, err
	}
	if ctx.Err() == nil {
		observeDNS(ctx, w.config.Observer, "public_url", "advance", advanceStarted, !saved.AvailableAt.After(now), advanceErr)
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
	var complete controlstate.PublicURLDNSState
	switch work.State {
	case controlstate.PublicURLDNSPending:
		complete = controlstate.PublicURLDNSPublished
	case controlstate.PublicURLDNSRemoving:
		if record.WildcardHostname != "" {
			// the wildcard belongs to the namespace, not this public URL.
			work.State = controlstate.PublicURLDNSRemoved
			work.AvailableAt = time.Time{}
			return nil
		}
		complete = controlstate.PublicURLDNSRemoved
	default:
		return terminalf("cannot process public URL DNS in state %q", work.State)
	}
	verified, err := w.reconcileAddress(ctx, record, nameservers, work.State == controlstate.PublicURLDNSRemoving, "public_url")
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
) (AddressRecord, []string, bool, error) {
	ipv4, ipv6, ready, err := w.ingressAddresses(ctx, work.IngressPoolID)
	if err != nil {
		return AddressRecord{}, nil, false, err
	}
	if !ready {
		return AddressRecord{}, nil, false, nil
	}
	record := AddressRecord{
		Owner: PublicURLOwner(work.PublicURLID), DomainID: work.DomainID, CanonicalHostname: work.CanonicalHostname,
		Namespace: work.Namespace, IngressIPv4Addresses: ipv4, IngressIPv6Addresses: ipv6,
	}
	record.AuthorityReference = work.DNSAuthorityReference
	return w.addressZoneRecord(ctx, record)
}

func (w *Worker) ingressAddresses(ctx context.Context, id string) ([]string, []string, bool, error) {
	pool, err := w.store.GetIngressPool(ctx, id)
	if err != nil {
		return nil, nil, false, err
	}
	if pool.ID != id {
		return nil, nil, false, terminalf("endpoint ingress pool does not match its saved pool")
	}
	ipv4, ipv6 := append([]string(nil), w.config.IngressIPv4Addresses...), append([]string(nil), w.config.IngressIPv6Addresses...)
	if pool.State == controlstate.IngressPoolEnabled || pool.State == controlstate.IngressPoolDraining {
		ipv4, ipv6 = nil, nil
		if pool.IPv4Address.IsValid() {
			ipv4 = []string{pool.IPv4Address.String()}
		}
		if pool.IPv6Address.IsValid() {
			ipv6 = []string{pool.IPv6Address.String()}
		}
	} else if pool.State == controlstate.IngressPoolDisabled && id != controlstate.PrimaryIngressPoolID {
		return nil, nil, false, nil
	} else if pool.State != controlstate.IngressPoolDisabled {
		return nil, nil, false, terminalf("endpoint ingress pool is invalid")
	}
	return ipv4, ipv6, true, nil
}

func (w *Worker) addressZoneRecord(ctx context.Context, record AddressRecord) (AddressRecord, []string, bool, error) {
	if record.CanonicalHostname == w.config.ManagedDomain || strings.HasSuffix(record.CanonicalHostname, "."+w.config.ManagedDomain) {
		record.ZoneID, record.ZoneDomain = w.config.ManagedZoneID, w.config.ManagedDomain
		if record.ZoneID == "" {
			return AddressRecord{}, nil, false, terminalf("managed Route 53 zone is not configured")
		}
		if record.Owner.kind == "public-url" {
			record.WildcardHostname = naming.PublicURLWildcard(record.CanonicalHostname, record.Namespace)
		}
		return record, nil, true, nil
	}
	if record.AuthorityReference == "" {
		return AddressRecord{}, nil, false, terminalf("custom-domain public URL has no DNS authority reference")
	}
	authority, err := w.store.GetDNSAuthority(ctx, record.AuthorityReference)
	if err != nil {
		return AddressRecord{}, nil, false, err
	}
	if authority.DomainID != record.DomainID ||
		record.CanonicalHostname != authority.CanonicalDomain && !strings.HasSuffix(record.CanonicalHostname, "."+authority.CanonicalDomain) {
		return AddressRecord{}, nil, false, terminalf("public URL does not match its DNS authority")
	}
	if authority.State == controlstate.DNSAuthorityPending {
		return AddressRecord{}, nil, false, nil
	}
	if authority.State != controlstate.DNSAuthorityReady && authority.State != controlstate.DNSAuthorityReleasing || authority.ProviderZoneID == "" {
		return AddressRecord{}, nil, false, terminalf("DNS authority is not available")
	}
	record.ZoneID, record.ZoneDomain, record.CustomZone = authority.ProviderZoneID, authority.CanonicalDomain, true
	record.AuthorityReference, record.TeamID = authority.Reference, authority.TeamID
	if record.Owner.kind == "public-url" {
		record.WildcardHostname = naming.PublicURLWildcard(record.CanonicalHostname, record.Namespace)
	}
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
