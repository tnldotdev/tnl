package dns

import (
	"context"
	"errors"
	"strings"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
)

type serviceEndpointStore interface {
	ClaimServiceEndpointDNSWork(context.Context, string, time.Time, time.Duration) (controlstate.ServiceEndpointDNSWork, bool, error)
	SaveServiceEndpointDNSWork(context.Context, controlstate.ServiceEndpointDNSWork, time.Time) (controlstate.ServiceEndpointDNSWork, error)
	ValidateServiceEndpointDNSWork(context.Context, controlstate.ServiceEndpointDNSWork, time.Time) error
	WithDNSRecordLock(context.Context, string, func() error) error
}

func (w *Worker) processServiceEndpoint(ctx context.Context, now time.Time) (_ bool, retErr error) {
	store := w.store
	ctx, finish := observability.WorkerAttempt(ctx, "dns.service.attempt")
	var attemptErr error
	defer func() { finishDNSAttempt(ctx, finish, errors.Join(retErr, attemptErr)) }()
	started := time.Now()
	work, found, err := store.ClaimServiceEndpointDNSWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if ctx.Err() == nil {
		observeDNS(ctx, w.config.Observer, "service", "claim", started, found, err)
	}
	if err != nil || !found {
		return found, err
	}
	err = store.WithDNSRecordLock(ctx, work.Hostname, func() error {
		if err := store.ValidateServiceEndpointDNSWork(ctx, work, w.now()); err != nil {
			return err
		}
		var saveErr error
		attemptErr, saveErr = w.advanceServiceEndpoint(ctx, store, work)
		return saveErr
	})
	if errors.Is(err, controlstate.ErrServiceEndpointDNSWorkStale) {
		return true, nil
	}
	return true, err
}

func (w *Worker) advanceServiceEndpoint(ctx context.Context, store serviceEndpointStore, work controlstate.ServiceEndpointDNSWork) (attemptErr, saveErr error) {
	started, initial := time.Now(), work.State
	work.LastError = ""
	record := AddressRecord{Owner: ServiceOwner(work.OwnerID), DomainID: work.DomainID, CanonicalHostname: work.Hostname, AuthorityReference: work.AuthorityReference}
	ready := true
	var err error
	if !work.Public && work.State != controlstate.ServiceEndpointDNSRemoving {
		err = terminalf("connector-only service endpoint cannot publish DNS")
	}
	if err == nil && work.Public && work.State != controlstate.ServiceEndpointDNSRemoving {
		record.IngressIPv4Addresses, record.IngressIPv6Addresses, ready, err = w.ingressAddresses(ctx, work.PoolID)
		ready = ready && len(record.IngressIPv4Addresses)+len(record.IngressIPv6Addresses) > 0
	}
	var nameservers []string
	if err == nil && ready {
		record, nameservers, ready, err = w.addressZoneRecord(ctx, record)
	}
	if err == nil && ready {
		removing := work.State == controlstate.ServiceEndpointDNSRemoving
		ready, err = w.reconcileAddress(ctx, record, nameservers, removing, "service")
		if err == nil && ready {
			work.State = controlstate.ServiceEndpointDNSPublished
			if removing {
				work.State = controlstate.ServiceEndpointDNSRemoved
			}
			work.AvailableAt = time.Time{}
		}
	}
	if ctx.Err() != nil {
		return err, context.Cause(ctx)
	}
	observeDNS(ctx, w.config.Observer, "service", "advance", started, ready, err)
	if err != nil {
		work.LastError = storedFailureReason(err)
		work.AvailableAt = w.retryAvailableAt(uint64(work.Attempts), w.now())
		var terminal *terminalError
		if errors.As(err, &terminal) {
			work.State, work.AvailableAt = controlstate.ServiceEndpointDNSFailed, time.Time{}
		}
	} else if !ready {
		work.AvailableAt = w.now().Add(w.config.PollInterval)
	}
	started = time.Now()
	attemptErr = err
	saved, err := store.SaveServiceEndpointDNSWork(ctx, work, w.now())
	if ctx.Err() == nil {
		observeDNS(ctx, w.config.Observer, "service", "save", started, true, err)
	}
	if err == nil && w.config.Observer != nil && saved.State != initial {
		w.config.Observer.ObserveDNSTransition("service", string(saved.State))
	}
	return attemptErr, err
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
		return record, nil, true, nil
	}
	if record.AuthorityReference == "" {
		return AddressRecord{}, nil, false, terminalf("custom-domain service endpoint has no DNS authority reference")
	}
	authority, err := w.store.GetDNSAuthority(ctx, record.AuthorityReference)
	if err != nil {
		return AddressRecord{}, nil, false, err
	}
	if authority.Reference != record.AuthorityReference || authority.DomainID != record.DomainID ||
		record.CanonicalHostname != authority.CanonicalDomain && !strings.HasSuffix(record.CanonicalHostname, "."+authority.CanonicalDomain) {
		return AddressRecord{}, nil, false, terminalf("service endpoint does not match its DNS authority")
	}
	if authority.State == controlstate.DNSAuthorityPending {
		return AddressRecord{}, nil, false, nil
	}
	if authority.State != controlstate.DNSAuthorityReady && authority.State != controlstate.DNSAuthorityReleasing || authority.ProviderZoneID == "" {
		return AddressRecord{}, nil, false, terminalf("DNS authority is not available")
	}
	record.ZoneID, record.ZoneDomain, record.CustomZone = authority.ProviderZoneID, authority.CanonicalDomain, true
	record.AuthorityReference, record.TeamID = authority.Reference, authority.TeamID
	if authority.DelegationSetID != "" {
		record.Nameservers = authority.Nameservers
		record.DelegationSetID = authority.DelegationSetID
	}
	return record, authority.Nameservers, true, nil
}
