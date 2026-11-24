package dns

import (
	"context"
	"time"
)

// reconcile the service address record and verify its authoritative DNS answers.
func (w *Worker) reconcileAddress(ctx context.Context, record AddressRecord, nameservers []string, removing bool, kind string) (bool, error) {
	var zone Zone
	var err error
	var removal AddressRemoval
	started := time.Now()
	if removing {
		removal, err = w.provider.RemoveAddress(ctx, record)
		zone = removal.Zone
	} else {
		zone, err = w.provider.PublishAddress(ctx, record)
	}
	observeDNS(ctx, w.config.Observer, kind, "provider", started, true, err)
	if err != nil {
		return false, err
	}
	if len(zone.Nameservers) != 0 {
		nameservers = zone.Nameservers
	}
	started = time.Now()
	var verified bool
	if removing {
		// a wildcard can answer A and AAAA after the exact records disappear.
		// require both exact provider absence and authoritative withdrawal of
		// the marker that was changed in the same batch as the addresses.
		if removal.ExactRecordsAbsent {
			verified, err = w.verifier.VerifyAddressRemoval(ctx, record, nameservers)
		}
	} else {
		verified, err = w.verifier.VerifyAddress(ctx, record.CanonicalHostname, record.IngressIPv4Addresses, record.IngressIPv6Addresses, nameservers)
	}
	observeDNS(ctx, w.config.Observer, kind, "verify", started, verified, err)
	return verified, err
}
