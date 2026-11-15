package dns

import (
	"context"
	"time"
)

// reconcile the service address record and verify its authoritative DNS answers.
func (w *Worker) reconcileAddress(ctx context.Context, record AddressRecord, nameservers []string, removing bool, kind string) (bool, error) {
	var zone Zone
	var err error
	var ipv4, ipv6 []string
	started := time.Now()
	if removing {
		zone, err = w.provider.RemoveAddress(ctx, record)
	} else {
		zone, err = w.provider.PublishAddress(ctx, record)
		ipv4, ipv6 = record.IngressIPv4Addresses, record.IngressIPv6Addresses
	}
	observeDNS(ctx, w.config.Observer, kind, "provider", started, true, err)
	if err != nil {
		return false, err
	}
	if len(zone.Nameservers) != 0 {
		nameservers = zone.Nameservers
	}
	started = time.Now()
	verified, err := w.verifier.VerifyAddress(ctx, record.CanonicalHostname, ipv4, ipv6, nameservers)
	observeDNS(ctx, w.config.Observer, kind, "verify", started, verified, err)
	return verified, err
}
