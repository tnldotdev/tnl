package dnscontroller

import (
	"context"
	"time"
)

// provider changes and authoritative verification share one implementation for
// public URLs and managed services. their ownership markers remain distinct.
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
	hostname := record.CanonicalHostname
	if record.WildcardHostname != "" {
		hostname = record.WildcardHostname
	}
	started = time.Now()
	verified, err := w.verifier.VerifyPublicURL(ctx, hostname, ipv4, ipv6, nameservers)
	observeDNS(ctx, w.config.Observer, kind, "verify", started, verified, err)
	return verified, err
}
