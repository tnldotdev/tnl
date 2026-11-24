package dns

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// VerifyAddressRemoval checks the authoritative half of an exact removal.
// callers must first check that the provider no longer lists the exact sets.
func (v *AuthoritativeVerifier) VerifyAddressRemoval(ctx context.Context, record AddressRecord, nameservers []string) (bool, error) {
	nameservers = normalizeDNSNames(nameservers)
	marker, err := strconv.Unquote(record.Owner.marker())
	if err != nil || len(nameservers) < 2 {
		return false, errors.New("dnscontroller: address removal proof is incomplete")
	}
	name := addressOwnerName(record.CanonicalHostname)
	ready := true
	for _, nameserver := range nameservers {
		addresses, err := v.resolver.LookupIPAddr(ctx, nameserver)
		if err != nil {
			return false, fmt.Errorf("dnscontroller: resolve removal nameserver %q: %w", nameserver, err)
		}
		removed, err := verifyNameserver(ctx, addresses, func(ctx context.Context, server string) (bool, error) {
			response, err := v.exchange(ctx, server, name, dns.TypeTXT)
			if err != nil {
				return false, err
			}
			return verifyRemovedAddressMarker(response, name, record.ZoneDomain, marker)
		})
		if err != nil {
			return false, fmt.Errorf("dnscontroller: query removal nameserver %q: %w", nameserver, err)
		}
		ready = ready && removed
	}
	return ready, nil
}

func verifyRemovedAddressMarker(response *dns.Msg, name, zone, marker string) (bool, error) {
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return false, fmt.Errorf("DNS response code is %s", dns.RcodeToString[response.Rcode])
	}
	if response.Truncated || !response.Authoritative {
		return false, errors.New("DNS ownership marker response is truncated or not authoritative")
	}
	if len(response.Question) != 1 || response.Question[0].Qtype != dns.TypeTXT ||
		response.Question[0].Qclass != dns.ClassINET || !strings.EqualFold(response.Question[0].Name, dns.Fqdn(name)) {
		return false, errors.New("DNS ownership marker response answers another question")
	}
	for _, answer := range response.Answer {
		txt, ok := answer.(*dns.TXT)
		if response.Rcode != dns.RcodeSuccess || !ok || !strings.EqualFold(txt.Hdr.Name, dns.Fqdn(name)) || txt.Hdr.Class != dns.ClassINET {
			return false, errors.New("DNS ownership marker response has an unexpected answer")
		}
		if strings.Join(txt.Txt, "") == marker {
			return false, nil
		}
	}
	if len(response.Answer) > 0 {
		// a foreign TXT value can be synthesized from a wildcard. the exact
		// provider listing has already excluded an exact marker at this name.
		return true, nil
	}
	for _, answer := range response.Ns {
		soa, ok := answer.(*dns.SOA)
		if ok && strings.EqualFold(soa.Hdr.Name, dns.Fqdn(zone)) && soa.Hdr.Class == dns.ClassINET {
			return true, nil
		}
	}
	return false, errors.New("DNS ownership marker response has no negative proof from its hosted zone")
}
