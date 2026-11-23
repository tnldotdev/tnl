package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/tnldotdev/tnl/internal/naming"
)

type nameserverSetupError struct {
	host  string
	check string
	cause error
}

func (e *nameserverSetupError) Error() string { return e.host + ": " + e.check }
func (e *nameserverSetupError) Unwrap() error { return e.cause }

func (v *AuthoritativeVerifier) VerifyNameserverMapping(ctx context.Context, public, aws []string) error {
	if len(public) != 4 || len(aws) != 4 {
		return errors.New("branded delegation requires four nameservers")
	}
	seen := make(map[netip.Addr]bool)
	for i, name := range public {
		expected, err := v.publicAddresses(ctx, aws[i])
		if err != nil {
			return fmt.Errorf("look up Route 53 nameserver %s: %w", aws[i], err)
		}
		canonical, err := v.resolver.LookupCNAME(ctx, name)
		if err != nil {
			return &nameserverSetupError{name, "does not resolve", err}
		}
		if !strings.EqualFold(canonical, dns.Fqdn(name)) {
			return &nameserverSetupError{name, "must use A and AAAA records, not a CNAME", nil}
		}
		actual, err := v.publicAddresses(ctx, name)
		if err != nil {
			return &nameserverSetupError{name, "does not resolve to public DNS addresses", err}
		}
		if !slices.Equal(actual, expected) {
			return &nameserverSetupError{name, "must use the assigned Route 53 addresses", nil}
		}
		for _, addr := range actual {
			if seen[addr] {
				return &nameserverSetupError{name, "repeats another nameserver address", nil}
			}
			seen[addr] = true
		}
	}
	return nil
}

func (v *AuthoritativeVerifier) VerifyClaimProof(ctx context.Context, domain, name, value string, backend []string) (bool, error) {
	_, parent, _ := strings.Cut(domain, ".")
	apex := naming.IsWithin(name, domain)
	start := parent
	if apex {
		start = domain
	}
	zone, servers, err := v.enclosingAuthority(ctx, start)
	if err != nil || len(servers) == 0 || apex && zone != domain {
		return false, err
	}
	// a registrable domain must prove control at its current external DNS
	// provider. a stale delegation to our servers cannot prove dns ownership.
	var ourAddresses []netip.Addr
	if apex {
		for _, server := range backend {
			addresses, err := v.publicAddresses(ctx, server)
			if err != nil {
				return false, err
			}
			ourAddresses = append(ourAddresses, addresses...)
		}
	}
	return v.verifyAtAuthority(ctx, zone, servers, ourAddresses, func(address string) (bool, error) {
		return v.queryTXT(ctx, address, name, value)
	})
}

func (v *AuthoritativeVerifier) VerifyParentDelegation(ctx context.Context, domain string, expected []string) (bool, error) {
	return v.verifyParent(ctx, domain, func(reply *dns.Msg, zone string) bool {
		return matchesDelegationReferral(reply, domain, expected)
	})
}

func (v *AuthoritativeVerifier) VerifyBrandedZone(ctx context.Context, domain string, expected []string) (bool, error) {
	return v.verifyAtAuthority(ctx, domain, expected, nil, func(address string) (bool, error) {
		normalized := normalizeDNSNames(expected)
		soa, err := v.query(ctx, address, domain, dns.TypeSOA, normalized)
		if err != nil || !soa {
			return false, err
		}
		return v.query(ctx, address, domain, dns.TypeNS, normalized)
	})
}

func (v *AuthoritativeVerifier) VerifyDelegationRemoved(ctx context.Context, domain string, previous []string) (bool, error) {
	return v.verifyParent(ctx, domain, func(reply *dns.Msg, zone string) bool {
		return delegationRemoved(reply, domain, zone, previous)
	})
}

func (v *AuthoritativeVerifier) verifyParent(ctx context.Context, domain string, check func(*dns.Msg, string) bool) (bool, error) {
	_, parent, _ := strings.Cut(domain, ".")
	zone, servers, err := v.enclosingAuthority(ctx, parent)
	if err != nil || len(servers) == 0 {
		return false, err
	}
	return v.verifyAtAuthority(ctx, zone, servers, nil, func(address string) (bool, error) {
		reply, err := v.exchange(ctx, address, domain, dns.TypeNS)
		if err != nil {
			return false, err
		}
		return check(reply, zone), nil
	})
}

// a child nameserver answering authoritatively for its apex does not prove
// that the parent delegates to it. only accept the parent's exact referral.
func matchesDelegationReferral(reply *dns.Msg, domain string, expected []string) bool {
	if reply.Rcode != dns.RcodeSuccess || reply.Authoritative || len(reply.Answer) != 0 {
		return false
	}
	var actual []string
	for _, rr := range reply.Ns {
		if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, dns.Fqdn(domain)) {
			actual = append(actual, ns.Ns)
		}
	}
	return len(expected) >= 2 && slices.Equal(normalizeDNSNames(actual), normalizeDNSNames(expected))
}

func delegationRemoved(reply *dns.Msg, domain, zone string, previous []string) bool {
	if len(reply.Answer) != 0 {
		return false
	}
	if reply.Authoritative && (reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError) {
		for _, rr := range reply.Ns {
			if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, dns.Fqdn(zone)) {
				return true
			}
		}
		return false
	}
	if reply.Rcode != dns.RcodeSuccess {
		return false
	}
	other := false
	for _, rr := range reply.Ns {
		if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, dns.Fqdn(domain)) {
			if slices.Contains(previous, strings.TrimSuffix(strings.ToLower(ns.Ns), ".")) {
				return false
			}
			other = true
		}
	}
	return other
}

// the immediate parent need not be a DNS zone. walk outward until the
// recursive resolver finds its closest delegation.
func (v *AuthoritativeVerifier) enclosingAuthority(ctx context.Context, zone string) (string, []string, error) {
	for depth := 0; zone != "" && depth < 32; depth++ {
		records, err := v.resolver.LookupNS(ctx, dns.Fqdn(zone))
		if err != nil {
			var dnsErr *net.DNSError
			if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
				return "", nil, err
			}
		}
		if len(records) != 0 {
			if len(records) > 32 {
				return "", nil, errors.New("too many authoritative nameservers for a DNS claim")
			}
			names := make([]string, 0, len(records))
			for _, rr := range records {
				names = append(names, rr.Host)
			}
			return zone, normalizeDNSNames(names), nil
		}
		_, zone, _ = strings.Cut(zone, ".")
	}
	return "", nil, nil
}

func (v *AuthoritativeVerifier) verifyAtAuthority(ctx context.Context, zone string, servers []string, blocked []netip.Addr, check func(string) (bool, error)) (bool, error) {
	for _, server := range servers {
		addresses, err := v.publicAddresses(ctx, server)
		if err != nil {
			return false, err
		}
		for _, addr := range addresses {
			if slices.Contains(blocked, addr) {
				return false, nil
			}
		}
		valid := false
		var queryErr error
		for _, addr := range addresses {
			address := net.JoinHostPort(addr.String(), "53")
			// lookupNS may follow a CNAME. require the actual zone's SOA
			// from this server before accepting a TXT answer or referral.
			authority, err := v.hasAuthority(ctx, address, zone)
			if err == nil && authority {
				valid, err = check(address)
			}
			if err != nil {
				queryErr = errors.Join(queryErr, err)
			}
			if valid {
				break
			}
		}
		if !valid {
			return false, queryErr
		}
	}
	return true, nil
}

func (v *AuthoritativeVerifier) hasAuthority(ctx context.Context, address, zone string) (bool, error) {
	reply, err := v.exchange(ctx, address, zone, dns.TypeSOA)
	if err != nil || reply.Rcode != dns.RcodeSuccess || !reply.Authoritative {
		return false, err
	}
	for _, rr := range reply.Answer {
		if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, dns.Fqdn(zone)) {
			return true, nil
		}
	}
	return false, nil
}

func (v *AuthoritativeVerifier) publicAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	addresses, err := v.resolver.LookupNetIP(ctx, "ip", dns.Fqdn(host))
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 || len(addresses) > 16 {
		return nil, errors.New("unexpected number of nameserver addresses")
	}
	for i, address := range addresses {
		addresses[i] = address.Unmap()
		if !publicDNSAddress(addresses[i]) {
			return nil, fmt.Errorf("nameserver %s does not have public DNS addresses", host)
		}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return slices.Compact(addresses), nil
}

func publicDNSAddress(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.Zone() != "" {
		return false
	}
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, prefix := range nonPublicDNSPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var nonPublicDNSPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}
