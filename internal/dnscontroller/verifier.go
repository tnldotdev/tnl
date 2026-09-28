package dnscontroller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type AuthoritativeVerifier struct {
	resolver *net.Resolver
	dialer   net.Dialer
}

func NewAuthoritativeVerifier(server string) (*AuthoritativeVerifier, error) {
	resolver := net.DefaultResolver
	if server != "" {
		if _, _, err := net.SplitHostPort(server); err != nil {
			return nil, fmt.Errorf("dnscontroller: invalid DNS resolver address: %w", err)
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server)
			},
		}
	}
	return &AuthoritativeVerifier{resolver: resolver}, nil
}

func (v *AuthoritativeVerifier) Verify(ctx context.Context, domain string, expected []string) (bool, error) {
	expected = normalizeDNSNames(expected)
	if len(expected) < 2 {
		return false, errors.New("dnscontroller: expected nameserver set is incomplete")
	}
	delegated, err := v.resolver.LookupNS(ctx, domain)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) && dnsError.IsNotFound {
			return false, nil
		}
		return false, fmt.Errorf("dnscontroller: resolve delegated nameservers: %w", err)
	}
	actual := make([]string, len(delegated))
	for index, nameserver := range delegated {
		actual[index] = nameserver.Host
	}
	if !slices.Equal(normalizeDNSNames(actual), expected) {
		return false, nil
	}
	for _, nameserver := range expected {
		addresses, err := v.resolver.LookupIPAddr(ctx, nameserver)
		if err != nil {
			return false, fmt.Errorf("dnscontroller: resolve authoritative nameserver %q: %w", nameserver, err)
		}
		verified := false
		var queryErr error
		for _, address := range addresses {
			server := net.JoinHostPort(address.IP.String(), "53")
			validNS, err := v.query(ctx, server, domain, dns.TypeNS, expected)
			if err != nil {
				queryErr = errors.Join(queryErr, err)
				continue
			}
			validSOA, err := v.query(ctx, server, domain, dns.TypeSOA, expected)
			if err != nil {
				queryErr = errors.Join(queryErr, err)
				continue
			}
			if validNS && validSOA {
				verified = true
				break
			}
		}
		if !verified {
			if queryErr != nil {
				return false, fmt.Errorf("dnscontroller: query authoritative nameserver %q: %w", nameserver, queryErr)
			}
			return false, nil
		}
	}
	return true, nil
}

func (v *AuthoritativeVerifier) VerifyPublicURL(
	ctx context.Context,
	hostname string,
	expectedIPv4, expectedIPv6, nameservers []string,
) (bool, error) {
	nameservers = normalizeDNSNames(nameservers)
	if len(nameservers) < 2 {
		return false, errors.New("dnscontroller: route nameserver set is incomplete")
	}
	expected := map[uint16][]string{dns.TypeA: slices.Clone(expectedIPv4), dns.TypeAAAA: slices.Clone(expectedIPv6)}
	for recordType := range expected {
		slices.Sort(expected[recordType])
	}
	for _, nameserver := range nameservers {
		addresses, err := v.resolver.LookupIPAddr(ctx, nameserver)
		if err != nil {
			return false, fmt.Errorf("dnscontroller: resolve route nameserver %q: %w", nameserver, err)
		}
		verified := false
		var queryErr error
		for _, address := range addresses {
			server := net.JoinHostPort(address.IP.String(), "53")
			valid := true
			for _, recordType := range []uint16{dns.TypeA, dns.TypeAAAA} {
				matches, err := v.queryAddresses(ctx, server, hostname, recordType, expected[recordType])
				if err != nil {
					queryErr = errors.Join(queryErr, err)
					valid = false
					break
				}
				if !matches {
					valid = false
					break
				}
			}
			if valid {
				verified = true
				break
			}
		}
		if !verified {
			if queryErr != nil {
				return false, fmt.Errorf("dnscontroller: query route nameserver %q: %w", nameserver, queryErr)
			}
			return false, nil
		}
	}
	return true, nil
}

func (v *AuthoritativeVerifier) VerifyChallenge(
	ctx context.Context,
	recordName, expected string,
	nameservers []string,
) (bool, error) {
	nameservers = normalizeDNSNames(nameservers)
	if len(nameservers) < 2 {
		return false, errors.New("dnscontroller: challenge nameserver set is incomplete")
	}
	for _, nameserver := range nameservers {
		addresses, err := v.resolver.LookupIPAddr(ctx, nameserver)
		if err != nil {
			return false, fmt.Errorf("dnscontroller: resolve challenge nameserver %q: %w", nameserver, err)
		}
		verified := false
		var queryErr error
		for _, address := range addresses {
			valid, err := v.queryTXT(ctx, net.JoinHostPort(address.IP.String(), "53"), recordName, expected)
			if err != nil {
				queryErr = errors.Join(queryErr, err)
				continue
			}
			if valid {
				verified = true
				break
			}
		}
		if !verified {
			if queryErr != nil {
				return false, fmt.Errorf("dnscontroller: query challenge nameserver %q: %w", nameserver, queryErr)
			}
			return false, nil
		}
	}
	// After Route 53 reports INSYNC and its nameservers agree, also require
	// the configured recursive resolver to see this value. It may still have
	// cached an earlier NXDOMAIN answer from before the record existed.
	return v.verifyRecursiveChallenge(ctx, recordName, expected)
}

func (v *AuthoritativeVerifier) verifyRecursiveChallenge(ctx context.Context, recordName, expected string) (bool, error) {
	resolver := v.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	values, err := resolver.LookupTXT(ctx, recordName)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) && dnsError.IsNotFound {
			return false, nil
		}
		return false, fmt.Errorf("dnscontroller: resolve challenge through recursive DNS: %w", err)
	}
	return slices.Contains(values, expected), nil
}

func (v *AuthoritativeVerifier) query(
	ctx context.Context,
	server, domain string,
	recordType uint16,
	expectedNameservers []string,
) (bool, error) {
	response, err := v.exchange(ctx, server, domain, recordType)
	if err != nil {
		return false, err
	}
	if response.Rcode == dns.RcodeNameError {
		return false, nil
	}
	if response.Rcode != dns.RcodeSuccess {
		return false, fmt.Errorf("DNS response code is %s", dns.RcodeToString[response.Rcode])
	}
	if !response.Authoritative {
		return false, nil
	}
	switch recordType {
	case dns.TypeNS:
		actual := make([]string, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if record, ok := answer.(*dns.NS); ok && strings.EqualFold(record.Hdr.Name, dns.Fqdn(domain)) {
				actual = append(actual, record.Ns)
			}
		}
		return slices.Equal(normalizeDNSNames(actual), expectedNameservers), nil
	case dns.TypeSOA:
		for _, answer := range response.Answer {
			record, ok := answer.(*dns.SOA)
			if ok && strings.EqualFold(record.Hdr.Name, dns.Fqdn(domain)) &&
				slices.Contains(expectedNameservers, strings.TrimSuffix(strings.ToLower(record.Ns), ".")) {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, errors.New("dnscontroller: unsupported verification record type")
	}
}

func (v *AuthoritativeVerifier) queryAddresses(
	ctx context.Context,
	server, hostname string,
	recordType uint16,
	expected []string,
) (bool, error) {
	response, err := v.exchange(ctx, server, hostname, recordType)
	if err != nil {
		return false, err
	}
	if response.Rcode == dns.RcodeNameError {
		return len(expected) == 0 && response.Authoritative, nil
	}
	if response.Rcode != dns.RcodeSuccess {
		return false, fmt.Errorf("DNS response code is %s", dns.RcodeToString[response.Rcode])
	}
	if !response.Authoritative {
		return false, nil
	}
	actual := make([]string, 0, len(response.Answer))
	for _, answer := range response.Answer {
		switch record := answer.(type) {
		case *dns.A:
			if recordType == dns.TypeA && strings.EqualFold(record.Hdr.Name, dns.Fqdn(hostname)) {
				actual = append(actual, record.A.String())
			}
		case *dns.AAAA:
			if recordType == dns.TypeAAAA && strings.EqualFold(record.Hdr.Name, dns.Fqdn(hostname)) {
				actual = append(actual, record.AAAA.String())
			}
		}
	}
	slices.Sort(actual)
	return slices.Equal(actual, expected), nil
}

func (v *AuthoritativeVerifier) queryTXT(
	ctx context.Context,
	server, recordName, expected string,
) (bool, error) {
	response, err := v.exchange(ctx, server, recordName, dns.TypeTXT)
	if err != nil {
		return false, err
	}
	if response.Rcode != dns.RcodeSuccess {
		return false, nil
	}
	if !response.Authoritative {
		return false, nil
	}
	for _, answer := range response.Answer {
		record, ok := answer.(*dns.TXT)
		if ok && strings.EqualFold(record.Hdr.Name, dns.Fqdn(recordName)) && strings.Join(record.Txt, "") == expected {
			return true, nil
		}
	}
	return false, nil
}

func (v *AuthoritativeVerifier) exchange(
	ctx context.Context,
	server, name string,
	recordType uint16,
) (*dns.Msg, error) {
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(name), recordType)
	request.RecursionDesired = false
	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second, Dialer: &v.dialer}
	response, _, err := client.ExchangeContext(ctx, request, server)
	if err != nil {
		return nil, err
	}
	if response.Truncated {
		client.Net = "tcp"
		response, _, err = client.ExchangeContext(ctx, request, server)
		if err != nil {
			return nil, err
		}
	}
	return response, nil
}

func normalizeDNSNames(values []string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strings.TrimSuffix(strings.ToLower(value), ".")
	}
	slices.Sort(result)
	return slices.Compact(result)
}
