package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
	mdns "github.com/miekg/dns"
)

type benchmarkRoute53API interface {
	CreateHostedZone(context.Context, *route53.CreateHostedZoneInput, ...func(*route53.Options)) (*route53.CreateHostedZoneOutput, error)
	GetHostedZone(context.Context, *route53.GetHostedZoneInput, ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error)
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(context.Context, *route53.ChangeResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
	DeleteHostedZone(context.Context, *route53.DeleteHostedZoneInput, ...func(*route53.Options)) (*route53.DeleteHostedZoneOutput, error)
}

type benchmarkResolver interface {
	LookupNS(context.Context, string) ([]*net.NS, error)
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type benchmarkDNS struct {
	client   benchmarkRoute53API
	resolver benchmarkResolver
}

func (d benchmarkDNS) validateParentZone(ctx context.Context, zoneID, domain string) error {
	output, err := d.client.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String(zoneID)})
	if err != nil {
		return fmt.Errorf("read benchmark parent hosted zone: %w", err)
	}
	if output.HostedZone == nil || canonicalDNSName(aws.ToString(output.HostedZone.Name)) != domain ||
		output.HostedZone.Config != nil && output.HostedZone.Config.PrivateZone {
		return errors.New("benchmark parent hosted zone does not match BENCH_PARENT_DOMAIN or is private")
	}
	return nil
}

func (d benchmarkDNS) hostedZoneNameServers(ctx context.Context, zoneID string) ([]string, error) {
	output, err := d.client.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String(zoneID)})
	if err != nil {
		return nil, fmt.Errorf("read benchmark hosted-zone name servers: %w", err)
	}
	if output.DelegationSet == nil || len(output.DelegationSet.NameServers) < 2 {
		return nil, errors.New("benchmark hosted zone has no public delegation set")
	}
	nameServers := append([]string(nil), output.DelegationSet.NameServers...)
	for index := range nameServers {
		nameServers[index] = canonicalDNSName(nameServers[index])
	}
	slices.Sort(nameServers)
	return nameServers, nil
}

func (d benchmarkDNS) createZone(ctx context.Context, name, reference string) (manifestZone, error) {
	output, err := d.client.CreateHostedZone(ctx, &route53.CreateHostedZoneInput{
		CallerReference: aws.String(reference), Name: aws.String(name),
		HostedZoneConfig: &types.HostedZoneConfig{Comment: aws.String("transient tnl benchmark " + reference)},
	})
	if err != nil {
		return manifestZone{}, fmt.Errorf("create hosted zone %s: %w", name, err)
	}
	if output.HostedZone == nil || output.DelegationSet == nil {
		return manifestZone{}, fmt.Errorf("create hosted zone %s: Route 53 returned incomplete state", name)
	}
	zone := manifestZone{
		Name: name, ID: canonicalZoneID(aws.ToString(output.HostedZone.Id)),
		NameServers: append([]string(nil), output.DelegationSet.NameServers...),
	}
	for index := range zone.NameServers {
		zone.NameServers[index] = canonicalDNSName(zone.NameServers[index])
	}
	slices.Sort(zone.NameServers)
	if zone.ID == "" || len(zone.NameServers) < 2 {
		return manifestZone{}, fmt.Errorf("create hosted zone %s: Route 53 returned invalid identity", name)
	}
	return zone, nil
}

func (d benchmarkDNS) upsertDelegation(ctx context.Context, parentZoneID string, zone manifestZone) error {
	return d.changeRecord(ctx, parentZoneID, types.ChangeActionUpsert, recordSet(zone.Name, types.RRTypeNs, zone.NameServers))
}

func (d benchmarkDNS) upsertAddress(ctx context.Context, zoneID, hostname string, ipv4, ipv6 []string) error {
	var changes []types.Change
	for _, record := range []struct {
		typeName types.RRType
		values   []string
	}{{types.RRTypeA, ipv4}, {types.RRTypeAaaa, ipv6}} {
		if len(record.values) == 0 {
			continue
		}
		changes = append(changes, types.Change{
			Action: types.ChangeActionUpsert, ResourceRecordSet: recordSet(hostname, record.typeName, record.values),
		})
	}
	if len(changes) == 0 {
		return nil
	}
	if err := d.changeRecords(ctx, zoneID, changes); err != nil {
		return fmt.Errorf("change benchmark DNS address %s: %w", hostname, err)
	}
	return nil
}

func (d benchmarkDNS) waitDelegation(
	ctx context.Context,
	parentNameServers []string,
	zone manifestZone,
	timeout time.Duration,
) error {
	expected := make(map[string]struct{}, len(zone.NameServers))
	for _, nameServer := range zone.NameServers {
		expected[canonicalDNSName(nameServer)] = struct{}{}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for {
		matchedAll := true
		for _, parentNameServer := range parentNameServers {
			nameServers, err := d.lookupAuthoritativeNameServers(ctx, parentNameServer, zone.Name)
			if err != nil {
				lastErr = fmt.Errorf("query %s: %w", parentNameServer, err)
				matchedAll = false
				break
			}
			matched := len(nameServers) == len(expected)
			if matched {
				for _, nameServer := range nameServers {
					if _, ok := expected[canonicalDNSName(nameServer)]; !ok {
						matched = false
						break
					}
				}
			}
			if matched {
				continue
			}
			matchedAll = false
			observed := make([]string, 0, len(nameServers))
			for _, nameServer := range nameServers {
				observed = append(observed, canonicalDNSName(nameServer))
			}
			slices.Sort(observed)
			wanted := append([]string(nil), zone.NameServers...)
			for index := range wanted {
				wanted[index] = canonicalDNSName(wanted[index])
			}
			slices.Sort(wanted)
			lastErr = fmt.Errorf("%s resolved name servers %v, want %v", parentNameServer, observed, wanted)
			break
		}
		if matchedAll {
			return nil
		}
		if err := sleepContext(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("wait for authoritative DNS delegation of %s: %w (last lookup error: %v)", zone.Name, err, lastErr)
		}
	}
}

func (d benchmarkDNS) waitAddresses(
	ctx context.Context,
	nameServers []string,
	hostname string,
	ipv4, ipv6 []string,
	timeout time.Duration,
) error {
	expected := make(map[netip.Addr]struct{}, len(ipv4)+len(ipv6))
	for _, value := range append(append([]string(nil), ipv4...), ipv6...) {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return fmt.Errorf("parse expected benchmark address %q: %w", value, err)
		}
		expected[address.Unmap()] = struct{}{}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for {
		matchedAll := true
		for _, nameServer := range nameServers {
			addresses, err := d.lookupAuthoritativeAddresses(ctx, nameServer, hostname)
			if err != nil {
				lastErr = fmt.Errorf("query %s: %w", nameServer, err)
				matchedAll = false
				break
			}
			matched := addressesMatchExpected(addresses, expected)
			if matched {
				continue
			}
			matchedAll = false
			observed := make([]string, 0, len(addresses))
			for _, address := range addresses {
				observed = append(observed, address.Unmap().String())
			}
			slices.Sort(observed)
			wanted := make([]string, 0, len(expected))
			for address := range expected {
				wanted = append(wanted, address.String())
			}
			slices.Sort(wanted)
			lastErr = fmt.Errorf("%s resolved addresses %v, want %v", nameServer, observed, wanted)
			break
		}
		if matchedAll {
			return nil
		}
		if err := sleepContext(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("wait for authoritative DNS addresses of %s: %w (last lookup error: %v)", hostname, err, lastErr)
		}
	}
}

func (d benchmarkDNS) lookupAuthoritativeNameServers(ctx context.Context, nameServer, hostname string) ([]string, error) {
	if d.resolver != nil {
		records, err := d.resolver.LookupNS(ctx, hostname)
		if err != nil {
			return nil, err
		}
		nameServers := make([]string, 0, len(records))
		for _, record := range records {
			nameServers = append(nameServers, canonicalDNSName(record.Host))
		}
		return nameServers, nil
	}
	response, err := queryAuthoritativeDNS(ctx, nameServer, hostname, mdns.TypeNS)
	if err != nil {
		return nil, err
	}
	if response.Rcode == mdns.RcodeNameError {
		return nil, nil
	}
	if response.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("dns response code is %s", mdns.RcodeToString[response.Rcode])
	}
	var nameServers []string
	for _, section := range [][]mdns.RR{response.Answer, response.Ns} {
		for _, answer := range section {
			record, ok := answer.(*mdns.NS)
			if ok && strings.EqualFold(record.Hdr.Name, mdns.Fqdn(hostname)) {
				nameServers = append(nameServers, canonicalDNSName(record.Ns))
			}
		}
	}
	return nameServers, nil
}

func (d benchmarkDNS) lookupAuthoritativeAddresses(ctx context.Context, nameServer, hostname string) ([]netip.Addr, error) {
	if d.resolver != nil {
		return d.resolver.LookupNetIP(ctx, "ip", hostname)
	}
	var addresses []netip.Addr
	for _, recordType := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
		response, err := queryAuthoritativeDNS(ctx, nameServer, hostname, recordType)
		if err != nil {
			return nil, err
		}
		if response.Rcode == mdns.RcodeNameError {
			continue
		}
		if response.Rcode != mdns.RcodeSuccess {
			return nil, fmt.Errorf("dns response code is %s", mdns.RcodeToString[response.Rcode])
		}
		if !response.Authoritative {
			return nil, errors.New("dns response is not authoritative")
		}
		for _, answer := range response.Answer {
			var address net.IP
			switch record := answer.(type) {
			case *mdns.A:
				address = record.A
			case *mdns.AAAA:
				address = record.AAAA
			}
			parsed, ok := netip.AddrFromSlice(address)
			if ok {
				addresses = append(addresses, parsed.Unmap())
			}
		}
	}
	return addresses, nil
}

func queryAuthoritativeDNS(ctx context.Context, nameServer, hostname string, recordType uint16) (*mdns.Msg, error) {
	servers := []string{nameServer}
	if _, _, err := net.SplitHostPort(nameServer); err != nil {
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", nameServer)
		if err != nil {
			return nil, fmt.Errorf("resolve authoritative name server %s: %w", nameServer, err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("resolve authoritative name server %s: no IPv4 address", nameServer)
		}
		servers = make([]string, 0, len(addresses))
		for _, address := range addresses {
			servers = append(servers, netip.AddrPortFrom(address, 53).String())
		}
	}
	query := new(mdns.Msg)
	query.SetQuestion(mdns.Fqdn(hostname), recordType)
	query.RecursionDesired = false
	client := &mdns.Client{Net: "udp", Timeout: 5 * time.Second}
	var queryErr error
	for _, server := range servers {
		response, _, err := client.ExchangeContext(ctx, query, server)
		if err == nil {
			return response, nil
		}
		queryErr = errors.Join(queryErr, err)
	}
	return nil, queryErr
}

func addressesMatchExpected(addresses []netip.Addr, expected map[netip.Addr]struct{}) bool {
	if len(addresses) != len(expected) {
		return false
	}
	for _, address := range addresses {
		if _, ok := expected[address.Unmap()]; !ok {
			return false
		}
	}
	return true
}

func (d benchmarkDNS) changeRecord(ctx context.Context, zoneID string, action types.ChangeAction, record *types.ResourceRecordSet) error {
	err := d.changeRecords(ctx, zoneID, []types.Change{{Action: action, ResourceRecordSet: record}})
	if err != nil {
		return fmt.Errorf("change benchmark DNS record %s: %w", aws.ToString(record.Name), err)
	}
	return nil
}

func (d benchmarkDNS) changeRecords(ctx context.Context, zoneID string, changes []types.Change) error {
	_, err := d.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch:  &types.ChangeBatch{Comment: aws.String("transient tnl benchmark"), Changes: changes},
	})
	if err != nil {
		return err
	}
	return nil
}

func (d benchmarkDNS) deleteZone(ctx context.Context, zone manifestZone) error {
	childMissing := false
	if err := d.validateParentZone(ctx, zone.ID, zone.Name); err != nil {
		if route53Error(err, "NoSuchHostedZone") {
			childMissing = true
		} else {
			return fmt.Errorf("refuse to delete benchmark hosted zone: %w", err)
		}
	}
	if zone.ParentZoneID != "" {
		if err := d.validateParentZone(ctx, zone.ParentZoneID, zone.ParentName); err != nil {
			if route53Error(err, "NoSuchHostedZone") {
				if childMissing {
					return nil
				}
			} else {
				return err
			}
		} else {
			err := d.changeRecord(ctx, zone.ParentZoneID, types.ChangeActionDelete, recordSet(zone.Name, types.RRTypeNs, zone.NameServers))
			if err != nil && !route53Error(err, "InvalidChangeBatch") && !route53Error(err, "NoSuchHostedZone") {
				return err
			}
		}
	}
	if childMissing {
		return nil
	}
	records, err := d.listDeletableRecords(ctx, zone.ID, zone.Name)
	if err != nil && !route53Error(err, "NoSuchHostedZone") {
		return err
	}
	for start := 0; start < len(records); start += 1000 {
		end := min(start+1000, len(records))
		changes := make([]types.Change, 0, end-start)
		for index := start; index < end; index++ {
			record := records[index]
			changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: &record})
		}
		if err := d.changeRecords(ctx, zone.ID, changes); err != nil && !route53Error(err, "NoSuchHostedZone") {
			return fmt.Errorf("empty benchmark hosted zone %s: %w", zone.Name, err)
		}
	}
	if _, err := d.client.DeleteHostedZone(ctx, &route53.DeleteHostedZoneInput{Id: aws.String(zone.ID)}); err != nil &&
		!route53Error(err, "NoSuchHostedZone") {
		return fmt.Errorf("delete benchmark hosted zone %s: %w", zone.Name, err)
	}
	return nil
}

func (d benchmarkDNS) listDeletableRecords(ctx context.Context, zoneID, zoneName string) ([]types.ResourceRecordSet, error) {
	input := &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String(zoneID)}
	var records []types.ResourceRecordSet
	for {
		output, err := d.client.ListResourceRecordSets(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list benchmark hosted-zone records: %w", err)
		}
		for _, record := range output.ResourceRecordSets {
			isApexDefault := canonicalDNSName(aws.ToString(record.Name)) == zoneName &&
				(record.Type == types.RRTypeNs || record.Type == types.RRTypeSoa) && record.SetIdentifier == nil
			if !isApexDefault {
				records = append(records, record)
			}
		}
		if !output.IsTruncated {
			return records, nil
		}
		input.StartRecordName = output.NextRecordName
		input.StartRecordType = output.NextRecordType
		input.StartRecordIdentifier = output.NextRecordIdentifier
	}
}

func recordSet(name string, recordType types.RRType, values []string) *types.ResourceRecordSet {
	records := make([]types.ResourceRecord, len(values))
	for index, value := range values {
		if recordType == types.RRTypeNs {
			value = canonicalDNSName(value) + "."
		}
		records[index].Value = aws.String(value)
	}
	return &types.ResourceRecordSet{
		Name: aws.String(canonicalDNSName(name) + "."), Type: recordType, TTL: aws.Int64(60), ResourceRecords: records,
	}
}

func canonicalDNSName(value string) string { return strings.TrimSuffix(strings.ToLower(value), ".") }

func canonicalZoneID(value string) string { return strings.TrimPrefix(value, "/hostedzone/") }

func route53Error(err error, code string) bool {
	var apiError smithy.APIError
	return errors.As(err, &apiError) && apiError.ErrorCode() == code
}
