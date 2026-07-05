package dnscontroller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/naming"
)

const (
	managedByTagKey            = "tnl.dev/managed-by"
	managedByTagValue          = "tnld"
	authorityReferenceTagKey   = "tnl.dev/dns-authority-reference"
	domainIDTagKey             = "tnl.dev/domain-id"
	teamIDTagKey               = "tnl.dev/team-id"
	hostedZoneResourceIDPrefix = "/hostedzone/"
)

type route53API interface {
	CreateHostedZone(context.Context, *route53.CreateHostedZoneInput, ...func(*route53.Options)) (*route53.CreateHostedZoneOutput, error)
	ListHostedZonesByName(context.Context, *route53.ListHostedZonesByNameInput, ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error)
	GetHostedZone(context.Context, *route53.GetHostedZoneInput, ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error)
	ChangeTagsForResource(context.Context, *route53.ChangeTagsForResourceInput, ...func(*route53.Options)) (*route53.ChangeTagsForResourceOutput, error)
	ListTagsForResource(context.Context, *route53.ListTagsForResourceInput, ...func(*route53.Options)) (*route53.ListTagsForResourceOutput, error)
	DeleteHostedZone(context.Context, *route53.DeleteHostedZoneInput, ...func(*route53.Options)) (*route53.DeleteHostedZoneOutput, error)
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(context.Context, *route53.ChangeResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
}

func (p *Route53Provider) PublishRoute(ctx context.Context, record RouteRecord) (Zone, error) {
	zone, err := p.routeZone(ctx, record)
	if err != nil {
		return Zone{}, err
	}
	addressRecords, owner, err := p.routeRecords(ctx, record)
	if err != nil {
		return Zone{}, err
	}
	marker := routeOwnerValue(record.RouteID)
	ownerExists := owner != nil
	if ownerExists && !plainRecordSet(owner) || ownerExists &&
		(len(owner.ResourceRecords) != 1 || aws.ToString(owner.ResourceRecords[0].Value) != marker) {
		return Zone{}, terminalf("route DNS ownership marker does not match")
	}
	if !ownerExists && len(addressRecords) != 0 {
		return Zone{}, terminalf("route hostname already has unowned address records")
	}
	action := types.ChangeActionCreate
	if ownerExists {
		action = types.ChangeActionUpsert
	}
	changes := []types.Change{{
		Action: action,
		ResourceRecordSet: &types.ResourceRecordSet{
			Name: aws.String(routeOwnerName(record.CanonicalHostname)), Type: types.RRTypeTxt, TTL: aws.Int64(60),
			ResourceRecords: []types.ResourceRecord{{Value: aws.String(marker)}},
		},
	}}
	desired := map[types.RRType][]string{
		types.RRTypeA: record.IngressIPv4Addresses, types.RRTypeAaaa: record.IngressIPv6Addresses,
	}
	for _, recordType := range []types.RRType{types.RRTypeA, types.RRTypeAaaa} {
		existing := addressRecords[recordType]
		values := desired[recordType]
		if len(values) != 0 {
			changes = append(changes, types.Change{
				Action:            types.ChangeActionUpsert,
				ResourceRecordSet: simpleRecordSet(record.CanonicalHostname, recordType, values),
			})
		} else if existing != nil {
			changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: existing})
		}
	}
	if _, err := p.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zone.ID),
		ChangeBatch:  &types.ChangeBatch{Comment: aws.String("publish tnl route " + record.RouteID), Changes: changes},
	}); err != nil {
		return Zone{}, fmt.Errorf("dnscontroller: publish Route 53 route records: %w", err)
	}
	return zone, nil
}

func (p *Route53Provider) RemoveRoute(ctx context.Context, record RouteRecord) (Zone, error) {
	zone, err := p.routeZone(ctx, record)
	if err != nil {
		return Zone{}, err
	}
	addressRecords, owner, err := p.routeRecords(ctx, record)
	if err != nil {
		return Zone{}, err
	}
	if owner == nil {
		if len(addressRecords) == 0 {
			return zone, nil
		}
		return Zone{}, terminalf("route hostname has address records without an ownership marker")
	}
	if !plainRecordSet(owner) || len(owner.ResourceRecords) != 1 ||
		aws.ToString(owner.ResourceRecords[0].Value) != routeOwnerValue(record.RouteID) {
		return Zone{}, terminalf("route DNS ownership marker does not match")
	}
	changes := make([]types.Change, 0, len(addressRecords)+1)
	for _, recordType := range []types.RRType{types.RRTypeA, types.RRTypeAaaa} {
		if existing := addressRecords[recordType]; existing != nil {
			changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: existing})
		}
	}
	changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: owner})
	if _, err := p.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zone.ID),
		ChangeBatch:  &types.ChangeBatch{Comment: aws.String("remove tnl route " + record.RouteID), Changes: changes},
	}); err != nil {
		return Zone{}, fmt.Errorf("dnscontroller: remove Route 53 route records: %w", err)
	}
	return zone, nil
}

func (p *Route53Provider) ReconcileChallenge(ctx context.Context, record ChallengeRecord) (Zone, error) {
	zoneRecord := RouteRecord{
		ZoneID: record.ZoneID, ZoneDomain: record.ZoneDomain, ClaimedZone: record.ClaimedZone,
		AuthorityReference: record.AuthorityReference, TeamID: record.TeamID, DomainID: record.DomainID,
		CanonicalHostname: record.RecordName,
	}
	zone, err := p.routeZone(ctx, zoneRecord)
	if err != nil {
		return Zone{}, err
	}
	sets, err := p.listRecordSets(ctx, zone.ID, record.RecordName)
	if err != nil {
		return Zone{}, err
	}
	var existing *types.ResourceRecordSet
	for index := range sets {
		if sets[index].Type == types.RRTypeCname {
			return Zone{}, terminalf("DNS challenge name has a conflicting CNAME record")
		}
		if sets[index].Type != types.RRTypeTxt {
			continue
		}
		if existing != nil {
			return Zone{}, terminalf("DNS challenge has multiple TXT record sets")
		}
		existing = &sets[index]
	}
	if existing != nil && !plainRecordSet(existing) {
		return Zone{}, terminalf("DNS challenge TXT record uses an unsupported routing policy")
	}
	owned := make(map[string]struct{}, len(record.PreviouslyOwnedValues))
	for _, value := range record.PreviouslyOwnedValues {
		owned[strconv.Quote(value)] = struct{}{}
	}
	values := make(map[string]struct{}, len(record.DesiredOwnedValues))
	if existing != nil {
		for _, value := range existing.ResourceRecords {
			raw := aws.ToString(value.Value)
			if _, isOwned := owned[raw]; !isOwned {
				values[raw] = struct{}{}
			}
		}
	}
	for _, value := range record.DesiredOwnedValues {
		values[strconv.Quote(value)] = struct{}{}
	}
	nextValues := mapKeys(values)
	if existing == nil && len(nextValues) == 0 {
		return zone, nil
	}
	change := types.Change{Action: types.ChangeActionUpsert}
	if existing == nil {
		change.Action = types.ChangeActionCreate
	}
	if len(nextValues) == 0 {
		change.Action = types.ChangeActionDelete
		change.ResourceRecordSet = existing
	} else {
		change.ResourceRecordSet = simpleRecordSet(record.RecordName, types.RRTypeTxt, nextValues)
	}
	if _, err := p.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zone.ID),
		ChangeBatch:  &types.ChangeBatch{Comment: aws.String("reconcile owned tnl ACME challenge values"), Changes: []types.Change{change}},
	}); err != nil {
		return Zone{}, fmt.Errorf("dnscontroller: reconcile Route 53 DNS challenge: %w", err)
	}
	return zone, nil
}

type Route53Provider struct{ client route53API }

func NewRoute53Provider(client route53API) (*Route53Provider, error) {
	if client == nil {
		return nil, errors.New("dnscontroller: Route 53 client is required")
	}
	return &Route53Provider{client: client}, nil
}

func (p *Route53Provider) EnsureClaimedZone(ctx context.Context, work controlstate.DNSAuthorityWork) (Zone, error) {
	hostedZone, err := p.findClaimedZone(ctx, work)
	if err != nil {
		return Zone{}, err
	}
	if hostedZone == nil {
		output, err := p.client.CreateHostedZone(ctx, &route53.CreateHostedZoneInput{
			CallerReference: aws.String(work.Reference), Name: aws.String(work.CanonicalDomain),
			HostedZoneConfig: &types.HostedZoneConfig{Comment: aws.String("tnl DNS authority " + work.Reference)},
		})
		if err != nil {
			return Zone{}, fmt.Errorf("dnscontroller: create Route 53 hosted zone: %w", err)
		}
		hostedZone = output.HostedZone
	}
	zoneID, err := validateHostedZone(hostedZone, work)
	if err != nil {
		return Zone{}, err
	}
	if _, err := p.client.ChangeTagsForResource(ctx, &route53.ChangeTagsForResourceInput{
		ResourceId: aws.String(zoneID), ResourceType: types.TagResourceTypeHostedzone,
		AddTags: []types.Tag{
			{Key: aws.String(managedByTagKey), Value: aws.String(managedByTagValue)},
			{Key: aws.String(authorityReferenceTagKey), Value: aws.String(work.Reference)},
			{Key: aws.String(domainIDTagKey), Value: aws.String(work.DomainID)},
			{Key: aws.String(teamIDTagKey), Value: aws.String(work.TeamID)},
		},
	}); err != nil {
		return Zone{}, fmt.Errorf("dnscontroller: tag Route 53 hosted zone: %w", err)
	}
	output, err := p.client.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String(zoneID)})
	if err != nil {
		return Zone{}, fmt.Errorf("dnscontroller: read Route 53 hosted zone: %w", err)
	}
	if _, err := validateHostedZone(output.HostedZone, work); err != nil {
		return Zone{}, err
	}
	if output.DelegationSet == nil {
		return Zone{}, terminalf("Route 53 hosted zone has no delegation set")
	}
	nameservers, err := canonicalNameservers(output.DelegationSet.NameServers)
	if err != nil {
		return Zone{}, err
	}
	return Zone{ID: zoneID, Nameservers: nameservers}, nil
}

func (p *Route53Provider) ReleaseClaimedZone(ctx context.Context, work controlstate.DNSAuthorityWork) error {
	if work.ProviderZoneID == "" {
		return nil
	}
	zoneID := canonicalZoneID(work.ProviderZoneID)
	output, err := p.client.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String(zoneID)})
	if isRoute53Error(err, "NoSuchHostedZone") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("dnscontroller: read Route 53 hosted zone before release: %w", err)
	}
	if _, err := validateHostedZone(output.HostedZone, work); err != nil {
		return err
	}
	tags, err := p.client.ListTagsForResource(ctx, &route53.ListTagsForResourceInput{
		ResourceId: aws.String(zoneID), ResourceType: types.TagResourceTypeHostedzone,
	})
	if err != nil {
		return fmt.Errorf("dnscontroller: read Route 53 hosted-zone tags: %w", err)
	}
	if !ownedTags(tags, work) {
		return terminalf("Route 53 hosted zone ownership tags do not match")
	}
	if _, err := p.client.DeleteHostedZone(ctx, &route53.DeleteHostedZoneInput{Id: aws.String(zoneID)}); err != nil &&
		!isRoute53Error(err, "NoSuchHostedZone") {
		return fmt.Errorf("dnscontroller: delete Route 53 hosted zone: %w", err)
	}
	return nil
}

func (p *Route53Provider) findClaimedZone(ctx context.Context, work controlstate.DNSAuthorityWork) (*types.HostedZone, error) {
	dnsName := work.CanonicalDomain + "."
	input := &route53.ListHostedZonesByNameInput{DNSName: aws.String(dnsName), MaxItems: aws.Int32(100)}
	for {
		output, err := p.client.ListHostedZonesByName(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("dnscontroller: list Route 53 hosted zones: %w", err)
		}
		for index := range output.HostedZones {
			zone := &output.HostedZones[index]
			if aws.ToString(zone.Name) != dnsName {
				return nil, nil
			}
			if aws.ToString(zone.CallerReference) == work.Reference {
				return zone, nil
			}
		}
		if !output.IsTruncated || aws.ToString(output.NextDNSName) != dnsName {
			return nil, nil
		}
		input.DNSName, input.HostedZoneId = output.NextDNSName, output.NextHostedZoneId
	}
}

func (p *Route53Provider) routeZone(ctx context.Context, record RouteRecord) (Zone, error) {
	zoneID := canonicalZoneID(record.ZoneID)
	if zoneID == "" {
		return Zone{}, terminalf("route DNS zone has no ID")
	}
	output, err := p.client.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String(zoneID)})
	if err != nil {
		return Zone{}, fmt.Errorf("dnscontroller: read route Route 53 hosted zone: %w", err)
	}
	if output.HostedZone == nil {
		return Zone{}, terminalf("route Route 53 hosted zone is missing")
	}
	zoneDomain := strings.TrimSuffix(strings.ToLower(aws.ToString(output.HostedZone.Name)), ".")
	if output.HostedZone.LinkedService != nil ||
		output.HostedZone.Config != nil && output.HostedZone.Config.PrivateZone || zoneDomain != record.ZoneDomain ||
		record.CanonicalHostname != zoneDomain && !strings.HasSuffix(record.CanonicalHostname, "."+zoneDomain) {
		return Zone{}, terminalf("route Route 53 hosted zone identity does not match")
	}
	if record.ClaimedZone {
		work := controlstate.DNSAuthorityWork{DNSAuthority: controlstate.DNSAuthority{
			Reference: record.AuthorityReference, TeamID: record.TeamID, DomainID: record.DomainID,
			CanonicalDomain: record.ZoneDomain,
		}}
		if _, err := validateHostedZone(output.HostedZone, work); err != nil {
			return Zone{}, err
		}
		tags, err := p.client.ListTagsForResource(ctx, &route53.ListTagsForResourceInput{
			ResourceId: aws.String(zoneID), ResourceType: types.TagResourceTypeHostedzone,
		})
		if err != nil {
			return Zone{}, fmt.Errorf("dnscontroller: read claimed route hosted-zone tags: %w", err)
		}
		if !ownedTags(tags, work) {
			return Zone{}, terminalf("claimed route hosted-zone ownership tags do not match")
		}
	}
	if output.DelegationSet == nil {
		return Zone{}, terminalf("route Route 53 hosted zone has no delegation set")
	}
	nameservers, err := canonicalNameservers(output.DelegationSet.NameServers)
	if err != nil {
		return Zone{}, err
	}
	return Zone{ID: zoneID, Nameservers: nameservers}, nil
}

func (p *Route53Provider) routeRecords(
	ctx context.Context,
	record RouteRecord,
) (map[types.RRType]*types.ResourceRecordSet, *types.ResourceRecordSet, error) {
	addresses, err := p.listRecordSets(ctx, record.ZoneID, record.CanonicalHostname)
	if err != nil {
		return nil, nil, err
	}
	result := make(map[types.RRType]*types.ResourceRecordSet, 2)
	for index := range addresses {
		item := &addresses[index]
		if item.Type == types.RRTypeCname {
			return nil, nil, terminalf("route hostname has a conflicting CNAME record")
		}
		if item.Type == types.RRTypeA || item.Type == types.RRTypeAaaa {
			if !plainRecordSet(item) {
				return nil, nil, terminalf("route address record uses an unsupported routing policy")
			}
			if result[item.Type] != nil {
				return nil, nil, terminalf("route hostname has multiple address record sets")
			}
			result[item.Type] = item
		}
	}
	owners, err := p.listRecordSets(ctx, record.ZoneID, routeOwnerName(record.CanonicalHostname))
	if err != nil {
		return nil, nil, err
	}
	var owner *types.ResourceRecordSet
	for index := range owners {
		if owners[index].Type != types.RRTypeTxt {
			continue
		}
		if owner != nil {
			return nil, nil, terminalf("route hostname has multiple ownership record sets")
		}
		owner = &owners[index]
	}
	return result, owner, nil
}

func (p *Route53Provider) listRecordSets(ctx context.Context, zoneID, name string) ([]types.ResourceRecordSet, error) {
	name = dnsName(name)
	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(canonicalZoneID(zoneID)), StartRecordName: aws.String(name), MaxItems: aws.Int32(10),
	}
	result := []types.ResourceRecordSet(nil)
	for {
		output, err := p.client.ListResourceRecordSets(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("dnscontroller: list Route 53 record sets: %w", err)
		}
		for _, item := range output.ResourceRecordSets {
			if strings.ToLower(aws.ToString(item.Name)) != name {
				return result, nil
			}
			result = append(result, item)
		}
		if !output.IsTruncated || strings.ToLower(aws.ToString(output.NextRecordName)) != name {
			return result, nil
		}
		input.StartRecordName = output.NextRecordName
		input.StartRecordType = output.NextRecordType
		input.StartRecordIdentifier = output.NextRecordIdentifier
	}
}

func simpleRecordSet(name string, recordType types.RRType, values []string) *types.ResourceRecordSet {
	records := make([]types.ResourceRecord, len(values))
	for index, value := range values {
		records[index].Value = aws.String(value)
	}
	return &types.ResourceRecordSet{
		Name: aws.String(dnsName(name)), Type: recordType, TTL: aws.Int64(60), ResourceRecords: records,
	}
}

func plainRecordSet(record *types.ResourceRecordSet) bool {
	return record != nil && record.AliasTarget == nil && record.SetIdentifier == nil && record.HealthCheckId == nil &&
		record.CidrRoutingConfig == nil && record.Failover == "" && record.GeoLocation == nil &&
		record.GeoProximityLocation == nil && record.Region == "" && record.Weight == nil &&
		record.MultiValueAnswer == nil && record.TrafficPolicyInstanceId == nil
}

func routeOwnerName(hostname string) string { return "_tnl-owner." + hostname }

func routeOwnerValue(routeID string) string { return strconv.Quote("tnl-route:" + routeID) }

func dnsName(value string) string { return strings.ToLower(strings.TrimSuffix(value, ".")) + "." }

func validateHostedZone(zone *types.HostedZone, work controlstate.DNSAuthorityWork) (string, error) {
	if zone == nil || zone.LinkedService != nil || zone.Config != nil && zone.Config.PrivateZone ||
		aws.ToString(zone.CallerReference) != work.Reference ||
		strings.TrimSuffix(strings.ToLower(aws.ToString(zone.Name)), ".") != work.CanonicalDomain {
		return "", terminalf("Route 53 hosted zone identity does not match")
	}
	zoneID := canonicalZoneID(aws.ToString(zone.Id))
	if zoneID == "" {
		return "", terminalf("Route 53 hosted zone has no ID")
	}
	return zoneID, nil
}

func canonicalZoneID(value string) string {
	return strings.TrimPrefix(value, hostedZoneResourceIDPrefix)
}

func canonicalNameservers(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSuffix(strings.ToLower(value), ".")
		canonical, err := naming.CanonicalizeHostname(value)
		if err != nil || canonical != value {
			return nil, terminalf("Route 53 returned an invalid nameserver")
		}
		if _, exists := seen[value]; exists {
			return nil, terminalf("Route 53 returned a duplicate nameserver")
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) < 2 {
		return nil, terminalf("Route 53 returned too few nameservers")
	}
	slices.Sort(result)
	return result, nil
}

func ownedTags(output *route53.ListTagsForResourceOutput, work controlstate.DNSAuthorityWork) bool {
	if output == nil || output.ResourceTagSet == nil {
		return false
	}
	tags := make(map[string]string, len(output.ResourceTagSet.Tags))
	for _, tag := range output.ResourceTagSet.Tags {
		tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return tags[managedByTagKey] == managedByTagValue && tags[authorityReferenceTagKey] == work.Reference &&
		tags[domainIDTagKey] == work.DomainID && tags[teamIDTagKey] == work.TeamID
}

func isRoute53Error(err error, code string) bool {
	var apiError smithy.APIError
	return errors.As(err, &apiError) && apiError.ErrorCode() == code
}
