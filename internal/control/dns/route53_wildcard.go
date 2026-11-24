package dns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/tnldotdev/tnl/internal/naming"
)

func (p *Route53Provider) ReconcilePublisherAliasWildcard(ctx context.Context, record AddressRecord, removing bool) (PublisherAliasWildcardRecords, error) {
	var result PublisherAliasWildcardRecords
	marker := record.Owner.marker()
	parent := record.CanonicalHostname
	if record.Owner.kind != "alias-wildcard" || marker == "" || !naming.ValidGeneratedHostnameParent(parent) ||
		!strings.HasSuffix(parent, "."+record.ZoneDomain) {
		return result, terminalf("publisher alias wildcard has invalid ownership or DNS parent")
	}
	zone, err := p.addressZone(ctx, record)
	if err != nil {
		return result, err
	}
	result.Zone = zone
	wildcard, ownerName := "*."+parent, wildcardOwnerName(parent)
	wildcardSets, err := p.listRecordSets(ctx, zone.ID, wildcard)
	if err != nil {
		return result, err
	}
	ownerSets, err := p.listRecordSets(ctx, zone.ID, ownerName)
	if err != nil {
		return result, err
	}
	owned := len(ownerSets) == 1 && ownerSets[0].Type == types.RRTypeTxt && plainRecordSet(&ownerSets[0]) &&
		len(ownerSets[0].ResourceRecords) == 1 && aws.ToString(ownerSets[0].ResourceRecords[0].Value) == marker
	if !owned && (len(ownerSets) != 0 || len(wildcardSets) != 0) {
		if removing && !hasWildcardOwnerValue(ownerSets, marker) {
			// a failed create may have found unrelated DNS. withdraw only
			// our proof; never make domain transfer depend on deleting it.
			result.Settled = true
			return result, nil
		}
		return result, terminalf("publisher alias wildcard or its ownership name has unowned records")
	}
	byType := make(map[types.RRType]*types.ResourceRecordSet, 2)
	for i := range wildcardSets {
		set := &wildcardSets[i]
		if !plainRecordSet(set) || set.Type != types.RRTypeA && set.Type != types.RRTypeAaaa || byType[set.Type] != nil {
			return result, terminalf("publisher alias wildcard has conflicting record sets")
		}
		byType[set.Type] = set
	}
	if removing && !owned {
		result.Settled = true
		return result, nil
	}
	if !removing {
		// a child zone can share nameserver IPs with its parent, so an
		// authoritative-looking reply does not by itself prove no zone cut.
		for name := parent; name != record.ZoneDomain; {
			atName, err := p.listRecordSets(ctx, zone.ID, name)
			if err != nil {
				return result, err
			}
			for _, set := range atName {
				if set.Type == types.RRTypeNs || set.Type == "DNAME" {
					return result, terminalf("publisher alias wildcard is beneath a delegation or redirection")
				}
			}
			_, name, _ = strings.Cut(name, ".")
		}
		if owned && wildcardAddressesMatch(byType[types.RRTypeA], record.IngressIPv4Addresses) &&
			wildcardAddressesMatch(byType[types.RRTypeAaaa], record.IngressIPv6Addresses) {
			result.ShadowedLabels, err = p.publisherAliasShadows(ctx, zone.ID, parent)
			result.Settled = err == nil
			return result, err
		}
	}
	// the batch compares exact RRsets on deletion and uses CREATE for new
	// RRsets. concurrent foreign writes fail the batch rather than get replaced.
	changes := make([]types.Change, 0, 6)
	for i := range wildcardSets {
		changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: &wildcardSets[i]})
	}
	if owned {
		changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: &ownerSets[0]})
	}
	if !removing {
		changes = append(changes, types.Change{Action: types.ChangeActionCreate,
			ResourceRecordSet: simpleRecordSet(ownerName, types.RRTypeTxt, []string{marker})})
		if len(record.IngressIPv4Addresses) > 0 {
			changes = append(changes, types.Change{Action: types.ChangeActionCreate,
				ResourceRecordSet: simpleRecordSet(wildcard, types.RRTypeA, record.IngressIPv4Addresses)})
		}
		if len(record.IngressIPv6Addresses) > 0 {
			changes = append(changes, types.Change{Action: types.ChangeActionCreate,
				ResourceRecordSet: simpleRecordSet(wildcard, types.RRTypeAaaa, record.IngressIPv6Addresses)})
		}
	}
	if _, err := p.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zone.ID),
		ChangeBatch:  &types.ChangeBatch{Comment: aws.String("reconcile tnl publisher alias wildcard"), Changes: changes},
	}); err != nil {
		return result, fmt.Errorf("dnscontroller: reconcile Route 53 publisher alias wildcard: %w", err)
	}
	return result, nil
}

func hasWildcardOwnerValue(sets []types.ResourceRecordSet, marker string) bool {
	for _, set := range sets {
		if set.Type == types.RRTypeTxt {
			for _, record := range set.ResourceRecords {
				if aws.ToString(record.Value) == marker {
					return true
				}
			}
		}
	}
	return false
}

func wildcardAddressesMatch(set *types.ResourceRecordSet, wanted []string) bool {
	if len(wanted) == 0 {
		return set == nil
	}
	if set == nil || aws.ToInt64(set.TTL) != 60 || len(set.ResourceRecords) != 1 || len(wanted) != 1 {
		return false
	}
	actual, err := netip.ParseAddr(aws.ToString(set.ResourceRecords[0].Value))
	return err == nil && actual.String() == wanted[0]
}

// any RRset at or below a prospective alias makes that name exist. in
// particular, TXT ownership receipts and ACME records can create empty
// nonterminals without an A or AAAA set at the alias itself.
func (p *Route53Provider) publisherAliasShadows(ctx context.Context, zoneID, parent string) ([]string, error) {
	suffix := "." + dnsName(parent)
	// Route 53 sorts on reversed labels. start inside the alias label range,
	// not at the parent: a neighboring name can sort between a parent and
	// its children when a special character sorts before the label separator.
	input := &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String(zoneID),
		StartRecordName: aws.String(dnsName("p-0." + parent)), MaxItems: aws.Int32(300)}
	shadows := make(map[string]struct{})
	for range 50 {
		output, err := p.client.ListResourceRecordSets(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("dnscontroller: inventory Route 53 publisher alias parent: %w", err)
		}
		if output == nil {
			return nil, terminalf("publisher alias parent inventory has no response")
		}
		for _, set := range output.ResourceRecordSets {
			name := route53RecordName(aws.ToString(set.Name))
			relative, ok := strings.CutSuffix(name, suffix)
			if !ok {
				return mapKeys(shadows), nil
			}
			relative = relative[strings.LastIndex(relative, ".")+1:]
			if !strings.HasPrefix(relative, "p-") {
				return mapKeys(shadows), nil
			}
			shadows[relative] = struct{}{}
		}
		if !output.IsTruncated {
			return mapKeys(shadows), nil
		}
		input.StartRecordName, input.StartRecordType, input.StartRecordIdentifier = output.NextRecordName, output.NextRecordType, output.NextRecordIdentifier
	}
	return nil, terminalf("publisher alias parent inventory exceeds the work limit")
}
