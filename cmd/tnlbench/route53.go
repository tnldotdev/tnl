package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
)

type benchmarkRoute53API interface {
	CreateHostedZone(context.Context, *route53.CreateHostedZoneInput, ...func(*route53.Options)) (*route53.CreateHostedZoneOutput, error)
	GetHostedZone(context.Context, *route53.GetHostedZoneInput, ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error)
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(context.Context, *route53.ChangeResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
	DeleteHostedZone(context.Context, *route53.DeleteHostedZoneInput, ...func(*route53.Options)) (*route53.DeleteHostedZoneOutput, error)
}

type benchmarkDNS struct{ client benchmarkRoute53API }

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
	for _, record := range []struct {
		typeName types.RRType
		values   []string
	}{{types.RRTypeA, ipv4}, {types.RRTypeAaaa, ipv6}} {
		if len(record.values) == 0 {
			continue
		}
		if err := d.changeRecord(ctx, zoneID, types.ChangeActionUpsert, recordSet(hostname, record.typeName, record.values)); err != nil {
			return err
		}
	}
	return nil
}

func (d benchmarkDNS) changeRecord(ctx context.Context, zoneID string, action types.ChangeAction, record *types.ResourceRecordSet) error {
	_, err := d.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &types.ChangeBatch{Comment: aws.String("transient tnl benchmark"), Changes: []types.Change{{
			Action: action, ResourceRecordSet: record,
		}}},
	})
	if err != nil {
		return fmt.Errorf("change benchmark DNS record %s: %w", aws.ToString(record.Name), err)
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
		if _, err := d.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
			HostedZoneId: aws.String(zone.ID), ChangeBatch: &types.ChangeBatch{Changes: changes},
		}); err != nil && !route53Error(err, "NoSuchHostedZone") {
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
