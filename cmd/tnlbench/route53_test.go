package main

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
)

type route53Stub struct {
	zones   map[string]string
	records []types.ResourceRecordSet
	changes []*route53.ChangeResourceRecordSetsInput
	deleted []string
}

func (s *route53Stub) CreateHostedZone(context.Context, *route53.CreateHostedZoneInput, ...func(*route53.Options)) (*route53.CreateHostedZoneOutput, error) {
	panic("unexpected CreateHostedZone")
}

func (s *route53Stub) GetHostedZone(_ context.Context, input *route53.GetHostedZoneInput, _ ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error) {
	name, ok := s.zones[aws.ToString(input.Id)]
	if !ok {
		return nil, &smithy.GenericAPIError{Code: "NoSuchHostedZone", Message: "missing"}
	}
	return &route53.GetHostedZoneOutput{HostedZone: &types.HostedZone{
		Id: aws.String(aws.ToString(input.Id)), Name: aws.String(name), Config: &types.HostedZoneConfig{},
	}}, nil
}

func (s *route53Stub) ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: append([]types.ResourceRecordSet(nil), s.records...)}, nil
}

func (s *route53Stub) ChangeResourceRecordSets(_ context.Context, input *route53.ChangeResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	s.changes = append(s.changes, input)
	return &route53.ChangeResourceRecordSetsOutput{}, nil
}

func (s *route53Stub) DeleteHostedZone(_ context.Context, input *route53.DeleteHostedZoneInput, _ ...func(*route53.Options)) (*route53.DeleteHostedZoneOutput, error) {
	s.deleted = append(s.deleted, aws.ToString(input.Id))
	return &route53.DeleteHostedZoneOutput{}, nil
}

func TestDeleteZoneRefusesMismatchedLiveIdentity(t *testing.T) {
	client := &route53Stub{zones: map[string]string{
		"ZPARENT": "bench.example.com.", "ZCHILD": "production.example.com.",
	}}
	err := (benchmarkDNS{client: client}).deleteZone(t.Context(), manifestZone{
		Name: "run.bench.example.com", ID: "ZCHILD", ParentName: "bench.example.com", ParentZoneID: "ZPARENT",
		NameServers: []string{"ns-1.example.net", "ns-2.example.net"},
	})
	if err == nil || len(client.changes) != 0 || len(client.deleted) != 0 {
		t.Fatalf("delete mismatch = %v, changes = %d, deleted = %v", err, len(client.changes), client.deleted)
	}
}

func TestDeleteZoneRemovesOnlyDelegationAndNonDefaultRecords(t *testing.T) {
	client := &route53Stub{
		zones: map[string]string{"ZPARENT": "bench.example.com.", "ZCHILD": "run.bench.example.com."},
		records: []types.ResourceRecordSet{
			*recordSet("run.bench.example.com", types.RRTypeNs, []string{"ns-1.example.net", "ns-2.example.net"}),
			{Name: aws.String("run.bench.example.com."), Type: types.RRTypeSoa},
			*recordSet("control.run.bench.example.com", types.RRTypeA, []string{"192.0.2.10"}),
		},
	}
	err := (benchmarkDNS{client: client}).deleteZone(t.Context(), manifestZone{
		Name: "run.bench.example.com", ID: "ZCHILD", ParentName: "bench.example.com", ParentZoneID: "ZPARENT",
		NameServers: []string{"ns-1.example.net", "ns-2.example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.changes) != 2 || len(client.changes[1].ChangeBatch.Changes) != 1 ||
		client.changes[1].ChangeBatch.Changes[0].ResourceRecordSet.Type != types.RRTypeA {
		t.Fatalf("DNS changes = %#v", client.changes)
	}
	if len(client.deleted) != 1 || client.deleted[0] != "ZCHILD" {
		t.Fatalf("deleted zones = %v", client.deleted)
	}
}
