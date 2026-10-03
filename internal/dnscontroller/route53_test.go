package dnscontroller

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestRoute53ProviderCreatesTagsAndReleasesOwnedZone(t *testing.T) {
	work := testDNSWork(time.Now().UTC())
	zone := &types.HostedZone{
		Id: aws.String("/hostedzone/Z123"), Name: aws.String("claimed.example.test."),
		CallerReference: aws.String(work.Reference), Config: &types.HostedZoneConfig{},
	}
	client := &route53Stub{
		created: zone,
		get: &route53.GetHostedZoneOutput{
			HostedZone: zone,
			DelegationSet: &types.DelegationSet{NameServers: []string{
				"NS-2.EXAMPLE.TEST.", "ns-1.example.test.",
			}},
		},
		recordSets: route53ApexRecords(work.CanonicalDomain),
	}
	provider, err := NewRoute53Provider(client)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.EnsureClaimedZone(t.Context(), work)
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != "Z123" || len(result.Nameservers) != 2 || result.Nameservers[0] != "ns-1.example.test" ||
		client.createCalls != 1 || len(client.addedTags) != 4 || client.taggedZoneID != "Z123" || len(client.changes) != 2 {
		t.Fatalf("ensured zone = %#v, client = %#v", result, client)
	}
	for _, change := range client.changes {
		if change.Action != types.ChangeActionUpsert || aws.ToInt64(change.ResourceRecordSet.TTL) != 60 {
			t.Fatalf("apex TTL change = %#v", change)
		}
		if change.ResourceRecordSet.Type == types.RRTypeSoa &&
			aws.ToString(change.ResourceRecordSet.ResourceRecords[0].Value) !=
				"ns-1.example.test. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 60" {
			t.Fatalf("SOA change = %#v", change)
		}
	}
	for _, change := range client.changes {
		index := 0
		if change.ResourceRecordSet.Type == types.RRTypeSoa {
			index = 1
		}
		client.recordSets[dnsName(work.CanonicalDomain)][index] = *change.ResourceRecordSet
	}
	client.changes = nil
	if _, err := provider.EnsureClaimedZone(t.Context(), work); err != nil || len(client.changes) != 0 {
		t.Fatalf("unchanged claimed zone: changes %#v, error %v", client.changes, err)
	}
	client.tags = ownedRoute53Tags(work)
	work.ProviderZoneID = result.ID
	if err := provider.ReleaseClaimedZone(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	if client.deletedZoneID != "Z123" {
		t.Fatalf("deleted zone ID = %q", client.deletedZoneID)
	}
}

func TestRoute53ProviderPreservesClaimedZoneSOAFields(t *testing.T) {
	work := testDNSWork(time.Now().UTC())
	client, provider := route53TestProvider(t, work.CanonicalDomain)
	client.get.HostedZone.CallerReference = aws.String(work.Reference)
	client.created = client.get.HostedZone
	soa := &client.recordSets[dnsName(work.CanonicalDomain)][1]
	soa.TTL = aws.Int64(30)
	soa.ResourceRecords[0].Value = aws.String("ns-1.example.test. hostmaster.example.test. 42 1800 300 604800 86400")
	if _, err := provider.EnsureClaimedZone(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	if len(client.changes) != 2 || client.changes[1].ResourceRecordSet.Type != types.RRTypeSoa ||
		aws.ToInt64(client.changes[1].ResourceRecordSet.TTL) != 30 ||
		aws.ToString(client.changes[1].ResourceRecordSet.ResourceRecords[0].Value) !=
			"ns-1.example.test. hostmaster.example.test. 42 1800 300 604800 60" {
		t.Fatalf("claimed zone apex changes = %#v", client.changes)
	}
}

func TestRoute53ProviderRejectsChangedClaimedZoneNameservers(t *testing.T) {
	work := testDNSWork(time.Now().UTC())
	client, provider := route53TestProvider(t, work.CanonicalDomain)
	client.get.HostedZone.CallerReference = aws.String(work.Reference)
	client.created = client.get.HostedZone
	client.recordSets[dnsName(work.CanonicalDomain)][0].ResourceRecords[0].Value = aws.String("ns-foreign.example.test.")
	if _, err := provider.EnsureClaimedZone(t.Context(), work); err == nil || len(client.changes) != 0 {
		t.Fatalf("changed nameservers: changes %#v, error %v", client.changes, err)
	}
}

func TestRoute53ProviderPublishesAndRemovesOnlyOwnedRouteRecords(t *testing.T) {
	client, provider := route53TestProvider(t, "tunnels.example.test")
	record := PublicURLRecord{
		ZoneID: "Z123", ZoneDomain: "tunnels.example.test",
		PublicURLID: "public_url_0123456789abcdef0123456789abcdef", CanonicalHostname: "api.tunnels.example.test",
		IngressIPv4Addresses: []string{"192.0.2.10"}, IngressIPv6Addresses: []string{"2001:db8::10"},
	}
	if _, err := provider.PublishPublicURL(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if len(client.changes) != 3 || client.changes[0].Action != types.ChangeActionCreate ||
		client.changes[0].ResourceRecordSet.Type != types.RRTypeTxt {
		t.Fatalf("publish changes = %#v", client.changes)
	}
	client.recordSets[dnsName(record.CanonicalHostname)] = []types.ResourceRecordSet{
		*simpleRecordSet(record.CanonicalHostname, types.RRTypeA, record.IngressIPv4Addresses),
		*simpleRecordSet(record.CanonicalHostname, types.RRTypeAaaa, record.IngressIPv6Addresses),
	}
	client.recordSets[dnsName(publicURLOwnerName(record.CanonicalHostname))] = []types.ResourceRecordSet{{
		Name: aws.String(dnsName(publicURLOwnerName(record.CanonicalHostname))), Type: types.RRTypeTxt, TTL: aws.Int64(60),
		ResourceRecords: []types.ResourceRecord{{Value: aws.String(publicURLOwnerValue(record.PublicURLID))}},
	}}
	client.changes = nil
	if _, err := provider.PublishPublicURL(t.Context(), record); err != nil || len(client.changes) != 0 {
		t.Fatalf("unchanged public URL DNS submitted changes: %+v, %v", client.changes, err)
	}
	record.IngressIPv4Addresses = []string{"192.0.2.11"}
	if _, err := provider.PublishPublicURL(t.Context(), record); err != nil || len(client.changes) == 0 {
		t.Fatalf("changed public URL DNS did not submit changes: %+v, %v", client.changes, err)
	}
	client.changes = nil
	if _, err := provider.RemovePublicURL(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if len(client.changes) != 3 {
		t.Fatalf("remove changes = %#v", client.changes)
	}
	for _, change := range client.changes {
		if change.Action != types.ChangeActionDelete {
			t.Fatalf("remove change = %#v", change)
		}
	}
}

func TestRoute53ProviderPublishesMemberWildcardWithoutPerHostOwner(t *testing.T) {
	client, provider := route53TestProvider(t, "tunnels.example.test")
	record := PublicURLRecord{
		ZoneID: "Z123", ZoneDomain: "tunnels.example.test", PublicURLID: "public_url_one",
		CanonicalHostname: "api.member.tunnels.example.test", WildcardHostname: "*.member.tunnels.example.test",
		IngressIPv4Addresses: []string{"192.0.2.10"},
	}
	if _, err := provider.PublishPublicURL(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if len(client.changes) != 2 || client.changes[0].Action != types.ChangeActionUpsert ||
		aws.ToString(client.changes[0].ResourceRecordSet.Name) != "_tnl-wildcard.member.tunnels.example.test." ||
		client.changes[0].ResourceRecordSet.Type != types.RRTypeTxt ||
		client.changes[1].Action != types.ChangeActionUpsert ||
		aws.ToString(client.changes[1].ResourceRecordSet.Name) != "*.member.tunnels.example.test." ||
		client.changes[1].ResourceRecordSet.Type != types.RRTypeA {
		t.Fatalf("wildcard changes = %#v", client.changes)
	}
	client.recordSets[dnsName(memberWildcardOwnerName(record.WildcardHostname))] = []types.ResourceRecordSet{*client.changes[0].ResourceRecordSet}
	client.recordSets[dnsName(record.WildcardHostname)] = []types.ResourceRecordSet{*client.changes[1].ResourceRecordSet}
	client.changes = nil
	record.PublicURLID, record.CanonicalHostname = "public_url_two", "other.member.tunnels.example.test"
	if _, err := provider.PublishPublicURL(t.Context(), record); err != nil || len(client.changes) != 0 {
		t.Fatalf("second member URL changed shared wildcard: %#v, %v", client.changes, err)
	}
	if _, err := provider.RemovePublicURL(t.Context(), record); err == nil || len(client.changes) != 0 {
		t.Fatalf("removed shared wildcard with one public URL: %#v, %v", client.changes, err)
	}
	client.recordSets[dnsName(record.WildcardHostname)] = []types.ResourceRecordSet{
		*simpleRecordSet(record.WildcardHostname, types.RRTypeCname, []string{"foreign.example.test."}),
	}
	if _, err := provider.PublishPublicURL(t.Context(), record); err == nil || len(client.changes) != 0 {
		t.Fatalf("overwrote conflicting wildcard: %#v, %v", client.changes, err)
	}
}

func TestRoute53ProviderReleasesOnlyOwnedClaimedMemberWildcards(t *testing.T) {
	work := testDNSWork(time.Now().UTC())
	work.ProviderZoneID = "Z123"
	client, provider := route53TestProvider(t, work.CanonicalDomain)
	client.get.HostedZone.CallerReference = aws.String(work.Reference)
	client.tags = ownedRoute53Tags(work)
	const wildcard = "*.member.claimed.example.test"
	owner := simpleRecordSet(memberWildcardOwnerName(wildcard), types.RRTypeTxt, []string{memberWildcardOwnerValue(work.DomainID)})
	address := simpleRecordSet(wildcard, types.RRTypeA, []string{"192.0.2.10"})
	foreignOwner := simpleRecordSet("_tnl-wildcard.foreign.claimed.example.test", types.RRTypeTxt, []string{`"someone-else"`})
	client.listRecords = func(_ context.Context, input *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
		switch aws.ToString(input.StartRecordName) {
		case "":
			return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{*foreignOwner},
				IsTruncated: true, NextRecordName: owner.Name, NextRecordType: types.RRTypeTxt}, nil
		case aws.ToString(owner.Name):
			if input.StartRecordType != types.RRTypeTxt {
				t.Errorf("wildcard owner cursor = %#v", input)
			}
			return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{*owner}}, nil
		case dnsName(wildcard):
			return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{*address}}, nil
		}
		t.Errorf("unexpected DNS listing from %#v", input)
		return &route53.ListResourceRecordSetsOutput{}, nil
	}
	if err := provider.ReleaseClaimedZone(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	if client.deletedZoneID != "Z123" || len(client.changes) != 2 ||
		client.changes[0].Action != types.ChangeActionDelete || client.changes[1].Action != types.ChangeActionDelete ||
		aws.ToString(client.changes[0].ResourceRecordSet.Name) != dnsName(wildcard) ||
		aws.ToString(client.changes[1].ResourceRecordSet.Name) != aws.ToString(owner.Name) {
		t.Fatalf("claimed wildcard release = %#v, deleted zone %q", client.changes, client.deletedZoneID)
	}
}

func TestRoute53ProviderPreservesForeignChallengeValuesDuringReplacementAndCleanup(t *testing.T) {
	const recordName = "_acme-challenge.member.tunnels.example.test"
	client, provider := route53TestProvider(t, "tunnels.example.test")
	client.recordSets[dnsName(recordName)] = []types.ResourceRecordSet{*simpleRecordSet(recordName, types.RRTypeTxt, []string{`"foreign"`, `"old-owned"`})}
	record := ChallengeRecord{
		ZoneID: "Z123", ZoneDomain: "tunnels.example.test", RecordName: recordName,
		DesiredOwnedValues: []string{"new-owned"}, PreviouslyOwnedValues: []string{"old-owned", "new-owned"},
	}
	if _, err := provider.ReconcileChallenge(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	values := client.changes[0].ResourceRecordSet.ResourceRecords
	if len(values) != 2 || aws.ToString(values[0].Value) != `"foreign"` || aws.ToString(values[1].Value) != `"new-owned"` {
		t.Fatalf("reconciled challenge values = %#v", values)
	}
	client.recordSets[dnsName(recordName)] = []types.ResourceRecordSet{*client.changes[0].ResourceRecordSet}
	record.DesiredOwnedValues = nil
	if _, err := provider.ReconcileChallenge(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	values = client.changes[0].ResourceRecordSet.ResourceRecords
	if len(values) != 1 || aws.ToString(values[0].Value) != `"foreign"` {
		t.Fatalf("cleaned challenge values = %#v", values)
	}
}

func TestRoute53ProviderDoesNotRewriteUnchangedChallenge(t *testing.T) {
	const recordName = "_acme-challenge.member.tunnels.example.test"
	client, provider := route53TestProvider(t, "tunnels.example.test")
	client.recordSets[dnsName(recordName)] = []types.ResourceRecordSet{
		*simpleRecordSet(recordName, types.RRTypeTxt, []string{`"owned"`, `"foreign"`}),
	}
	record := ChallengeRecord{
		ZoneID: "Z123", ZoneDomain: "tunnels.example.test", RecordName: recordName,
		DesiredOwnedValues: []string{"owned"}, PreviouslyOwnedValues: []string{"owned"},
	}
	if _, err := provider.ReconcileChallenge(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if len(client.changes) != 0 {
		t.Fatalf("unchanged challenge changes = %#v", client.changes)
	}
}

func TestRoute53ProviderWaitsForItsChallengeChange(t *testing.T) {
	client, provider := route53TestProvider(t, "tunnels.example.test")
	record := ChallengeRecord{
		ZoneID: "Z123", ZoneDomain: "tunnels.example.test", RecordName: "_acme-challenge.member.tunnels.example.test",
		DesiredOwnedValues: []string{"owned"}, PreviouslyOwnedValues: []string{"owned"},
	}
	zone, err := provider.ReconcileChallenge(t.Context(), record)
	if err != nil || zone.ChangeID != "/change/test" {
		t.Fatalf("challenge change receipt = %#v, %v", zone, err)
	}
	client.changeStatus = types.ChangeStatusPending
	if ready, err := provider.ChangeReady(t.Context(), zone.ChangeID); err != nil || ready || client.getChangeID != zone.ChangeID {
		t.Fatalf("pending change = %t, queried %q, %v", ready, client.getChangeID, err)
	}
	client.changeStatus = types.ChangeStatusInsync
	if ready, err := provider.ChangeReady(t.Context(), zone.ChangeID); err != nil || !ready {
		t.Fatalf("synced change = %t, %v", ready, err)
	}
	// a lost receipt must be recoverable even when Route 53 already lists
	// the desired TXT record, without changing any foreign TXT values.
	client.recordSets[dnsName(record.RecordName)] = []types.ResourceRecordSet{
		*simpleRecordSet(record.RecordName, types.RRTypeTxt, []string{`"foreign"`, `"owned"`}),
	}
	zone, err = provider.RefreshChallenge(t.Context(), record)
	if err != nil || zone.ChangeID != "/change/test" || len(client.changes) != 1 ||
		len(client.changes[0].ResourceRecordSet.ResourceRecords) != 2 {
		t.Fatalf("recovered change receipt = %#v, writes=%#v, error=%v", zone, client.changes, err)
	}
}

func ownedRoute53Tags(work controlstate.DNSAuthorityWork) []types.Tag {
	return []types.Tag{
		{Key: aws.String(managedByTagKey), Value: aws.String(managedByTagValue)},
		{Key: aws.String(authorityReferenceTagKey), Value: aws.String(work.Reference)},
		{Key: aws.String(domainIDTagKey), Value: aws.String(work.DomainID)},
		{Key: aws.String(teamIDTagKey), Value: aws.String(work.TeamID)},
	}
}

type route53Stub struct {
	created       *types.HostedZone
	get           *route53.GetHostedZoneOutput
	tags          []types.Tag
	addedTags     []types.Tag
	taggedZoneID  string
	deletedZoneID string
	createCalls   int
	recordSets    map[string][]types.ResourceRecordSet
	changes       []types.Change
	createErr     error
	listZones     func(*route53.ListHostedZonesByNameInput) (*route53.ListHostedZonesByNameOutput, error)
	listRecords   func(context.Context, *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error)
	changeRecords func(context.Context, *route53.ChangeResourceRecordSetsInput) (*route53.ChangeResourceRecordSetsOutput, error)
	changeStatus  types.ChangeStatus
	getChangeID   string
}

func (s *route53Stub) CreateHostedZone(
	_ context.Context,
	_ *route53.CreateHostedZoneInput,
	_ ...func(*route53.Options),
) (*route53.CreateHostedZoneOutput, error) {
	s.createCalls++
	return &route53.CreateHostedZoneOutput{HostedZone: s.created}, s.createErr
}

func (s *route53Stub) ListHostedZonesByName(
	_ context.Context,
	input *route53.ListHostedZonesByNameInput,
	_ ...func(*route53.Options),
) (*route53.ListHostedZonesByNameOutput, error) {
	if s.listZones != nil {
		return s.listZones(input)
	}
	return &route53.ListHostedZonesByNameOutput{HostedZones: []types.HostedZone{}, MaxItems: aws.Int32(100)}, nil
}

func (s *route53Stub) GetHostedZone(
	context.Context,
	*route53.GetHostedZoneInput,
	...func(*route53.Options),
) (*route53.GetHostedZoneOutput, error) {
	return s.get, nil
}

func (s *route53Stub) ChangeTagsForResource(
	_ context.Context,
	input *route53.ChangeTagsForResourceInput,
	_ ...func(*route53.Options),
) (*route53.ChangeTagsForResourceOutput, error) {
	s.taggedZoneID = aws.ToString(input.ResourceId)
	s.addedTags = append([]types.Tag(nil), input.AddTags...)
	return &route53.ChangeTagsForResourceOutput{}, nil
}

func (s *route53Stub) ListTagsForResource(
	context.Context,
	*route53.ListTagsForResourceInput,
	...func(*route53.Options),
) (*route53.ListTagsForResourceOutput, error) {
	return &route53.ListTagsForResourceOutput{ResourceTagSet: &types.ResourceTagSet{Tags: s.tags}}, nil
}

func (s *route53Stub) DeleteHostedZone(
	_ context.Context,
	input *route53.DeleteHostedZoneInput,
	_ ...func(*route53.Options),
) (*route53.DeleteHostedZoneOutput, error) {
	s.deletedZoneID = aws.ToString(input.Id)
	return &route53.DeleteHostedZoneOutput{}, nil
}

func (s *route53Stub) ListResourceRecordSets(
	ctx context.Context,
	input *route53.ListResourceRecordSetsInput,
	_ ...func(*route53.Options),
) (*route53.ListResourceRecordSetsOutput, error) {
	if s.listRecords != nil {
		return s.listRecords(ctx, input)
	}
	return &route53.ListResourceRecordSetsOutput{
		ResourceRecordSets: append([]types.ResourceRecordSet(nil), s.recordSets[aws.ToString(input.StartRecordName)]...),
		IsTruncated:        false, MaxItems: aws.Int32(10),
	}, nil
}

func (s *route53Stub) ChangeResourceRecordSets(
	ctx context.Context,
	input *route53.ChangeResourceRecordSetsInput,
	_ ...func(*route53.Options),
) (*route53.ChangeResourceRecordSetsOutput, error) {
	if s.changeRecords != nil {
		return s.changeRecords(ctx, input)
	}
	s.changes = append([]types.Change(nil), input.ChangeBatch.Changes...)
	return &route53.ChangeResourceRecordSetsOutput{ChangeInfo: &types.ChangeInfo{Id: aws.String("/change/test"), Status: types.ChangeStatusPending}}, nil
}

func (s *route53Stub) GetChange(_ context.Context, input *route53.GetChangeInput, _ ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
	s.getChangeID = aws.ToString(input.Id)
	status := s.changeStatus
	if status == "" {
		status = types.ChangeStatusInsync
	}
	return &route53.GetChangeOutput{ChangeInfo: &types.ChangeInfo{Id: aws.String("/change/test"), Status: status}}, nil
}

func route53TestProvider(t *testing.T, domain string) (*route53Stub, *Route53Provider) {
	t.Helper()
	client := &route53Stub{get: &route53.GetHostedZoneOutput{
		HostedZone:    &types.HostedZone{Id: aws.String("Z123"), Name: aws.String(dnsName(domain))},
		DelegationSet: &types.DelegationSet{NameServers: []string{"ns-1.example.test.", "ns-2.example.test."}},
	}, recordSets: route53ApexRecords(domain)}
	provider, err := NewRoute53Provider(client)
	if err != nil {
		t.Fatal(err)
	}
	return client, provider
}

func route53ApexRecords(domain string) map[string][]types.ResourceRecordSet {
	ns := simpleRecordSet(domain, types.RRTypeNs, []string{"ns-1.example.test.", "ns-2.example.test."})
	soa := simpleRecordSet(domain, types.RRTypeSoa, []string{"ns-1.example.test. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"})
	ns.TTL, soa.TTL = aws.Int64(172800), aws.Int64(900)
	return map[string][]types.ResourceRecordSet{dnsName(domain): {*ns, *soa}}
}

func route53TestPublicURL(client *route53Stub) PublicURLRecord {
	record := PublicURLRecord{ZoneID: "Z123", ZoneDomain: "tunnels.example.test", PublicURLID: "public_url_1", CanonicalHostname: "api.tunnels.example.test", IngressIPv4Addresses: []string{"192.0.2.10"}}
	client.recordSets[dnsName(record.CanonicalHostname)] = []types.ResourceRecordSet{*simpleRecordSet(record.CanonicalHostname, types.RRTypeA, append([]string(nil), record.IngressIPv4Addresses...))}
	client.recordSets[dnsName(publicURLOwnerName(record.CanonicalHostname))] = []types.ResourceRecordSet{*simpleRecordSet(publicURLOwnerName(record.CanonicalHostname), types.RRTypeTxt, []string{publicURLOwnerValue(record.PublicURLID)})}
	return record
}
