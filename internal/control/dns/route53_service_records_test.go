package dns

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

func TestRoute53ProviderExactEndpointOwnershipAndZoneBoundaries(t *testing.T) {
	for _, custom := range []bool{false, true} {
		domain, kind := "routes.example.test", "managed"
		if custom {
			domain, kind = "claimed.example.test", "custom"
		}
		for _, scope := range []string{"member", "chase.studio", "preview.chase.studio"} {
			t.Run(kind+"/"+scope, func(t *testing.T) {
				work := testDNSWork(time.Now().UTC())
				work.CanonicalDomain, work.ProviderZoneID = domain, "Z123"
				client, provider := route53TestProvider(t, domain)
				if custom {
					client.get.HostedZone.CallerReference = aws.String(work.Reference)
					client.tags = ownedRoute53Tags(work)
				}
				record := AddressRecord{
					ZoneID: "Z123", ZoneDomain: domain, CustomZone: custom,
					Owner: ServiceOwner("svc_1"), CanonicalHostname: "api." + scope + "." + domain,
					IngressIPv4Addresses: []string{"192.0.2.10"}, IngressIPv6Addresses: []string{"2001:db8::10"},
				}
				if custom {
					record.AuthorityReference, record.TeamID, record.DomainID = work.Reference, work.TeamID, work.DomainID
				}
				if _, err := provider.PublishAddress(t.Context(), record); err != nil {
					t.Fatal(err)
				}
				if len(client.changes) != 3 {
					t.Fatalf("exact publication = %#v", client.changes)
				}
				for index, recordType := range []types.RRType{types.RRTypeTxt, types.RRTypeA, types.RRTypeAaaa} {
					change := client.changes[index]
					name, value, action := record.CanonicalHostname, record.IngressIPv4Addresses[0], types.ChangeActionUpsert
					if recordType == types.RRTypeTxt {
						name, value, action = addressOwnerName(record.CanonicalHostname), record.Owner.marker(), types.ChangeActionCreate
					} else if recordType == types.RRTypeAaaa {
						value = record.IngressIPv6Addresses[0]
					}
					set := change.ResourceRecordSet
					if set == nil || change.Action != action || set.Type != recordType || dnsName(aws.ToString(set.Name)) != dnsName(name) ||
						len(set.ResourceRecords) != 1 || aws.ToString(set.ResourceRecords[0].Value) != value {
						t.Fatalf("exact publication change %d = %#v", index, change)
					}
					stored := *set
					stored.Name = aws.String(dnsName(aws.ToString(set.Name)))
					client.recordSets[dnsName(name)] = append(client.recordSets[dnsName(name)], stored)
				}
				client.changes = nil
				if _, err := provider.PublishAddress(t.Context(), record); err != nil || len(client.changes) != 0 {
					t.Fatalf("unchanged exact endpoint was rewritten: %v, %#v", err, client.changes)
				}
				for _, mismatch := range []string{"foreign owner", "outside zone", "wrong zone domain", "CNAME"} {
					for _, operation := range []string{"publish", "remove"} {
						t.Run(mismatch+"/"+operation, func(t *testing.T) {
							rejected := record
							switch mismatch {
							case "foreign owner":
								rejected.Owner = ServiceOwner("svc_other")
							case "outside zone":
								rejected.CanonicalHostname = "api." + scope + ".not" + domain
							case "wrong zone domain":
								rejected.ZoneDomain = "other." + domain
							case "CNAME":
								key := dnsName(record.CanonicalHostname)
								original := client.recordSets[key]
								client.recordSets[key] = []types.ResourceRecordSet{*simpleRecordSet(record.CanonicalHostname, types.RRTypeCname, []string{"foreign.example.test."})}
								defer func() { client.recordSets[key] = original }()
							}
							var err error
							if operation == "publish" {
								_, err = provider.PublishAddress(t.Context(), rejected)
							} else {
								_, err = provider.RemoveAddress(t.Context(), rejected)
							}
							var terminal *terminalError
							if !errors.As(err, &terminal) || len(client.changes) != 0 {
								t.Fatalf("mismatched exact endpoint mutated DNS: error %v, changes %#v", err, client.changes)
							}
						})
					}
				}
			})
		}
	}
}

type nonemptyServiceZoneStub struct {
	*route53Stub
	deleteCalls  int
	deleteZoneID string
}

func (s *nonemptyServiceZoneStub) DeleteHostedZone(_ context.Context, input *route53.DeleteHostedZoneInput, _ ...func(*route53.Options)) (*route53.DeleteHostedZoneOutput, error) {
	s.deleteCalls++
	s.deleteZoneID = aws.ToString(input.Id)
	return nil, &types.HostedZoneNotEmpty{Message: aws.String("foreign service records remain")}
}

func TestRoute53ProviderExactEndpointRemovalPreservesForeignRecordsAndBlocksZoneRelease(t *testing.T) {
	work := testDNSWork(time.Now().UTC())
	work.ProviderZoneID = "Z123"
	base, _ := route53TestProvider(t, work.CanonicalDomain)
	base.get.HostedZone.CallerReference, base.tags = aws.String(work.Reference), ownedRoute53Tags(work)
	client := &nonemptyServiceZoneStub{route53Stub: base}
	provider, err := NewRoute53Provider(client)
	if err != nil {
		t.Fatal(err)
	}
	const hostname = "api.chase.studio.claimed.example.test"
	const foreignHostname = "api.bob.studio.claimed.example.test"
	record := AddressRecord{
		ZoneID: "Z123", ZoneDomain: work.CanonicalDomain, CustomZone: true,
		AuthorityReference: work.Reference, TeamID: work.TeamID, DomainID: work.DomainID,
		Owner: ServiceOwner("svc_1"), CanonicalHostname: hostname,
	}
	owned := []types.ResourceRecordSet{
		*simpleRecordSet(hostname, types.RRTypeA, []string{"192.0.2.10"}),
		*simpleRecordSet(hostname, types.RRTypeAaaa, []string{"2001:db8::10"}),
	}
	owner := *simpleRecordSet(addressOwnerName(hostname), types.RRTypeTxt, []string{record.Owner.marker()})
	foreign := *simpleRecordSet(foreignHostname, types.RRTypeA, []string{"192.0.2.20"})
	foreignOwner := *simpleRecordSet(addressOwnerName(foreignHostname), types.RRTypeTxt, []string{`"someone-else"`})
	client.recordSets[dnsName(hostname)] = owned
	client.recordSets[dnsName(addressOwnerName(hostname))] = []types.ResourceRecordSet{owner}
	client.recordSets[dnsName(foreignHostname)] = []types.ResourceRecordSet{foreign}
	client.recordSets[dnsName(addressOwnerName(foreignHostname))] = []types.ResourceRecordSet{foreignOwner}
	wildcard := "*." + work.CanonicalDomain
	client.recordSets[dnsName(wildcard)] = []types.ResourceRecordSet{*simpleRecordSet(wildcard, types.RRTypeA, []string{"192.0.2.30"})}
	var changes []types.Change
	client.changeRecords = func(_ context.Context, input *route53.ChangeResourceRecordSetsInput) (*route53.ChangeResourceRecordSetsOutput, error) {
		if aws.ToString(input.HostedZoneId) != "Z123" {
			t.Errorf("changed another zone: %#v", input)
		}
		for _, change := range input.ChangeBatch.Changes {
			changes = append(changes, change)
			if change.Action != types.ChangeActionDelete || change.ResourceRecordSet == nil {
				t.Errorf("unexpected removal change: %#v", change)
				continue
			}
			key := dnsName(aws.ToString(change.ResourceRecordSet.Name))
			sets := client.recordSets[key]
			for index, set := range sets {
				if reflect.DeepEqual(set, *change.ResourceRecordSet) {
					client.recordSets[key] = append(sets[:index:index], sets[index+1:]...)
					break
				}
			}
		}
		return &route53.ChangeResourceRecordSetsOutput{}, nil
	}
	if removed, err := provider.RemoveAddress(t.Context(), record); err != nil || removed.ExactRecordsAbsent {
		t.Fatal("accepted delete was treated as readback", removed, err)
	}
	if removed, err := provider.RemoveAddress(t.Context(), record); err != nil || !removed.ExactRecordsAbsent {
		t.Fatal("provider did not confirm exact removal under a wildcard", removed, err)
	}
	wantChanges := []types.Change{
		{Action: types.ChangeActionDelete, ResourceRecordSet: &owned[0]},
		{Action: types.ChangeActionDelete, ResourceRecordSet: &owned[1]},
		{Action: types.ChangeActionDelete, ResourceRecordSet: &owner},
	}
	if !reflect.DeepEqual(changes, wantChanges) || len(client.recordSets[dnsName(hostname)]) != 0 ||
		len(client.recordSets[dnsName(addressOwnerName(hostname))]) != 0 {
		t.Fatalf("exact endpoint removal = %#v, records %#v", changes, client.recordSets)
	}
	err = provider.ReleaseCustomZone(t.Context(), work)
	var nonempty *types.HostedZoneNotEmpty
	if !errors.As(err, &nonempty) || client.deleteCalls != 1 || client.deleteZoneID != "Z123" || client.deletedZoneID != "" ||
		!reflect.DeepEqual(changes, wantChanges) ||
		len(client.recordSets[dnsName(wildcard)]) != 1 ||
		!reflect.DeepEqual(client.recordSets[dnsName(foreignHostname)], []types.ResourceRecordSet{foreign}) ||
		!reflect.DeepEqual(client.recordSets[dnsName(addressOwnerName(foreignHostname))], []types.ResourceRecordSet{foreignOwner}) {
		t.Fatalf("release changed foreign exact records: error %v, changes %#v, records %#v", err, changes, client.recordSets)
	}
}
