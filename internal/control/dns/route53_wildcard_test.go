package dns

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

func TestRoute53WildcardNeverAdoptsForeignRecordsOrCrossesDelegation(t *testing.T) {
	const zone, parent = "example.test", "aliases.deployment.example.test"
	record := AddressRecord{ZoneID: "Z123", ZoneDomain: zone, CanonicalHostname: parent,
		Owner: AddressOwner{kind: "alias-wildcard", id: "fixture"}, IngressIPv4Addresses: []string{"192.0.2.10"}}
	for _, conflict := range []string{"unowned matching addresses", "foreign marker", "parent delegation", "ancestor delegation"} {
		t.Run(conflict, func(t *testing.T) {
			client, provider := route53TestProvider(t, zone)
			switch conflict {
			case "unowned matching addresses":
				client.recordSets[dnsName("*."+parent)] = []types.ResourceRecordSet{*simpleRecordSet("*."+parent, types.RRTypeA, record.IngressIPv4Addresses)}
			case "foreign marker":
				name := wildcardOwnerName(parent)
				client.recordSets[dnsName(name)] = []types.ResourceRecordSet{*simpleRecordSet(name, types.RRTypeTxt, []string{`"customer"`})}
			case "parent delegation", "ancestor delegation":
				name := parent
				if conflict == "ancestor delegation" {
					name = "deployment." + zone
				}
				client.recordSets[dnsName(name)] = []types.ResourceRecordSet{*simpleRecordSet(name, types.RRTypeNs, []string{"ns.example.test."})}
			}
			if _, err := provider.ReconcilePublisherAliasWildcard(t.Context(), record, false); err == nil || len(client.changes) != 0 {
				t.Fatal("wildcard work changed foreign DNS", err, client.changes)
			}
		})
	}
}

func TestRoute53WildcardInventoryCoversExactDescendantAndDelegatedShadows(t *testing.T) {
	const zone, parent = "example.test", "aliases.example.test"
	record := AddressRecord{ZoneID: "Z123", ZoneDomain: zone, CanonicalHostname: parent,
		Owner: AddressOwner{kind: "alias-wildcard", id: "fixture"}, IngressIPv4Addresses: []string{"192.0.2.10"}}
	client, provider := route53TestProvider(t, zone)
	first, err := provider.ReconcilePublisherAliasWildcard(t.Context(), record, false)
	if err != nil || first.Settled || len(client.changes) != 2 {
		t.Fatal("publication was not an unsettled wildcard and marker", first, err, client.changes)
	}
	for _, change := range client.changes {
		if change.Action != types.ChangeActionCreate {
			t.Fatal("creation overwrote a customer record")
		}
		key := aws.ToString(change.ResourceRecordSet.Name)
		client.recordSets[key] = []types.ResourceRecordSet{*change.ResourceRecordSet}
	}
	client.changes = nil
	exact := simpleRecordSet("p-exact."+parent, types.RRTypeA, []string{"192.0.2.90"})
	delegated := simpleRecordSet("p-delegated."+parent, types.RRTypeNs, []string{"ns.example.test."})
	receipt := simpleRecordSet("_tnl-owner.p-receipt."+parent, types.RRTypeTxt, []string{`"old"`})
	challenge := simpleRecordSet("_acme-challenge.p-acme."+parent, types.RRTypeTxt, []string{`"challenge"`})
	client.listRecords = func(_ context.Context, input *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
		name := aws.ToString(input.StartRecordName)
		if aws.ToInt32(input.MaxItems) == 300 {
			switch name {
			case dnsName("p-0." + parent):
				return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{*exact, *delegated},
					IsTruncated: true, NextRecordName: receipt.Name, NextRecordType: receipt.Type}, nil
			case aws.ToString(receipt.Name):
				return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{*receipt, *challenge}}, nil
			}
		}
		return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: client.recordSets[name]}, nil
	}
	proof, err := provider.ReconcilePublisherAliasWildcard(t.Context(), record, false)
	if err != nil || !proof.Settled || len(client.changes) != 0 ||
		!slices.Equal(proof.ShadowedLabels, []string{"p-acme", "p-delegated", "p-exact", "p-receipt"}) {
		t.Fatal("verified provider inventory lost an exact-name shadow", proof, err, client.changes)
	}

	// a failed second inventory page must not erase shadows from the first.
	transport := errors.New("fixture Route 53 transport lost")
	list := client.listRecords
	client.listRecords = func(ctx context.Context, input *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
		if aws.ToString(input.StartRecordName) == aws.ToString(receipt.Name) {
			return nil, transport
		}
		return list(ctx, input)
	}
	partial, err := provider.ReconcilePublisherAliasWildcard(t.Context(), record, false)
	if !errors.Is(err, transport) || partial.Settled || partial.Invalid ||
		!slices.Equal(partial.ShadowedLabels, []string{"p-delegated", "p-exact"}) {
		t.Fatal("inconclusive inventory lost known shadows", partial, err)
	}

	// loss of the wildcard itself is known invalidity, even if the next
	// Route 53 call fails before the worker can repair it.
	delete(client.recordSets, dnsName("*."+parent))
	client.listRecords = func(ctx context.Context, input *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
		if aws.ToString(input.StartRecordName) == dnsName(wildcardOwnerName(parent)) {
			return nil, transport
		}
		return list(ctx, input)
	}
	drift, err := provider.ReconcilePublisherAliasWildcard(t.Context(), record, false)
	if !errors.Is(err, transport) || drift.Settled || !drift.Invalid {
		t.Fatal("transport failure erased known invalid wildcard", drift, err)
	}
}
