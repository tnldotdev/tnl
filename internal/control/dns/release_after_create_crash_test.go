package dnscontroller

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

func TestRoute53ReleaseFindsZoneCreatedBeforeAuthoritySave(t *testing.T) {
	for _, tagged := range []bool{false, true} {
		name := "before tagging"
		if tagged {
			name = "after tagging"
		}
		t.Run(name, func(t *testing.T) {
			work := testDNSWork(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))
			zone := &types.HostedZone{
				Id: aws.String("/hostedzone/Z123"), Name: aws.String("claimed.example.test."),
				CallerReference: aws.String(work.Reference),
			}
			client := &route53Stub{
				created:    zone,
				recordSets: route53ApexRecords(work.CanonicalDomain),
				get: &route53.GetHostedZoneOutput{HostedZone: zone, DelegationSet: &types.DelegationSet{
					NameServers: []string{"ns-1.example.test.", "ns-2.example.test."},
				}},
				listZones: func(*route53.ListHostedZonesByNameInput) (*route53.ListHostedZonesByNameOutput, error) {
					return &route53.ListHostedZonesByNameOutput{HostedZones: []types.HostedZone{*zone}}, nil
				},
			}
			provider, err := NewRoute53Provider(client)
			if err != nil {
				t.Fatal(err)
			}
			if tagged {
				if _, err := provider.EnsureCustomZone(t.Context(), work); err != nil {
					t.Fatal(err)
				}
				client.tags = ownedRoute53Tags(work)
			}
			// release begins after a crash, before the returned ID was saved.
			work.State = "releasing"
			if err := provider.ReleaseCustomZone(t.Context(), work); err != nil {
				t.Fatal(err)
			}
			if client.deletedZoneID != "Z123" {
				t.Fatalf("zone created before crash was not released: deleted zone ID = %q, want Z123", client.deletedZoneID)
			}
		})
	}
}
