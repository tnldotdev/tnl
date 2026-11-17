package state_test

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/tnldotdev/tnl/internal/control/dns"
	"github.com/tnldotdev/tnl/internal/control/state"
)

func TestIntegrationServiceEndpointDNSHandoffPreservesCleanupOwner(t *testing.T) {
	for _, cleanupFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanup_first_%t", cleanupFirst), func(t *testing.T) {
			var client *endpointRoute53Records
			var provider *dns.Route53Provider
			state.ExerciseServiceEndpointDNSHandoff(t, cleanupFirst, func(removing bool, domain string, work state.ServiceEndpointDNSWork) error {
				if provider == nil {
					client = &endpointRoute53Records{domain: domain, records: make(map[string][]types.ResourceRecordSet)}
					var err error
					provider, err = dns.NewRoute53Provider(client)
					if err != nil {
						return err
					}
				}
				record := dns.AddressRecord{ZoneID: "ZENDPOINT", ZoneDomain: domain,
					Owner: dns.ServiceOwner(work.OwnerID), CanonicalHostname: work.Hostname,
					IngressIPv4Addresses: []string{"192.0.2.10"}}
				if removing {
					_, err := provider.RemoveAddress(t.Context(), record)
					if err == nil && client.marker(work.Hostname) != "" {
						t.Fatal("successful predecessor removal retained the ownership marker")
					}
					return err
				}
				if _, err := provider.PublishAddress(t.Context(), record); err != nil {
					return err
				}
				expected := strconv.Quote("tnl-service:" + work.OwnerID)
				if client.marker(work.Hostname) != expected {
					t.Fatal("provider did not persist the exact service ownership marker", client.marker(work.Hostname), expected)
				}
				// the fix must not weaken the provider's separate foreign-owner
				// protection to make replacement publication succeed.
				foreign := record
				foreign.Owner = dns.ServiceOwner("foreign-service")
				writes := client.writes
				_, publishErr := provider.PublishAddress(t.Context(), foreign)
				_, removeErr := provider.RemoveAddress(t.Context(), foreign)
				if publishErr == nil || removeErr == nil ||
					!strings.Contains(publishErr.Error(), "ownership marker does not match") ||
					!strings.Contains(removeErr.Error(), "ownership marker does not match") ||
					client.writes != writes || client.marker(work.Hostname) != expected {
					t.Fatal("foreign owner changed provider records", publishErr, removeErr)
				}
				return nil
			})
		})
	}
}

// only managed-zone address operations are used. unexpected embedded methods
// cannot reach a configured AWS client.
type endpointRoute53Records struct {
	*route53.Client
	domain  string
	records map[string][]types.ResourceRecordSet
	writes  int
}

func endpointDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".") + "."
}

func (s *endpointRoute53Records) marker(hostname string) string {
	for _, set := range s.records[endpointDNSName("_tnl-owner."+hostname)] {
		if set.Type == types.RRTypeTxt && len(set.ResourceRecords) == 1 {
			return aws.ToString(set.ResourceRecords[0].Value)
		}
	}
	return ""
}

func (s *endpointRoute53Records) GetHostedZone(context.Context, *route53.GetHostedZoneInput, ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error) {
	return &route53.GetHostedZoneOutput{
		HostedZone:    &types.HostedZone{Id: aws.String("ZENDPOINT"), Name: aws.String(endpointDNSName(s.domain))},
		DelegationSet: &types.DelegationSet{NameServers: []string{"ns-1.example.test.", "ns-2.example.test."}},
	}, nil
}

func (s *endpointRoute53Records) ListResourceRecordSets(_ context.Context, input *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	return &route53.ListResourceRecordSetsOutput{
		ResourceRecordSets: append([]types.ResourceRecordSet(nil), s.records[endpointDNSName(aws.ToString(input.StartRecordName))]...),
	}, nil
}

func (s *endpointRoute53Records) ChangeResourceRecordSets(_ context.Context, input *route53.ChangeResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	for _, change := range input.ChangeBatch.Changes {
		if change.ResourceRecordSet == nil {
			return nil, fmt.Errorf("record change has no record set")
		}
		key := endpointDNSName(aws.ToString(change.ResourceRecordSet.Name))
		set := *change.ResourceRecordSet
		set.Name = aws.String(key)
		existing := s.records[key]
		index := -1
		for i, old := range existing {
			if old.Type == set.Type {
				index = i
				break
			}
		}
		switch change.Action {
		case types.ChangeActionCreate:
			if index >= 0 {
				return nil, fmt.Errorf("record already exists")
			}
			s.records[key] = append(existing, set)
		case types.ChangeActionUpsert:
			if index < 0 {
				s.records[key] = append(existing, set)
			} else {
				existing[index] = set
			}
		case types.ChangeActionDelete:
			if index < 0 || !reflect.DeepEqual(existing[index], set) {
				return nil, fmt.Errorf("delete does not match the existing record")
			}
			s.records[key] = append(existing[:index:index], existing[index+1:]...)
		default:
			return nil, fmt.Errorf("unsupported record action %s", change.Action)
		}
		s.writes++
	}
	return &route53.ChangeResourceRecordSetsOutput{
		ChangeInfo: &types.ChangeInfo{Id: aws.String("/change/endpoint"), Status: types.ChangeStatusInsync},
	}, nil
}
