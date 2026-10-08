package dnscontroller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
)

func TestRoute53ProviderRecoversLostZoneCreateResponseAcrossPages(t *testing.T) {
	work := testDNSWork(time.Now().UTC())
	client, provider := route53TestProvider(t, "claimed.example.test")
	client.get.HostedZone.CallerReference = aws.String(work.Reference)
	client.created, client.createErr = client.get.HostedZone, io.ErrUnexpectedEOF
	if _, err := provider.EnsureCustomZone(t.Context(), work); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("lost create response = %v", err)
	}
	if client.createCalls != 1 || len(client.addedTags) != 0 {
		t.Fatalf("create calls %d, tags %#v", client.createCalls, client.addedTags)
	}
	// the zone exists remotely, but its ID and tags were never persisted locally.
	pages := 0
	client.listZones = func(input *route53.ListHostedZonesByNameInput) (*route53.ListHostedZonesByNameOutput, error) {
		pages++
		if aws.ToString(input.DNSName) != "claimed.example.test." {
			t.Errorf("DNSName = %q", aws.ToString(input.DNSName))
		}
		if pages == 1 {
			if input.HostedZoneId != nil {
				t.Error("first page has a zone cursor")
			}
			return &route53.ListHostedZonesByNameOutput{
				HostedZones: []types.HostedZone{{Id: aws.String("ZFOREIGN"), Name: aws.String("claimed.example.test."), CallerReference: aws.String("foreign")}},
				IsTruncated: true, NextDNSName: aws.String("claimed.example.test."), NextHostedZoneId: aws.String("Z123"),
			}, nil
		}
		if pages != 2 || aws.ToString(input.HostedZoneId) != "Z123" {
			t.Errorf("page %d, cursor %q", pages, aws.ToString(input.HostedZoneId))
		}
		return &route53.ListHostedZonesByNameOutput{HostedZones: []types.HostedZone{*client.created}}, nil
	}
	zone, err := provider.EnsureCustomZone(t.Context(), work)
	if err != nil || zone.ID != "Z123" || pages != 2 || client.createCalls != 1 || len(client.addedTags) != 4 {
		t.Fatalf("recovered zone %#v, error %v, pages %d, creates %d, tags %#v", zone, err, pages, client.createCalls, client.addedTags)
	}
}

func TestRoute53ProviderRejectsConflictsBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*route53Stub, PublicURLRecord)
	}{
		{"unowned_A", func(c *route53Stub, r PublicURLRecord) {
			delete(c.recordSets, dnsName(publicURLOwnerName(r.CanonicalHostname)))
		}},
		{"foreign_owner", func(c *route53Stub, r PublicURLRecord) {
			c.recordSets[dnsName(publicURLOwnerName(r.CanonicalHostname))][0].ResourceRecords[0].Value = aws.String(`"tnl-public-url:foreign"`)
		}},
		{"CNAME", func(c *route53Stub, r PublicURLRecord) {
			c.recordSets[dnsName(r.CanonicalHostname)] = []types.ResourceRecordSet{*simpleRecordSet(r.CanonicalHostname, types.RRTypeCname, []string{"foreign.example.test."})}
		}},
		{"weighted_address", func(c *route53Stub, r PublicURLRecord) {
			c.recordSets[dnsName(r.CanonicalHostname)][0].SetIdentifier = aws.String("weighted")
			c.recordSets[dnsName(r.CanonicalHostname)][0].Weight = aws.Int64(10)
		}},
		{"alias_address", func(c *route53Stub, r PublicURLRecord) {
			c.recordSets[dnsName(r.CanonicalHostname)][0].AliasTarget = &types.AliasTarget{DNSName: aws.String("foreign.example.test."), HostedZoneId: aws.String("ZFOREIGN")}
			c.recordSets[dnsName(r.CanonicalHostname)][0].ResourceRecords = nil
			c.recordSets[dnsName(r.CanonicalHostname)][0].TTL = nil
		}},
		{"weighted_owner", func(c *route53Stub, r PublicURLRecord) {
			c.recordSets[dnsName(publicURLOwnerName(r.CanonicalHostname))][0].SetIdentifier = aws.String("weighted")
		}},
	} {
		for _, operation := range []string{"publish", "remove"} {
			t.Run(test.name+"/"+operation, func(t *testing.T) {
				client, provider := route53TestProvider(t, "tunnels.example.test")
				record := route53TestPublicURL(client)
				test.change(client, record)
				var err error
				if operation == "publish" {
					_, err = provider.PublishPublicURL(t.Context(), record)
				} else {
					_, err = provider.RemovePublicURL(t.Context(), record)
				}
				var terminal *terminalError
				if !errors.As(err, &terminal) || len(client.changes) != 0 {
					t.Fatalf("conflicting %s: error %v, changes %#v", operation, err, client.changes)
				}
			})
		}
	}
}

func TestRoute53ProviderChecksCustomZoneIdentityAndTags(t *testing.T) {
	for _, mismatch := range []string{"caller", "name", "private", "linked", managedByTagKey, authorityReferenceTagKey, domainIDTagKey, teamIDTagKey} {
		for _, operation := range []string{"publish", "challenge", "release"} {
			t.Run(mismatch+"/"+operation, func(t *testing.T) {
				work := testDNSWork(time.Now().UTC())
				work.ProviderZoneID = "Z123"
				client, provider := route53TestProvider(t, work.CanonicalDomain)
				client.get.HostedZone.CallerReference = aws.String(work.Reference)
				client.tags = ownedRoute53Tags(work)
				switch mismatch {
				case "caller":
					client.get.HostedZone.CallerReference = aws.String("foreign")
				case "name":
					client.get.HostedZone.Name = aws.String("foreign.example.test.")
				case "private":
					client.get.HostedZone.Config = &types.HostedZoneConfig{PrivateZone: true}
				case "linked":
					client.get.HostedZone.LinkedService = &types.LinkedService{ServicePrincipal: aws.String("foreign")}
				default:
					for i := range client.tags {
						if aws.ToString(client.tags[i].Key) == mismatch {
							client.tags[i].Value = aws.String("foreign")
						}
					}
				}
				record := PublicURLRecord{ZoneID: "Z123", ZoneDomain: work.CanonicalDomain, CustomZone: true, AuthorityReference: work.Reference, TeamID: work.TeamID, DomainID: work.DomainID, PublicURLID: "public_url_1", CanonicalHostname: "api." + work.CanonicalDomain, IngressIPv4Addresses: []string{"192.0.2.10"}}
				var err error
				switch operation {
				case "publish":
					_, err = provider.PublishPublicURL(t.Context(), record)
				case "challenge":
					_, err = provider.ReconcileChallenge(t.Context(), ChallengeRecord{ZoneID: record.ZoneID, ZoneDomain: record.ZoneDomain, CustomZone: true, AuthorityReference: record.AuthorityReference, TeamID: record.TeamID, DomainID: record.DomainID, RecordName: "_acme-challenge." + record.CanonicalHostname, DesiredOwnedValues: []string{"owned"}})
				case "release":
					err = provider.ReleaseCustomZone(t.Context(), work)
				}
				var terminal *terminalError
				if !errors.As(err, &terminal) || len(client.changes) != 0 || client.deletedZoneID != "" {
					t.Fatalf("ownership mismatch: error %v, changes %#v, deleted %q", err, client.changes, client.deletedZoneID)
				}
			})
		}
	}
}

func TestRoute53ProviderRejectsChallengeNameConflicts(t *testing.T) {
	for _, conflict := range []string{"CNAME", "routing_policy", "multiple_TXT", "paginated_routing_policy"} {
		t.Run(conflict, func(t *testing.T) {
			client, provider := route53TestProvider(t, "tunnels.example.test")
			const name = "_acme-challenge.api.tunnels.example.test"
			set := simpleRecordSet(name, types.RRTypeTxt, []string{`"foreign"`})
			switch conflict {
			case "CNAME":
				set = simpleRecordSet(name, types.RRTypeCname, []string{"foreign.example.test."})
			case "routing_policy":
				set.SetIdentifier, set.Weight = aws.String("foreign"), aws.Int64(10)
			case "multiple_TXT":
				client.recordSets[dnsName(name)] = []types.ResourceRecordSet{*set, *simpleRecordSet(name, types.RRTypeTxt, []string{`"other"`})}
			case "paginated_routing_policy":
				pages := 0
				client.listRecords = func(_ context.Context, input *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
					pages++
					if aws.ToString(input.HostedZoneId) != "Z123" || aws.ToString(input.StartRecordName) != dnsName(name) {
						t.Errorf("list input %#v", input)
					}
					if pages == 1 {
						return &route53.ListResourceRecordSetsOutput{
							ResourceRecordSets: []types.ResourceRecordSet{*simpleRecordSet(name, types.RRTypeA, []string{"192.0.2.1"})},
							IsTruncated:        true, NextRecordName: aws.String(dnsName(name)), NextRecordType: types.RRTypeTxt,
						}, nil
					}
					if input.StartRecordType != types.RRTypeTxt {
						t.Errorf("pagination cursor %#v", input)
					}
					set.SetIdentifier, set.Weight = aws.String("foreign"), aws.Int64(10)
					return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{*set}}, nil
				}
				t.Cleanup(func() {
					if pages != 2 {
						t.Errorf("listed %d record-set pages", pages)
					}
				})
			}
			if conflict != "multiple_TXT" && conflict != "paginated_routing_policy" {
				client.recordSets[dnsName(name)] = []types.ResourceRecordSet{*set}
			}
			_, err := provider.ReconcileChallenge(t.Context(), ChallengeRecord{ZoneID: "Z123", ZoneDomain: "tunnels.example.test", RecordName: name, DesiredOwnedValues: []string{"owned"}})
			var terminal *terminalError
			if !errors.As(err, &terminal) || len(client.changes) != 0 {
				t.Fatalf("challenge conflict: error %v, changes %#v", err, client.changes)
			}
		})
	}
}

func TestRoute53ProviderRemovesAddressFamilyAndSupportsAAAAOnly(t *testing.T) {
	for _, family := range []types.RRType{types.RRTypeA, types.RRTypeAaaa} {
		t.Run(string(family), func(t *testing.T) {
			client, provider := route53TestProvider(t, "tunnels.example.test")
			record := route53TestPublicURL(client)
			client.recordSets[dnsName(record.CanonicalHostname)] = append(client.recordSets[dnsName(record.CanonicalHostname)], *simpleRecordSet(record.CanonicalHostname, types.RRTypeAaaa, []string{"2001:db8::10"}))
			if family == types.RRTypeA {
				record.IngressIPv4Addresses = nil
				record.IngressIPv6Addresses = []string{"2001:db8::20"}
			}
			if _, err := provider.PublishPublicURL(t.Context(), record); err != nil {
				t.Fatal(err)
			}
			if len(client.changes) != 3 {
				t.Fatalf("changes %#v", client.changes)
			}
			deletions := 0
			wantValue := "192.0.2.10"
			if family == types.RRTypeAaaa {
				wantValue = "2001:db8::10"
			}
			for _, change := range client.changes {
				if change.ResourceRecordSet.Type != family {
					continue
				}
				if change.Action != types.ChangeActionDelete || len(change.ResourceRecordSet.ResourceRecords) != 1 ||
					aws.ToString(change.ResourceRecordSet.Name) != "api.tunnels.example.test." ||
					aws.ToString(change.ResourceRecordSet.ResourceRecords[0].Value) != wantValue {
					t.Fatalf("removed family %#v", change)
				}
				deletions++
			}
			if deletions != 1 {
				t.Fatalf("matching deletions = %d, changes %#v", deletions, client.changes)
			}
		})
	}
	client, provider := route53TestProvider(t, "tunnels.example.test")
	record := route53TestPublicURL(client)
	client.recordSets = map[string][]types.ResourceRecordSet{}
	record.IngressIPv4Addresses, record.IngressIPv6Addresses = nil, []string{"2001:db8::10"}
	if _, err := provider.PublishPublicURL(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if len(client.changes) != 2 || client.changes[1].ResourceRecordSet.Type != types.RRTypeAaaa {
		t.Fatalf("AAAA-only changes %#v", client.changes)
	}
}

func TestRoute53ProviderReleaseHTTPResponseRecovery(t *testing.T) {
	for _, mode := range []string{"absent", "nonempty", "lost_delete_response"} {
		t.Run(mode, func(t *testing.T) {
			work := testDNSWork(time.Now().UTC())
			work.ProviderZoneID = "/hostedzone/Z123"
			var absent atomic.Bool
			absent.Store(mode == "absent")
			var deletes, tagReads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/xml")
				switch r.Method + " " + r.URL.Path {
				case "GET /2013-04-01/hostedzone/Z123":
					if absent.Load() {
						w.WriteHeader(http.StatusNotFound)
						_, _ = io.WriteString(w, `<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><Error><Type>Sender</Type><Code>NoSuchHostedZone</Code><Message>Zone is absent</Message></Error><RequestId>test</RequestId></ErrorResponse>`)
						return
					}
					_, _ = fmt.Fprintf(w, `<GetHostedZoneResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZone><Id>/hostedzone/Z123</Id><Name>claimed.example.test.</Name><CallerReference>%s</CallerReference><Config><PrivateZone>false</PrivateZone></Config></HostedZone></GetHostedZoneResponse>`, work.Reference)
				case "GET /2013-04-01/tags/hostedzone/Z123":
					tagReads.Add(1)
					_, _ = io.WriteString(w, `<ListTagsForResourceResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceTagSet><ResourceType>hostedzone</ResourceType><ResourceId>Z123</ResourceId><Tags>`)
					for _, tag := range ownedRoute53Tags(work) {
						_, _ = fmt.Fprintf(w, `<Tag><Key>%s</Key><Value>%s</Value></Tag>`, aws.ToString(tag.Key), aws.ToString(tag.Value))
					}
					_, _ = io.WriteString(w, `</Tags></ResourceTagSet></ListTagsForResourceResponse>`)
				case "GET /2013-04-01/hostedzone/Z123/rrset":
					_, _ = io.WriteString(w, `<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>`)
				case "DELETE /2013-04-01/hostedzone/Z123":
					deletes.Add(1)
					if mode == "nonempty" {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = io.WriteString(w, `<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><Error><Type>Sender</Type><Code>HostedZoneNotEmpty</Code><Message>Foreign records remain</Message></Error><RequestId>test</RequestId></ErrorResponse>`)
						return
					}
					absent.Store(true)
					// the delete took effect, but the response was cut off in transit.
					_, _ = io.WriteString(w, `<DeleteHostedZoneResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeInfo>`)
				default:
					t.Errorf("unexpected Route 53 request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			t.Cleanup(server.Close)
			client := route53.New(route53.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), Retryer: aws.NopRetryer{}, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
			})})
			provider, err := NewRoute53Provider(client)
			if err != nil {
				t.Fatal(err)
			}
			err = provider.ReleaseCustomZone(t.Context(), work)
			switch mode {
			case "absent":
				if err != nil || deletes.Load() != 0 || tagReads.Load() != 0 {
					t.Fatalf("absent release: error %v, deletes %d, tags %d", err, deletes.Load(), tagReads.Load())
				}
			case "nonempty":
				var apiError smithy.APIError
				if !errors.As(err, &apiError) || apiError.ErrorCode() != "HostedZoneNotEmpty" || deletes.Load() != 1 || tagReads.Load() != 1 || absent.Load() {
					t.Fatalf("nonempty release: error %v, deletes %d, tags %d", err, deletes.Load(), tagReads.Load())
				}
			case "lost_delete_response":
				if err == nil || !absent.Load() || deletes.Load() != 1 {
					t.Fatalf("lost response: error %v, deleted %v, calls %d", err, absent.Load(), deletes.Load())
				}
				if err := provider.ReleaseCustomZone(t.Context(), work); err != nil || deletes.Load() != 1 || tagReads.Load() != 1 {
					t.Fatalf("release retry: error %v, deletes %d, tags %d", err, deletes.Load(), tagReads.Load())
				}
			}
		})
	}
}

func TestRoute53ProviderCleanupRetriesLostRecordResponse(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		name := "owned_only"
		if foreign {
			name = "foreign_TXT"
		}
		t.Run(name, func(t *testing.T) {
			client, provider := route53TestProvider(t, "tunnels.example.test")
			record := ChallengeRecord{ZoneID: "Z123", ZoneDomain: "tunnels.example.test", RecordName: "_acme-challenge.api.tunnels.example.test", PreviouslyOwnedValues: []string{"owned"}}
			values := []string{`"owned"`}
			if foreign {
				values = append(values, `"foreign"`)
			}
			client.recordSets[dnsName(record.RecordName)] = []types.ResourceRecordSet{*simpleRecordSet(record.RecordName, types.RRTypeTxt, values)}
			calls := 0
			client.changeRecords = func(_ context.Context, input *route53.ChangeResourceRecordSetsInput) (*route53.ChangeResourceRecordSetsOutput, error) {
				calls++
				change := input.ChangeBatch.Changes[0]
				if change.Action == types.ChangeActionDelete {
					delete(client.recordSets, dnsName(record.RecordName))
				} else {
					client.recordSets[dnsName(record.RecordName)] = []types.ResourceRecordSet{*change.ResourceRecordSet}
				}
				if calls == 1 {
					return nil, io.ErrUnexpectedEOF
				}
				return &route53.ChangeResourceRecordSetsOutput{}, nil
			}
			if _, err := provider.ReconcileChallenge(t.Context(), record); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("lost cleanup response = %v", err)
			}
			if _, err := provider.ReconcileChallenge(t.Context(), record); err != nil {
				t.Fatal(err)
			}
			sets := client.recordSets[dnsName(record.RecordName)]
			if foreign {
				if len(sets) != 1 || len(sets[0].ResourceRecords) != 1 || aws.ToString(sets[0].ResourceRecords[0].Value) != `"foreign"` {
					t.Fatalf("foreign TXT after retry %#v", sets)
				}
			} else if len(sets) != 0 || calls != 1 {
				t.Fatalf("absent record retry: sets %#v, writes %d", sets, calls)
			}
		})
	}
}
