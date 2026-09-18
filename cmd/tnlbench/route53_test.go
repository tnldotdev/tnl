package main

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
	mdns "github.com/miekg/dns"
)

type resolverStub struct {
	nameServers     []*net.NS
	addresses       []netip.Addr
	nameServerReads int
	addressReads    int
}

func (s *resolverStub) LookupNS(context.Context, string) ([]*net.NS, error) {
	s.nameServerReads++
	return append([]*net.NS(nil), s.nameServers...), nil
}

func (s *resolverStub) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	s.addressReads++
	return append([]netip.Addr(nil), s.addresses...), nil
}

type route53Stub struct {
	zones       map[string]string
	nameServers map[string][]string
	records     []types.ResourceRecordSet
	changes     []*route53.ChangeResourceRecordSetsInput
	deleted     []string
}

func (s *route53Stub) CreateHostedZone(context.Context, *route53.CreateHostedZoneInput, ...func(*route53.Options)) (*route53.CreateHostedZoneOutput, error) {
	panic("unexpected CreateHostedZone")
}

func (s *route53Stub) GetHostedZone(_ context.Context, input *route53.GetHostedZoneInput, _ ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error) {
	name, ok := s.zones[aws.ToString(input.Id)]
	if !ok {
		return nil, &smithy.GenericAPIError{Code: "NoSuchHostedZone", Message: "missing"}
	}
	return &route53.GetHostedZoneOutput{
		HostedZone: &types.HostedZone{
			Id: aws.String(aws.ToString(input.Id)), Name: aws.String(name), Config: &types.HostedZoneConfig{},
		},
		DelegationSet: &types.DelegationSet{NameServers: append([]string(nil), s.nameServers[aws.ToString(input.Id)]...)},
	}, nil
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

func TestHostedZoneNameServersReturnsCanonicalSortedDelegation(t *testing.T) {
	client := &route53Stub{
		zones: map[string]string{"ZPARENT": "bench.example.com."},
		nameServers: map[string][]string{
			"ZPARENT": {"NS-2.EXAMPLE.NET.", "ns-1.example.net."},
		},
	}
	nameServers, err := (benchmarkDNS{client: client}).hostedZoneNameServers(t.Context(), "ZPARENT")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(nameServers, []string{"ns-1.example.net", "ns-2.example.net"}) {
		t.Fatalf("name servers = %v", nameServers)
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

func TestUpsertAddressBatchesRoute53Change(t *testing.T) {
	client := &route53Stub{}
	err := (benchmarkDNS{client: client}).upsertAddress(
		t.Context(), "ZCHILD", "control.run.bench.example.com", []string{"192.0.2.10"}, []string{"2001:db8::10"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.changes) != 1 || len(client.changes[0].ChangeBatch.Changes) != 2 {
		t.Fatalf("DNS changes = %#v", client.changes)
	}
}

func TestWaitForAuthoritativeBenchmarkDNS(t *testing.T) {
	resolver := &resolverStub{
		nameServers: []*net.NS{{Host: "ns-2.example.net."}, {Host: "ns-1.example.net."}},
		addresses:   []netip.Addr{netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("192.0.2.10")},
	}
	dns := benchmarkDNS{resolver: resolver}
	zone := manifestZone{
		Name: "run.bench.example.com", NameServers: []string{"ns-1.example.net", "ns-2.example.net"},
	}
	if err := dns.waitDelegation(t.Context(), []string{"parent-ns-1.example.net", "parent-ns-2.example.net"}, zone, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := dns.waitAddresses(
		t.Context(), []string{"ns-1.example.net", "ns-2.example.net"}, "control.run.bench.example.com",
		[]string{"192.0.2.10"}, []string{"2001:db8::10"}, time.Second,
	); err != nil {
		t.Fatal(err)
	}
	if resolver.nameServerReads != 2 || resolver.addressReads != 2 {
		t.Fatalf("authoritative reads = %d NS and %d address, want 2 each", resolver.nameServerReads, resolver.addressReads)
	}
}

func TestAuthoritativeDNSQueriesAcceptParentReferralAndAddressAnswers(t *testing.T) {
	server := benchmarkDNSServer(t, func(request *mdns.Msg) *mdns.Msg {
		response := new(mdns.Msg)
		response.SetReply(request)
		var records *[]mdns.RR
		var values []string
		switch request.Question[0].Qtype {
		case mdns.TypeNS:
			records = &response.Ns
			values = []string{
				"run.bench.example.com. 60 IN NS ns-1.example.net.",
				"run.bench.example.com. 60 IN NS ns-2.example.net.",
			}
		case mdns.TypeA:
			response.Authoritative, records = true, &response.Answer
			values = []string{"control.run.bench.example.com. 60 IN A 192.0.2.10"}
		case mdns.TypeAAAA:
			response.Authoritative, records = true, &response.Answer
			values = []string{"control.run.bench.example.com. 60 IN AAAA 2001:db8::10"}
		}
		for _, value := range values {
			record, err := mdns.NewRR(value)
			if err != nil {
				t.Error(err)
				continue
			}
			*records = append(*records, record)
		}
		return response
	})
	dns := benchmarkDNS{}
	nameServers, err := dns.lookupAuthoritativeNameServers(t.Context(), server, "run.bench.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(nameServers, []string{"ns-1.example.net", "ns-2.example.net"}) {
		t.Fatalf("name servers = %v", nameServers)
	}
	addresses, err := dns.lookupAuthoritativeAddresses(t.Context(), server, "control.run.bench.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}) {
		t.Fatalf("addresses = %v", addresses)
	}
}

func benchmarkDNSServer(t *testing.T, respond func(*mdns.Msg) *mdns.Msg) string {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
		if err := writer.WriteMsg(respond(request)); err != nil {
			t.Error(err)
		}
	})}
	started, done := make(chan struct{}), make(chan error, 1)
	server.NotifyStartedFunc = func() { close(started) }
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("start DNS server: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return packet.LocalAddr().String()
}
