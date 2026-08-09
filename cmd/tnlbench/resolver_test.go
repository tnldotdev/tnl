package main

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestAuthoritativeResolverForwardsChallengeQueries(t *testing.T) {
	resolver, err := newAuthoritativeResolver(resolverCommand{
		ServerDomain: "run.bench.example.com", ServerNameServers: "ns-1.example.net,ns-2.example.net",
		ManagedDomain: "routes.run.bench.example.com", ManagedNameServers: "ns-3.example.net,ns-4.example.net",
	})
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	resolver.exchange = func(_ context.Context, request *mdns.Msg, nameServer string) (*mdns.Msg, time.Duration, error) {
		calls = append(calls, nameServer)
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		response.Answer = []mdns.RR{&mdns.TXT{
			Hdr: mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60},
			Txt: []string{"expected"},
		}}
		return response, 0, nil
	}

	for _, test := range []struct {
		name, nameServer string
		recordType       uint16
	}{
		{"_acme-challenge.relay-a.run.bench.example.com.", "ns-1.example.net:53", mdns.TypeTXT},
		{"_acme-challenge.route.routes.run.bench.example.com.", "ns-4.example.net:53", mdns.TypeTXT},
		{"control.run.bench.example.com.", "ns-1.example.net:53", mdns.TypeA},
	} {
		before := len(calls)
		request := new(mdns.Msg)
		request.SetQuestion(test.name, test.recordType)
		writer := &dnsResponseWriterStub{}
		resolver.ServeDNS(writer, request)
		if writer.message == nil || writer.message.Rcode != mdns.RcodeSuccess || len(writer.message.Answer) != 1 {
			t.Fatalf("response for %s = %#v", test.name, writer.message)
		}
		if calls[before] != test.nameServer {
			t.Fatalf("first name server for %s = %q, want %q", test.name, calls[before], test.nameServer)
		}
	}
}

func TestAuthoritativeResolverRetriesEmptyChallengeAnswers(t *testing.T) {
	resolver, err := newAuthoritativeResolver(resolverCommand{
		ServerDomain: "run.bench.example.com", ServerNameServers: "ns-1.example.net,ns-2.example.net",
		ManagedDomain: "routes.run.bench.example.com", ManagedNameServers: "ns-3.example.net,ns-4.example.net",
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver.lookupTimeout, resolver.retryInterval = time.Second, time.Millisecond
	calls := 0
	resolver.exchange = func(_ context.Context, request *mdns.Msg, _ string) (*mdns.Msg, time.Duration, error) {
		calls++
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		if calls > 2 {
			response.Answer = []mdns.RR{&mdns.TXT{
				Hdr: mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60},
				Txt: []string{"expected"},
			}}
		}
		return response, 0, nil
	}
	request := new(mdns.Msg)
	request.SetQuestion("_acme-challenge.relay-a.run.bench.example.com.", mdns.TypeTXT)
	writer := &dnsResponseWriterStub{}
	resolver.ServeDNS(writer, request)
	if calls != 4 || writer.message == nil || len(writer.message.Answer) != 1 {
		t.Fatalf("retried response: calls %d, message %#v", calls, writer.message)
	}
}

func TestAuthoritativeResolverRejectsQueriesOutsideBenchmarkDomains(t *testing.T) {
	resolver, err := newAuthoritativeResolver(resolverCommand{
		ServerDomain: "run.bench.example.com", ServerNameServers: "ns-1.example.net,ns-2.example.net",
		ManagedDomain: "routes.run.bench.example.com", ManagedNameServers: "ns-3.example.net,ns-4.example.net",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := new(mdns.Msg)
	request.SetQuestion("_acme-challenge.example.net.", mdns.TypeTXT)
	writer := &dnsResponseWriterStub{}
	resolver.ServeDNS(writer, request)
	if writer.message == nil || writer.message.Rcode != mdns.RcodeRefused {
		t.Fatalf("outside response = %#v", writer.message)
	}
}

func TestResolverNameServersValidatesAndCanonicalizes(t *testing.T) {
	got, err := resolverNameServers("NS-1.Example.NET.,ns-2.example.net")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ns-1.example.net:53", "ns-2.example.net:53"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("name servers = %v, want %v", got, want)
	}
	for _, value := range []string{"ns-1.example.net", "ns-1.example.net,ns-1.example.net", "ns-1.example.net,bad name"} {
		if _, err := resolverNameServers(value); err == nil {
			t.Fatalf("invalid name servers accepted: %q", value)
		}
	}
}

type dnsResponseWriterStub struct{ message *mdns.Msg }

func (*dnsResponseWriterStub) LocalAddr() net.Addr              { return nil }
func (*dnsResponseWriterStub) RemoteAddr() net.Addr             { return nil }
func (w *dnsResponseWriterStub) WriteMsg(value *mdns.Msg) error { w.message = value; return nil }
func (*dnsResponseWriterStub) Write([]byte) (int, error)        { return 0, nil }
func (*dnsResponseWriterStub) Close() error                     { return nil }
func (*dnsResponseWriterStub) TsigStatus() error                { return nil }
func (*dnsResponseWriterStub) TsigTimersOnly(bool)              {}
func (*dnsResponseWriterStub) Hijack()                          {}
