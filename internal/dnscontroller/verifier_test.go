package dnscontroller

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestAuthoritativeVerifierChecksNSAndSOAAnswers(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc("claimed.example.test.", func(response dns.ResponseWriter, request *dns.Msg) {
		message := new(dns.Msg)
		message.SetReply(request)
		message.Authoritative = true
		switch request.Question[0].Qtype {
		case dns.TypeNS:
			message.Answer = []dns.RR{
				&dns.NS{Hdr: dns.RR_Header{Name: "claimed.example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns-1.example.test."},
				&dns.NS{Hdr: dns.RR_Header{Name: "claimed.example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns-2.example.test."},
			}
		case dns.TypeSOA:
			message.Answer = []dns.RR{&dns.SOA{
				Hdr: dns.RR_Header{Name: "claimed.example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET},
				Ns:  "ns-1.example.test.", Mbox: "hostmaster.example.test.", Serial: 1,
			}}
		}
		_ = response.WriteMsg(message)
	})
	server := &dns.Server{PacketConn: packet, Handler: mux}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = server.Shutdown()
		<-done
	})

	verifier := &AuthoritativeVerifier{}
	expected := []string{"ns-1.example.test", "ns-2.example.test"}
	for _, recordType := range []uint16{dns.TypeNS, dns.TypeSOA} {
		valid, err := verifier.query(t.Context(), packet.LocalAddr().String(), "claimed.example.test", recordType, expected)
		if err != nil || !valid {
			t.Fatalf("record type %d = valid %v, error %v", recordType, valid, err)
		}
	}
}

func TestAuthoritativeVerifierChecksExactRouteAddresses(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc("api.claimed.example.test.", func(response dns.ResponseWriter, request *dns.Msg) {
		message := new(dns.Msg)
		message.SetReply(request)
		message.Authoritative = true
		switch request.Question[0].Qtype {
		case dns.TypeA:
			message.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "api.claimed.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET},
				A:   net.ParseIP("192.0.2.10"),
			}}
		case dns.TypeAAAA:
			message.Answer = []dns.RR{&dns.AAAA{
				Hdr:  dns.RR_Header{Name: "api.claimed.example.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
				AAAA: net.ParseIP("2001:db8::10"),
			}}
		}
		_ = response.WriteMsg(message)
	})
	server := &dns.Server{PacketConn: packet, Handler: mux}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = server.Shutdown()
		<-done
	})

	verifier := &AuthoritativeVerifier{}
	for _, test := range []struct {
		recordType uint16
		expected   []string
	}{
		{recordType: dns.TypeA, expected: []string{"192.0.2.10"}},
		{recordType: dns.TypeAAAA, expected: []string{"2001:db8::10"}},
	} {
		valid, err := verifier.queryAddresses(
			t.Context(), packet.LocalAddr().String(), "api.claimed.example.test", test.recordType, test.expected,
		)
		if err != nil || !valid {
			t.Fatalf("record type %d = valid %v, error %v", test.recordType, valid, err)
		}
	}
	valid, err := verifier.queryAddresses(
		t.Context(), packet.LocalAddr().String(), "api.claimed.example.test", dns.TypeA, []string{"192.0.2.11"},
	)
	if err != nil || valid {
		t.Fatalf("mismatched address = valid %v, error %v", valid, err)
	}
}

func TestAuthoritativeVerifierFindsChallengeAmongTXTValues(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc("_acme-challenge.example.test.", func(response dns.ResponseWriter, request *dns.Msg) {
		message := new(dns.Msg)
		message.SetReply(request)
		message.Authoritative = true
		message.Answer = []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{Name: "_acme-challenge.example.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
				Txt: []string{"foreign"},
			},
			&dns.TXT{
				Hdr: dns.RR_Header{Name: "_acme-challenge.example.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
				Txt: []string{"owned", "-value"},
			},
		}
		_ = response.WriteMsg(message)
	})
	server := &dns.Server{PacketConn: packet, Handler: mux}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = server.Shutdown()
		<-done
	})

	verifier := &AuthoritativeVerifier{}
	valid, err := verifier.queryTXT(
		t.Context(), packet.LocalAddr().String(), "_acme-challenge.example.test", "owned-value",
	)
	if err != nil || !valid {
		t.Fatalf("challenge TXT = valid %v, error %v", valid, err)
	}
}
