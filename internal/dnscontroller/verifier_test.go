package dnscontroller

import (
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func TestAuthoritativeVerifierChecksNSAndSOAAnswers(t *testing.T) {
	address := verifierDNS(t, func(_ string, request *dns.Msg) *dns.Msg {
		answers := map[uint16][]string{
			dns.TypeNS: {
				"claimed.example.test. 60 IN NS ns-1.example.test.",
				"claimed.example.test. 60 IN NS ns-2.example.test.",
			},
			dns.TypeSOA: {"claimed.example.test. 60 IN SOA ns-1.example.test. hostmaster.example.test. 1 60 60 60 60"},
		}
		return verifierResponse(t, request, true, dns.RcodeSuccess, answers[request.Question[0].Qtype]...)
	})

	verifier := &AuthoritativeVerifier{}
	expected := []string{"ns-1.example.test", "ns-2.example.test"}
	for _, recordType := range []uint16{dns.TypeNS, dns.TypeSOA} {
		valid, err := verifier.query(t.Context(), address, "claimed.example.test", recordType, expected)
		if err != nil || !valid {
			t.Fatalf("record type %d = valid %v, error %v", recordType, valid, err)
		}
	}
}

func TestAuthoritativeVerifierChecksExactRouteAddresses(t *testing.T) {
	address := verifierDNS(t, func(_ string, request *dns.Msg) *dns.Msg {
		answers := map[uint16][]string{
			dns.TypeA:    {"api.claimed.example.test. 60 IN A 192.0.2.10"},
			dns.TypeAAAA: {"api.claimed.example.test. 60 IN AAAA 2001:db8::10"},
		}
		return verifierResponse(t, request, true, dns.RcodeSuccess, answers[request.Question[0].Qtype]...)
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
			t.Context(), address, "api.claimed.example.test", test.recordType, test.expected,
		)
		if err != nil || !valid {
			t.Fatalf("record type %d = valid %v, error %v", test.recordType, valid, err)
		}
	}
	valid, err := verifier.queryAddresses(
		t.Context(), address, "api.claimed.example.test", dns.TypeA, []string{"192.0.2.11"},
	)
	if err != nil || valid {
		t.Fatalf("mismatched address = valid %v, error %v", valid, err)
	}
}

func TestAuthoritativeVerifierFindsChallengeAmongTXTValues(t *testing.T) {
	address := verifierDNS(t, func(_ string, request *dns.Msg) *dns.Msg {
		return verifierResponse(t, request, true, dns.RcodeSuccess,
			`_acme-challenge.example.test. 60 IN TXT "foreign"`,
			`_acme-challenge.example.test. 60 IN TXT "owned" "-value"`,
		)
	})

	verifier := &AuthoritativeVerifier{}
	valid, err := verifier.queryTXT(
		t.Context(), address, "_acme-challenge.example.test", "owned-value",
	)
	if err != nil || !valid {
		t.Fatalf("challenge TXT = valid %v, error %v", valid, err)
	}
}

func TestAuthoritativeVerifierWaitsForRecursiveChallengeAnswer(t *testing.T) {
	var visible atomic.Bool
	address := verifierDNS(t, func(_ string, request *dns.Msg) *dns.Msg {
		if !visible.Load() {
			return verifierResponse(t, request, true, dns.RcodeNameError)
		}
		return verifierResponse(t, request, true, dns.RcodeSuccess,
			`_acme-challenge.example.test. 60 IN TXT "owned"`,
		)
	})
	verifier, err := NewAuthoritativeVerifier(address)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := verifier.verifyRecursiveChallenge(t.Context(), "_acme-challenge.example.test", "owned")
	if err != nil || ready {
		t.Fatalf("cached missing TXT: ready=%t error=%v", ready, err)
	}
	visible.Store(true)
	ready, err = verifier.verifyRecursiveChallenge(t.Context(), "_acme-challenge.example.test", "owned")
	if err != nil || !ready {
		t.Fatalf("recursive TXT visible: ready=%t error=%v", ready, err)
	}
}

func verifierDNS(t *testing.T, respond func(string, *dns.Msg) *dns.Msg) string {
	t.Helper()
	return verifierDNSHandler(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		if err := writer.WriteMsg(respond(writer.RemoteAddr().Network(), request)); err != nil {
			t.Error(err)
		}
	}))
}

func verifierDNSHandler(t *testing.T, handler dns.Handler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	packet, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	for _, server := range []*dns.Server{{Listener: listener, Handler: handler}, {PacketConn: packet, Handler: handler}} {
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
	}
	return listener.Addr().String()
}

func verifierResponse(t *testing.T, request *dns.Msg, authoritative bool, rcode int, answers ...string) *dns.Msg {
	t.Helper()
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative, response.Rcode = authoritative, rcode
	for _, text := range answers {
		record, err := dns.NewRR(text)
		if err != nil {
			t.Error(err)
			continue
		}
		response.Answer = append(response.Answer, record)
	}
	return response
}
