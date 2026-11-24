package dns

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
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

func TestVerifyNameserverAddressesDistinguishesPropagationFromFailure(t *testing.T) {
	const hostname = "api.example.test"
	addresses := []net.IPAddr{{IP: net.ParseIP("192.0.2.53")}, {IP: net.ParseIP("2001:db8::53")}}
	const ipv4, ipv6 = "192.0.2.53:53", "[2001:db8::53]:53"
	expected := map[uint16][]string{dns.TypeA: {"192.0.2.10"}, dns.TypeAAAA: {"2001:db8::10"}}
	unreachable := &net.OpError{Op: "dial", Net: "udp6", Err: syscall.ENETUNREACH}
	for _, test := range []struct {
		name   string
		a, b   string
		ready  bool
		failed bool
	}{
		{name: "incident: IPv4 NXDOMAIN and IPv6 unreachable", a: "absent", b: "unreachable"},
		{name: "unreachable first does not hide mismatch", a: "unreachable", b: "absent"},
		{name: "exact A and AAAA wins without IPv6 transport", a: "exact", b: "unreachable", ready: true},
		{name: "exact A on one address and AAAA on another is not enough", a: "only-a", b: "only-aaaa"},
		{name: "exact alternate wins", a: "absent", b: "exact", ready: true},
		{name: "all addresses unreachable", a: "unreachable", b: "unreachable", failed: true},
		{name: "no useful DNS responses", a: "referral", b: "unreachable", failed: true},
		{name: "NXDOMAIN does not hide REFUSED", a: "absent", b: "refused", failed: true},
		{name: "NXDOMAIN does not hide SERVFAIL", a: "servfail", b: "absent", failed: true},
		{name: "NXDOMAIN does not hide a non-authoritative answer", a: "absent", b: "referral", failed: true},
		{name: "NXDOMAIN does not hide a still-truncated answer", a: "absent", b: "truncated", failed: true},
		{name: "NXDOMAIN does not hide a fatal exchange error", a: "absent", b: "malformed", failed: true},
		{name: "NXDOMAIN does not hide permission errors", a: "absent", b: "denied", failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixtures := map[string]string{}
			for server, mode := range map[string]string{ipv4: test.a, ipv6: test.b} {
				switch mode {
				case "unreachable", "malformed", "denied":
					continue
				}
				fixtures[server] = verifierDNS(t, func(_ string, request *dns.Msg) *dns.Msg {
					q := request.Question[0]
					switch mode {
					case "absent":
						return verifierResponse(t, request, true, dns.RcodeNameError)
					case "refused":
						return verifierResponse(t, request, false, dns.RcodeRefused)
					case "servfail":
						return verifierResponse(t, request, false, dns.RcodeServerFailure)
					case "referral":
						return verifierResponse(t, request, false, dns.RcodeSuccess)
					case "truncated":
						response := verifierResponse(t, request, true, dns.RcodeSuccess)
						response.Truncated = true
						return response
					}
					if mode == "only-a" && q.Qtype == dns.TypeAAAA || mode == "only-aaaa" && q.Qtype == dns.TypeA {
						return verifierResponse(t, request, true, dns.RcodeSuccess)
					}
					return verifierResponse(t, request, true, dns.RcodeSuccess,
						q.Name+" 60 IN "+dns.TypeToString[q.Qtype]+" "+expected[q.Qtype][0])
				})
			}
			v := &AuthoritativeVerifier{}
			ready, err := verifyNameserverAddresses(t.Context(), hostname, addresses, expected,
				func(ctx context.Context, server, name string, recordType uint16, values []string) (bool, error) {
					mode := test.a
					if server == ipv6 {
						mode = test.b
					}
					switch mode {
					case "unreachable":
						return false, unreachable
					case "malformed":
						return false, dns.ErrBuf
					case "denied":
						return false, &net.OpError{Op: "dial", Net: "udp6", Err: syscall.EACCES}
					default:
						return v.queryAddresses(ctx, fixtures[server], name, recordType, values)
					}
				})
			if ready != test.ready || (err != nil) != test.failed {
				t.Fatalf("ready=%t error=%v, want ready=%t, error=%t", ready, err, test.ready, test.failed)
			}
		})
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
	var listener net.Listener
	var packet net.PacketConn
	for range 10 {
		var err error
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		packet, err = net.ListenPacket("udp", listener.Addr().String())
		if err == nil {
			break
		}
		_ = listener.Close()
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatal(err)
		}
	}
	if packet == nil {
		t.Fatal("could not reserve the same TCP and UDP port for the DNS fixture")
	}
	t.Cleanup(func() { _ = listener.Close() })
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
