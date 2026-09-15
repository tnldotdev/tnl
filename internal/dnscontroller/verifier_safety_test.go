package dnscontroller

import (
	"errors"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/miekg/dns"
)

func TestAuthoritativeVerifierRejectsNegativeAnswers(t *testing.T) {
	for _, test := range []struct {
		name             string
		kind             uint16
		answers          []string
		nonAuthoritative bool
		rcode            int
		expected         []string
		want             bool
	}{
		{name: "NS_mismatch", kind: dns.TypeNS, answers: []string{"example.test. 60 IN NS foreign.test."}},
		{name: "NS_wrong_owner", kind: dns.TypeNS, answers: []string{"other.test. 60 IN NS ns-1.example.test.", "other.test. 60 IN NS ns-2.example.test."}},
		{name: "NS_irrelevant_type", kind: dns.TypeNS, answers: []string{"example.test. 60 IN TXT \"ns-1.example.test ns-2.example.test\""}},
		{name: "SOA_mismatch", kind: dns.TypeSOA, answers: []string{"example.test. 60 IN SOA foreign.test. hostmaster.test. 1 60 60 60 60"}},
		{name: "SOA_wrong_owner", kind: dns.TypeSOA, answers: []string{"other.test. 60 IN SOA ns-1.example.test. hostmaster.test. 1 60 60 60 60"}},
		{name: "SOA_irrelevant_type", kind: dns.TypeSOA, answers: []string{"example.test. 60 IN NS ns-1.example.test."}},
		{name: "NS_not_authoritative", kind: dns.TypeNS, nonAuthoritative: true, answers: []string{"example.test. 60 IN NS ns-1.example.test.", "example.test. 60 IN NS ns-2.example.test."}},
		{name: "SOA_not_authoritative", kind: dns.TypeSOA, nonAuthoritative: true, answers: []string{"example.test. 60 IN SOA ns-1.example.test. hostmaster.test. 1 60 60 60 60"}},
		{name: "TXT_missing", kind: dns.TypeTXT, answers: []string{"example.test. 60 IN TXT \"foreign\""}},
		{name: "TXT_wrong_owner", kind: dns.TypeTXT, answers: []string{"other.test. 60 IN TXT \"owned\""}},
		{name: "TXT_irrelevant_type", kind: dns.TypeTXT, answers: []string{"example.test. 60 IN A 192.0.2.10"}},
		{name: "TXT_not_authoritative", kind: dns.TypeTXT, nonAuthoritative: true, answers: []string{"example.test. 60 IN TXT \"owned\""}},
		{name: "TXT_NXDOMAIN", kind: dns.TypeTXT, rcode: dns.RcodeNameError},
		{name: "NS_NXDOMAIN", kind: dns.TypeNS, rcode: dns.RcodeNameError},
		{name: "SOA_NXDOMAIN", kind: dns.TypeSOA, rcode: dns.RcodeNameError},
		{name: "IPv4_extra", kind: dns.TypeA, expected: []string{"192.0.2.10"}, answers: []string{"example.test. 60 IN A 192.0.2.10", "example.test. 60 IN A 192.0.2.11"}},
		{name: "IPv4_missing", kind: dns.TypeA, expected: []string{"192.0.2.10", "192.0.2.11"}, answers: []string{"example.test. 60 IN A 192.0.2.10"}},
		{name: "IPv4_irrelevant_type", kind: dns.TypeA, expected: []string{"192.0.2.10"}, answers: []string{"example.test. 60 IN AAAA 2001:db8::10"}},
		{name: "IPv6_extra", kind: dns.TypeAAAA, expected: []string{"2001:db8::10"}, answers: []string{"example.test. 60 IN AAAA 2001:db8::10", "example.test. 60 IN AAAA 2001:db8::11"}},
		{name: "IPv6_missing", kind: dns.TypeAAAA, expected: []string{"2001:db8::10", "2001:db8::11"}, answers: []string{"example.test. 60 IN AAAA 2001:db8::10"}},
		{name: "IPv4_exact_set", kind: dns.TypeA, expected: []string{"192.0.2.10", "192.0.2.11"}, answers: []string{"example.test. 60 IN A 192.0.2.11", "example.test. 60 IN A 192.0.2.10"}, want: true},
		{name: "IPv6_exact_set", kind: dns.TypeAAAA, expected: []string{"2001:db8::10", "2001:db8::11"}, answers: []string{"example.test. 60 IN AAAA 2001:db8::11", "example.test. 60 IN AAAA 2001:db8::10"}, want: true},
		{name: "IPv4_not_authoritative", kind: dns.TypeA, expected: []string{"192.0.2.10"}, nonAuthoritative: true, answers: []string{"example.test. 60 IN A 192.0.2.10"}},
		{name: "IPv6_not_authoritative", kind: dns.TypeAAAA, expected: []string{"2001:db8::10"}, nonAuthoritative: true, answers: []string{"example.test. 60 IN AAAA 2001:db8::10"}},
		{name: "IPv4_NXDOMAIN_required", kind: dns.TypeA, expected: []string{"192.0.2.10"}, rcode: dns.RcodeNameError},
		{name: "IPv6_NXDOMAIN_required", kind: dns.TypeAAAA, expected: []string{"2001:db8::10"}, rcode: dns.RcodeNameError},
		{name: "IPv4_NXDOMAIN_removed", kind: dns.TypeA, rcode: dns.RcodeNameError, want: true},
		{name: "IPv6_NXDOMAIN_removed", kind: dns.TypeAAAA, rcode: dns.RcodeNameError, want: true},
		{name: "NXDOMAIN_not_authoritative", kind: dns.TypeA, rcode: dns.RcodeNameError, nonAuthoritative: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			address := verifierDNS(t, func(_ string, request *dns.Msg) *dns.Msg {
				if request.RecursionDesired {
					t.Error("authoritative query requested recursion")
				}
				return verifierResponse(t, request, !test.nonAuthoritative, test.rcode, test.answers...)
			})
			v := &AuthoritativeVerifier{}
			var valid bool
			var err error
			switch test.kind {
			case dns.TypeNS, dns.TypeSOA:
				valid, err = v.query(t.Context(), address, "example.test", test.kind, []string{"ns-1.example.test", "ns-2.example.test"})
			case dns.TypeTXT:
				valid, err = v.queryTXT(t.Context(), address, "example.test", "owned")
			default:
				valid, err = v.queryAddresses(t.Context(), address, "example.test", test.kind, test.expected)
			}
			if err != nil || valid != test.want {
				t.Fatalf("valid = %v, want %v, error %v", valid, test.want, err)
			}
		})
	}
}

func TestAuthoritativeVerifierRejectsMalformedResponse(t *testing.T) {
	address := verifierDNSHandler(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := verifierResponse(t, request, true, dns.RcodeSuccess, "example.test. 60 IN A 192.0.2.10")
		wire, err := response.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := writer.Write(wire[:len(wire)-1]); err != nil {
			t.Error(err)
		}
	}))
	valid, err := (&AuthoritativeVerifier{}).queryAddresses(t.Context(), address, "example.test", dns.TypeA, []string{"192.0.2.10"})
	if err == nil || valid {
		t.Fatalf("malformed response = valid %v, error %v", valid, err)
	}
}

func TestAuthoritativeVerifierRetriesTruncatedUDPOverTCP(t *testing.T) {
	for _, kind := range []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeTXT, dns.TypeA, dns.TypeAAAA} {
		t.Run(dns.TypeToString[kind], func(t *testing.T) {
			var udp, tcp atomic.Int32
			address := verifierDNS(t, func(network string, request *dns.Msg) *dns.Msg {
				if request.RecursionDesired {
					t.Error("authoritative query requested recursion")
				}
				if strings.HasPrefix(network, "udp") {
					udp.Add(1)
					response := verifierResponse(t, request, true, dns.RcodeSuccess)
					response.Truncated = true
					return response
				}
				tcp.Add(1)
				answers := map[uint16][]string{
					dns.TypeNS:   {"example.test. 60 IN NS ns-1.example.test.", "example.test. 60 IN NS ns-2.example.test."},
					dns.TypeSOA:  {"example.test. 60 IN SOA ns-1.example.test. hostmaster.test. 1 60 60 60 60"},
					dns.TypeTXT:  {"example.test. 60 IN TXT \"owned\""},
					dns.TypeA:    {"example.test. 60 IN A 192.0.2.10"},
					dns.TypeAAAA: {"example.test. 60 IN AAAA 2001:db8::10"},
				}
				return verifierResponse(t, request, true, dns.RcodeSuccess, answers[kind]...)
			})
			v := &AuthoritativeVerifier{}
			var valid bool
			var err error
			switch kind {
			case dns.TypeNS, dns.TypeSOA:
				valid, err = v.query(t.Context(), address, "example.test", kind, []string{"ns-1.example.test", "ns-2.example.test"})
			case dns.TypeTXT:
				valid, err = v.queryTXT(t.Context(), address, "example.test", "owned")
			case dns.TypeA:
				valid, err = v.queryAddresses(t.Context(), address, "example.test", kind, []string{"192.0.2.10"})
			case dns.TypeAAAA:
				valid, err = v.queryAddresses(t.Context(), address, "example.test", kind, []string{"2001:db8::10"})
			}
			if err != nil || !valid || udp.Load() != 1 || tcp.Load() != 1 {
				t.Fatalf("valid %v, error %v, UDP %d, TCP %d", valid, err, udp.Load(), tcp.Load())
			}
		})
	}
}

func TestAuthoritativeVerifierVerifyRequiresDelegationAndAuthority(t *testing.T) {
	for _, mode := range []string{"incomplete", "duplicate", "NS_mismatch", "NXDOMAIN", "SERVFAIL", "missing_nameserver_address", "delegation_without_authority"} {
		t.Run(mode, func(t *testing.T) {
			var queries, authorityQueries atomic.Int32
			address := verifierDNS(t, func(_ string, request *dns.Msg) *dns.Msg {
				queries.Add(1)
				q := request.Question[0]
				rcode := dns.RcodeSuccess
				var answers []string
				switch {
				case mode == "NXDOMAIN":
					rcode = dns.RcodeNameError
				case mode == "SERVFAIL":
					rcode = dns.RcodeServerFailure
				case q.Qtype == dns.TypeNS:
					for _, ns := range []string{"ns-1.example.test.", "ns-2.example.test."} {
						if mode == "NS_mismatch" {
							ns = "foreign.test."
						}
						answers = append(answers, q.Name+" 60 IN NS "+ns)
					}
				case mode == "missing_nameserver_address":
					rcode = dns.RcodeNameError
				case q.Qtype == dns.TypeA:
					answers = []string{q.Name + " 60 IN A 127.0.0.1"}
				}
				return verifierResponse(t, request, true, rcode, answers...)
			})
			v, err := NewAuthoritativeVerifier(address)
			if err != nil {
				t.Fatal(err)
			}
			unavailable := errors.New("authoritative DNS unavailable")
			// Verify hardcodes authoritative port 53. Fail at the real dial boundary
			// rather than binding a privileged port or contacting machine DNS.
			v.dialer.Control = func(_, address string, _ syscall.RawConn) error {
				authorityQueries.Add(1)
				if address != "127.0.0.1:53" {
					t.Errorf("unexpected authoritative address %q", address)
				}
				return unavailable
			}
			expected := []string{"NS-2.EXAMPLE.TEST.", "ns-1.example.test"}
			if mode == "incomplete" {
				expected = expected[:1]
			}
			if mode == "duplicate" {
				expected = []string{"ns-1.example.test", "NS-1.EXAMPLE.TEST."}
			}
			valid, err := v.Verify(t.Context(), "example.test", expected)
			wantErr := mode == "incomplete" || mode == "duplicate" || mode == "SERVFAIL" || mode == "missing_nameserver_address" || mode == "delegation_without_authority"
			if valid || (err != nil) != wantErr {
				t.Fatalf("Verify = %v, error %v, want error %v", valid, err, wantErr)
			}
			if mode == "delegation_without_authority" {
				if !errors.Is(err, unavailable) || authorityQueries.Load() == 0 {
					t.Fatalf("delegation bypassed authority: error %v, queries %d", err, authorityQueries.Load())
				}
			} else if authorityQueries.Load() != 0 {
				t.Fatalf("unexpected authority queries %d", authorityQueries.Load())
			}
			if (mode == "incomplete" || mode == "duplicate") && queries.Load() != 0 {
				t.Fatal("incomplete nameservers triggered DNS lookup")
			}
		})
	}
}
