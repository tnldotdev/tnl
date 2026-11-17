package serviceendpoint

import (
	"strings"
	"testing"
)

func TestPermissionPortDoesNotDependOnIngressReservation(t *testing.T) {
	for protocol, want := range map[string]uint16{"http": 443, "tcp": 0, "postgres": 0, "mysql": 0, "kubernetes": 0} {
		if got := PermissionPort(protocol); got != want {
			t.Fatalf("%s: permission port %d, want %d", protocol, got, want)
		}
	}
}

func TestServiceEndpointProtocolAndReachability(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "postgres", "mysql", "kubernetes", "unknown"} {
		for _, public := range []bool{false, true} {
			for _, port := range []int{-1, 0, 80, 443, 1023, 1024, 15432, 65535, 65536} {
				want := protocol == "http" && port == 443 ||
					(protocol == "tcp" || protocol == "postgres" || protocol == "mysql" || protocol == "kubernetes") &&
						(port >= 1024 && port <= 65535 || port == 0 && !public)
				if Valid(protocol, "service.example.test", port, public) != want {
					t.Fatalf("protocol=%s port=%d public=%t: want valid=%t", protocol, port, public, want)
				}
				for _, hostname := range []string{"", "SERVICE.example.test", "service.example.test.", "https://service.example.test", "service.example.test:443"} {
					if Valid(protocol, hostname, port, public) {
						t.Fatalf("accepted invalid hostname %q", hostname)
					}
				}
			}
		}
	}
}

func TestHTTPAuthorityUsesCanonicalHTTPSPort(t *testing.T) {
	const hostname = "service.example.test"
	if HTTPAuthority(hostname, 443) != hostname || HTTPAuthority(hostname, 8443) != hostname+":8443" {
		t.Fatal("authority did not distinguish canonical HTTPS and local alternate ports")
	}
	for _, authority := range []string{hostname, hostname + ":443", strings.ToUpper(hostname), "SeRvIcE.ExAmPlE.TeSt:443"} {
		if !MatchesHTTPAuthority(hostname, 443, authority) {
			t.Fatal("canonical HTTPS authority rejected", authority)
		}
	}
	for _, authority := range []string{
		hostname + ":8443", strings.ToUpper(hostname) + ":8443",
		hostname + ".", strings.ToUpper(hostname) + ".:443",
		"other.example.test", "SERVICE.example.test.other", "https://" + hostname,
		hostname + ":0443", hostname + ":+443", hostname + ":", hostname + ":443:443",
		hostname + ":443@other.example.test", "user@" + hostname, "[" + hostname + "]:443",
		hostname + "/path", hostname + "?query", hostname + "#fragment", hostname + " ",
		"\u017fervice.example.test", "\u017fervice.example.test:443",
	} {
		if MatchesHTTPAuthority(hostname, 443, authority) {
			t.Fatal("another authority was accepted", authority)
		}
	}
	for _, authority := range []string{hostname + ":8443", strings.ToUpper(hostname) + ":8443"} {
		if !MatchesHTTPAuthority(hostname, 8443, authority) {
			t.Fatal("exact alternate local port rejected", authority)
		}
	}
	for _, authority := range []string{hostname, strings.ToUpper(hostname), hostname + ":443", hostname + ":08443", hostname + ".:8443"} {
		if MatchesHTTPAuthority(hostname, 8443, authority) {
			t.Fatal("alternate local port was inferred or ignored", authority)
		}
	}
	for _, authority := range []string{"\u212a.example.test", "\u212a.example.test:443"} {
		if MatchesHTTPAuthority("k.example.test", 443, authority) {
			t.Fatal("non-ASCII case folding accepted another authority", authority)
		}
	}
}
