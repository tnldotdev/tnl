package proxy

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
)

func TestRequestAuthorityIncludesTheApprovedPort(t *testing.T) {
	for _, major := range []int{1, 2} {
		for _, port := range []int{443, 25443} {
			for _, test := range []struct {
				authority string
				allowed   bool
			}{
				{"route.example", port == 443},
				{"route.example:443", port == 443},
				{"ROUTE.EXAMPLE:25443", port == 25443},
				{"route.example:25444", false},
				{"sibling.example:25443", false},
				{"route.example:025443", false},
				{"route.example:+25443", false},
				{"route.example:", false},
				{"route.example:0", false},
				{"route.example:65536", false},
			} {
				request := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/"}, RequestURI: "/",
					ProtoMajor: major, Host: test.authority, TLS: &tls.ConnectionState{ServerName: "route.example"}}
				code := ValidateRequest(request, "route.example", port)
				if (code == "") != test.allowed {
					t.Fatalf("HTTP/%d authority=%q port=%d: %s", major, test.authority, port, code)
				}
				if !test.allowed && major == 2 && code != diagnostic.RequestMisdirected && code != diagnostic.RequestRejected {
					t.Fatal("invalid authority lost its HTTP request classification", code)
				}
				request.Host = "route.example:25443"
				request.TLS.ServerName = "sibling.example"
				if code := ValidateRequest(request, "route.example", 25443); code != diagnostic.RequestRejected {
					t.Fatal("matching HTTP authority replaced TLS identity", code)
				}
			}
		}
	}
}

func TestProxyRequiresAnExplicitNetworkPort(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if _, err := New(Config{Target: "3000", Hostname: "route.example", Port: port}); err == nil {
			t.Fatal("proxy accepted an unspecified or invalid endpoint", port)
		}
	}
}
