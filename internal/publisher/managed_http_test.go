package publisher

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestManagedHTTPCredentialPrecedenceFailsClosed(t *testing.T) {
	certificate := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("TLS key possession")}}}
	valid := "mhg_0123456789abcdefghijkl.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, test := range []struct {
		name    string
		headers http.Header
		kind    string
		invalid bool
	}{
		{"no HTTP proof", nil, "certificate", false},
		{"token", http.Header{"Tnl-Access-Token": {valid}}, "token", false},
		{"share", http.Header{"Tnl-Share-Token": {valid}}, "share", false},
		{"browser", http.Header{"Cookie": {"__Host-tnl-browser=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, "browser", false},
		{"invalid token", http.Header{"Tnl-Access-Token": {"invalid"}}, "", true},
		{"empty token", http.Header{"Tnl-Access-Token": {""}}, "", true},
		{"duplicate token", http.Header{"Tnl-Access-Token": {valid, valid}}, "", true},
		{"invalid share over browser", http.Header{"Tnl-Share-Token": {"invalid"}, "Cookie": {"__Host-tnl-browser=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, "", true},
		{"invalid browser", http.Header{"Cookie": {"__Host-tnl-browser=invalid"}}, "", true},
		{"unparsed browser", http.Header{"Cookie": {"__Host-tnl-browser=\x7f"}}, "", true},
		{"duplicate browser", http.Header{"Cookie": {"__Host-tnl-browser=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; __Host-tnl-browser=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, "", true},
		{"public URL share", http.Header{"Tnl-Share-Token": {"shr_0123456789abcdefghijkl.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://app.example:12000/", nil)
			if test.headers != nil {
				r.Header = test.headers
			}
			credential, err := managedHTTPCredential(r, certificate)
			if (err != nil) != test.invalid || string(credential.Kind) != test.kind {
				t.Fatalf("selected %q, error=%v", credential.Kind, err)
			}
		})
	}
}

func TestManagedHTTPWorkloadCertificateNeverFallsBackToHumanCredentials(t *testing.T) {
	uri, _ := url.Parse("tnl://workload-client/psvc_aaaaaaaaaaaaaaaaaaaaaa/wls_aaaaaaaaaaaaaaaaaaaaaa")
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("workload leaf"), URIs: []*url.URL{uri}}}}
	for _, headers := range []http.Header{nil,
		{"Cookie": {"__Host-tnl-browser=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
		{"Tnl-Access-Token": {"mhg_0123456789abcdefghijkl.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
		{"Tnl-Access-Token": {"invalid"}, "Cookie": {"__Host-tnl-browser=invalid"}},
	} {
		r := httptest.NewRequest("GET", "https://app.example:12000/", nil)
		if headers != nil {
			r.Header = headers
		}
		credential, err := managedHTTPCredential(r, state)
		if err != nil || credential.Kind != "certificate" || credential.Secret != nil || credential.Certificate == nil {
			t.Fatal("workload credential changed", err)
		}
	}
}
