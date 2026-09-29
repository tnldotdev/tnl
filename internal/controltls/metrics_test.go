package controltls

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestLoadedCertificateExpiryRequiresEveryConfiguredHostname(t *testing.T) {
	source := &Source{hostnames: []string{"control.example", "relay.example"}, certificates: make(map[string]*tls.Certificate)}
	first := time.Unix(100, 0)
	source.certificates["control.example"] = &tls.Certificate{Leaf: &x509.Certificate{NotAfter: first}}
	if got := source.EarliestCertificateExpiry(); !got.IsZero() {
		t.Fatalf("incomplete certificate set expired at %s", got)
	}
	source.certificates["relay.example"] = &tls.Certificate{Leaf: &x509.Certificate{NotAfter: time.Unix(200, 0)}}
	if got := source.EarliestCertificateExpiry(); !got.Equal(first) {
		t.Fatalf("earliest expiry=%s, want %s", got, first)
	}
}
