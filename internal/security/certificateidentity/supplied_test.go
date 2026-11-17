package certificateidentity

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/certificatetest"
)

func TestSuppliedCertificateTrustNamesValidityAndKeys(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuer := certificatetest.New(t, now)
	good := issuer.Issue(t, []string{"*.example.test", "other.example"}, now, now.Add(time.Hour), nil)
	names := []string{"canonical.example.test", "r-abc.example.test"}
	got, err := ValidateSuppliedChain(good.Chain, names, now, issuer.Roots)
	if err != nil || len(got.Fingerprint) != 64 || !got.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatal("trusted wildcard did not cover both approved names", err)
	}
	if _, err := LoadSupplied(good.Chain, good.Key, names, now); err != nil {
		t.Fatal(err)
	}
	long := issuer.Issue(t, []string{"*.example.test"}, now, now.Add(366*24*time.Hour), nil)
	bounded, err := ValidateSuppliedChain(long.Chain, names, now, issuer.Roots)
	if err != nil || !bounded.ExpiresAt.Equal(now.Add(365*24*time.Hour)) {
		t.Fatal("supplied serving deadline outlived its verified trust path", err)
	}
	for _, test := range []struct {
		name  string
		chain []byte
		names []string
		at    time.Time
		roots *x509.CertPool
	}{
		{"untrusted", good.Chain, names, now, x509.NewCertPool()},
		{"missing_alias", good.Chain, []string{"outside.test"}, now, issuer.Roots},
		{"nested_alias", good.Chain, []string{"nested.r-abc.example.test"}, now, issuer.Roots},
		{"expired", good.Chain, names, now.Add(time.Hour), issuer.Roots},
		{"future", good.Chain, names, now.Add(-time.Hour), issuer.Roots},
		{"empty", nil, names, now, issuer.Roots},
		{"whitespace", []byte(" \n "), names, now, issuer.Roots},
		{"trailing", append(append([]byte(nil), good.Chain...), []byte("private details")...), names, now, issuer.Roots},
		{"oversize", []byte(strings.Repeat("x", 128<<10+1)), names, now, issuer.Roots},
		{"no_names", good.Chain, nil, now, issuer.Roots},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ValidateSuppliedChain(test.chain, test.names, test.at, test.roots); err == nil {
				t.Fatal("invalid supplied chain was accepted")
			}
		})
	}
	for name, change := range map[string]func(*x509.Certificate){
		"ca":          func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true },
		"client_only": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
		"ip_san":      func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} },
	} {
		t.Run(name, func(t *testing.T) {
			material := issuer.Issue(t, []string{"*.example.test"}, now, now.Add(time.Hour), change)
			if _, err := ValidateSuppliedChain(material.Chain, names, now, issuer.Roots); err == nil {
				t.Fatal("unsupported supplied identity was accepted")
			}
		})
	}
	other := issuer.Issue(t, []string{"*.example.test"}, now, now.Add(time.Hour), nil)
	if _, err := LoadSupplied(good.Chain, other.Key, names, now); err == nil {
		t.Fatal("mismatched private key was accepted")
	}
	block, rest := pem.Decode(good.Chain)
	block.Bytes[len(block.Bytes)-1] ^= 1
	tampered := append(pem.EncodeToMemory(block), rest...)
	if _, err := ValidateSuppliedChain(tampered, names, now, issuer.Roots); err == nil {
		t.Fatal("invalid chain signature was accepted")
	}
}
