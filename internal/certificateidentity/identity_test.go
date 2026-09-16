package certificateidentity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestDNSNamesOnly(t *testing.T) {
	t.Parallel()

	dnsName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("route.example.test")}
	uri := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte("https://example.test")}
	dnsExtension := sanExtension(t, dnsName)
	if !DNSNamesOnly([]pkix.Extension{dnsExtension}, []string{"route.example.test"}) {
		t.Fatal("DNS-only SAN was rejected")
	}
	for name, extensions := range map[string][]pkix.Extension{
		"missing":       nil,
		"duplicate":     {dnsExtension, dnsExtension},
		"non-DNS entry": {sanExtension(t, dnsName, uri)},
	} {
		t.Run(name, func(t *testing.T) {
			if DNSNamesOnly(extensions, []string{"route.example.test"}) {
				t.Fatal("invalid SAN was accepted")
			}
		})
	}
	if DNSNamesOnly([]pkix.Extension{dnsExtension}, []string{"other.example.test"}) {
		t.Fatal("mismatched parsed DNS name was accepted")
	}
}

func TestCanonicalPlanAndExactBindings(t *testing.T) {
	plan := controlv1.CertificatePlan{CacheKey: "namespace", Scope: "member.example", Identifiers: []string{"member.example", "*.member.example"}, ChallengeMethod: controlv1.Dns01}
	canonical, err := CanonicalPlan(plan)
	if err != nil || !slices.Equal(canonical.Identifiers, []string{"*.member.example", "member.example"}) || plan.Identifiers[0] != "member.example" {
		t.Fatalf("canonical plan = %#v, %v", canonical, err)
	}
	if !SamePlan(plan, canonical) {
		t.Fatal("identifier order changed plan identity")
	}
	for _, test := range []struct {
		name   string
		change func(*controlv1.CertificatePlan)
		valid  bool
	}{
		{"scope", func(p *controlv1.CertificatePlan) { p.Scope = "different-scope" }, true},
		{"key", func(p *controlv1.CertificatePlan) { p.CacheKey = "different-key" }, true},
		{"identifiers", func(p *controlv1.CertificatePlan) { p.Identifiers = []string{"member.example"} }, true},
		{"empty_scope", func(p *controlv1.CertificatePlan) { p.Scope = "" }, false},
		{"empty_key", func(p *controlv1.CertificatePlan) { p.CacheKey = "" }, false},
		{"unknown_method", func(p *controlv1.CertificatePlan) { p.ChallengeMethod = "unknown" }, false},
		{"wildcard_TLS_ALPN", func(p *controlv1.CertificatePlan) { p.ChallengeMethod = controlv1.TlsAlpn01 }, false},
		{"empty_identifiers", func(p *controlv1.CertificatePlan) { p.Identifiers = nil }, false},
		{"too_many_identifiers", func(p *controlv1.CertificatePlan) {
			p.Identifiers = []string{"member.example", "*.member.example", "other.example"}
		}, false},
		{"duplicate", func(p *controlv1.CertificatePlan) { p.Identifiers = []string{"member.example", "member.example"} }, false},
		{"noncanonical", func(p *controlv1.CertificatePlan) { p.Identifiers = []string{"MEMBER.example"} }, false},
		{"nested_wildcard", func(p *controlv1.CertificatePlan) { p.Identifiers = []string{"*.*.example"} }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := plan
			test.change(&changed)
			_, err := CanonicalPlan(changed)
			if (err == nil) != test.valid || SamePlan(changed, plan) {
				t.Fatalf("changed plan accepted=%t, error=%v", SamePlan(changed, plan), err)
			}
		})
	}
	for _, hostname := range []string{"member.example", "app.member.example"} {
		if !Covers(plan.Identifiers, hostname) {
			t.Errorf("plan did not cover %s", hostname)
		}
	}
	for _, hostname := range []string{"deep.app.member.example", "other.example", "APP.member.example", "*.member.example"} {
		if Covers(plan.Identifiers, hostname) {
			t.Errorf("plan unexpectedly covered %s", hostname)
		}
	}
}

func TestValidateIssuedCertificate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	identifiers := []string{"*.member.example", "member.example"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	encode := func(t *testing.T, template, parent *x509.Certificate, publicKey any, signer *ecdsa.PrivateKey) []byte {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	caPEM := encode(t, ca, ca, &caKey.PublicKey, caKey)
	leaf := x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: identifiers,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafPEM := encode(t, &leaf, ca, &key.PublicKey, caKey)
	chain := string(leafPEM) + string(caPEM)
	request := func(names []string, extensions []pkix.Extension) []byte {
		t.Helper()
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names, ExtraExtensions: extensions}, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	csr := request(identifiers, nil)
	withHeaders, _ := pem.Decode(leafPEM)
	withHeaders.Headers = map[string]string{"Extra": "header"}
	badCertificate, _ := pem.Decode(leafPEM)
	badCertificate.Bytes[len(badCertificate.Bytes)-1] ^= 1
	for _, test := range []struct {
		name, chain string
		valid       bool
	}{
		{"valid", chain, true},
		{"whitespace", " \t\r\n" + string(leafPEM) + " \t\r\n" + string(caPEM) + " \t\r\n", true},
		{"leading_garbage", "garbage\n" + chain, false},
		{"between_garbage", string(leafPEM) + "garbage\n" + string(caPEM), false},
		{"trailing_garbage", chain + "garbage\n", false},
		{"skipped_malformed_block", "-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n" + chain, false},
		{"empty", " \t\r\n", false},
		{"wrong_block_type", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")})), false},
		{"headers", string(pem.EncodeToMemory(withHeaders)) + string(caPEM), false},
		{"malformed_DER", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")})), false},
		{"wrong_chain", string(leafPEM) + string(leafPEM), false},
		{"bad_chain_signature", string(pem.EncodeToMemory(badCertificate)) + string(caPEM), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ValidateIssuedCertificate([]byte(test.chain), csr, identifiers, now)
			if (err == nil) != test.valid {
				t.Fatalf("ValidateIssuedCertificate error = %v; want valid = %t", err, test.valid)
			}
			if test.valid && (!got.NotBefore.Equal(leaf.NotBefore) || !got.NotAfter.Equal(leaf.NotAfter)) {
				t.Fatal("issued certificate dates changed")
			}
		})
	}
	hiddenSAN := sanExtension(t,
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(identifiers[0])},
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(identifiers[1])},
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: []byte{42, 3, 4}})
	badSignature := bytes.Clone(csr)
	badSignature[len(badSignature)-1] ^= 1
	for name, der := range map[string][]byte{
		"malformed_CSR": []byte("invalid"), "bad_CSR_signature": badSignature,
		"unauthorized_CSR": request([]string{"other.example"}, nil), "hidden_CSR_identity": request(identifiers, []pkix.Extension{hiddenSAN}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateIssuedCertificate([]byte(chain), der, identifiers, now); err == nil {
				t.Fatal("invalid CSR accepted")
			}
		})
	}
	for _, test := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{"wrong_SAN", func(c *x509.Certificate) { c.DNSNames = []string{"other.example"} }},
		{"hidden_identity", func(c *x509.Certificate) { c.ExtraExtensions = []pkix.Extension{hiddenSAN} }},
		{"CA", func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true }},
		{"wrong_EKU", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"future", func(c *x509.Certificate) { c.NotBefore = now.Add(time.Second) }},
		{"expired", func(c *x509.Certificate) { c.NotAfter = now }},
		{"invalid_interval", func(c *x509.Certificate) { c.NotBefore = c.NotAfter }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := leaf
			test.change(&changed)
			chain := append(encode(t, &changed, ca, &key.PublicKey, caKey), caPEM...)
			if _, err := ValidateIssuedCertificate(chain, csr, identifiers, now); err == nil {
				t.Fatal("invalid issued certificate accepted")
			}
		})
	}
	t.Run("wrong_key", func(t *testing.T) {
		chain := append(encode(t, &leaf, ca, &caKey.PublicKey, caKey), caPEM...)
		if _, err := ValidateIssuedCertificate(chain, csr, identifiers, now); err == nil {
			t.Fatal("certificate with a different key accepted")
		}
	})
}

func sanExtension(t *testing.T, names ...asn1.RawValue) pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: subjectAlternativeNameOID, Value: value}
}
