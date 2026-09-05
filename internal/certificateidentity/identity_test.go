package certificateidentity

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
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

func sanExtension(t *testing.T, names ...asn1.RawValue) pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: subjectAlternativeNameOID, Value: value}
}
