package tnldruntime

import (
	"bytes"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

func TestRelayCertificateSourceValidatesAndReloads(t *testing.T) {
	const hostname = "relay-a.example.test"
	ca := newTestCertificateAuthority(t)
	first, second := ca.issue(t, hostname), ca.issue(t, hostname)
	source, err := newRelayCertificateSource("relay-a", hostname)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the same live config through both installs; recreating it would not
	// demonstrate that existing listeners observe a certificate replacement.
	config := source.TLSConfig()
	if _, err := config.GetCertificate(nil); err == nil {
		t.Fatal("empty certificate source returned a certificate")
	}
	certificate := func(material testCertificateMaterial) relayv1.RelayServiceCertificate {
		return relayv1.RelayServiceCertificate{
			RelayServiceId: "relay-a", TlsServerName: hostname,
			CertificatePem: string(material.certificatePEM), PrivateKeyPem: string(material.privateKeyPEM), NotAfter: material.leaf.NotAfter,
		}
	}
	if err := source.Install(certificate(first)); err != nil {
		t.Fatal(err)
	}
	installedFirst, err := config.GetCertificate(nil)
	if err != nil || installedFirst.Leaf == nil || !bytes.Equal(installedFirst.Certificate[0], first.leaf.Raw) {
		t.Fatalf("first installed certificate = %#v, %v", installedFirst, err)
	}
	if err := source.Install(certificate(second)); err != nil {
		t.Fatal(err)
	}
	installedSecond, err := config.GetCertificate(nil)
	if err != nil || installedSecond == installedFirst || !bytes.Equal(installedSecond.Certificate[0], second.leaf.Raw) {
		t.Fatalf("live config did not replace the certificate: %#v, %v", installedSecond, err)
	}
	if bytes.Equal(installedFirst.Certificate[0], installedSecond.Certificate[0]) {
		t.Fatal("test certificates are identical")
	}
	for _, test := range []struct {
		name   string
		mutate func(*relayv1.RelayServiceCertificate)
	}{
		{"identity", func(c *relayv1.RelayServiceCertificate) { c.TlsServerName = "relay-b.example.test" }},
		{"key_pair", func(c *relayv1.RelayServiceCertificate) { c.PrivateKeyPem = string(first.privateKeyPEM) }},
		{"expiry", func(c *relayv1.RelayServiceCertificate) { c.NotAfter = c.NotAfter.Add(-1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := certificate(second)
			test.mutate(&invalid)
			if err := source.Install(invalid); err == nil {
				t.Fatal("invalid update was accepted")
			}
			lastGood, err := config.GetCertificate(nil)
			if err != nil || lastGood != installedSecond || !bytes.Equal(lastGood.Certificate[0], second.leaf.Raw) {
				t.Fatalf("invalid update replaced last good certificate: %#v, %v", lastGood, err)
			}
		})
	}
}
