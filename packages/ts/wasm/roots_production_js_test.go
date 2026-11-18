//go:build js && wasm && !tnlwasmtest && !tnlpublisher

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"syscall/js"
	"testing"
	"time"
)

func TestProductionServiceTrustUsesMaintainedWebPKIRoots(t *testing.T) {
	host := js.Global().Get("Object").New()
	trust, err := serviceTrust(host)
	if err != nil {
		t.Fatal(err)
	}
	if trust.InsecureSkipVerify || trust.RootCAs == nil || len(trust.RootCAs.Subjects()) < 100 {
		t.Fatal("production inner TLS has no maintained root catalog")
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"service.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "service.example.test", Roots: trust.RootCAs}); err == nil {
		t.Fatal("unapproved self-signed service certificate trusted")
	}
	host.Set("__tnlTestServiceRootPEM", "injected")
	if _, err := serviceTrust(host); err == nil {
		t.Fatal("production accepted fixture root injection")
	}
}
