package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestDisposablePostgresTLSHasSeparateTrustRootAndServerLeaf(t *testing.T) {
	certificateFile, keyFile, rootFile, err := createPostgresTestCertificates(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server, err := tls.LoadX509KeyPair(certificateFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(server.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(rootPEM)
	if block == nil {
		t.Fatal("missing disposable PostgreSQL root CA certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !root.IsCA || leaf.IsCA {
		t.Fatalf("root CA = %t, server CA = %t", root.IsCA, leaf.IsCA)
	}
	trust := x509.NewCertPool()
	trust.AddCert(root)
	for _, hostname := range []string{"route.example", "db.internal"} {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: hostname, Roots: trust}); err != nil {
			t.Fatalf("verify disposable PostgreSQL server for %s: %v", hostname, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "other.internal", Roots: trust}); err == nil {
		t.Fatal("disposable PostgreSQL certificate covered another hostname")
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil || keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("disposable PostgreSQL key permissions = %v, %v", keyInfo, err)
	}
}
