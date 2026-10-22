package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseFixtureCertificateHasExactProviderHostname(t *testing.T) {
	directory := t.TempDir()
	if err := writeDatabaseCertificates(directory); err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(directory, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("missing fixture CA")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(directory, "server.pem"), filepath.Join(directory, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: databaseTLSHostname}); err != nil {
		t.Fatal(err)
	}
	for _, hostname := range []string{"127.0.0.1", "localhost", "wrong.example"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: hostname}); err == nil {
			t.Fatalf("fixture accepted unintended hostname %q", hostname)
		}
	}
	info, err := os.Stat(filepath.Join(directory, "server.key"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("fixture key permissions: %v", err)
	}
}
