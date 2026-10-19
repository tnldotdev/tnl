package projectconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/privatetrust"
)

func targetTrustCA(t *testing.T) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test target CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestApplyCapturesPortableTargetTrustSeparateFromVisitorTrust(t *testing.T) {
	root := t.TempDir()
	ca := targetTrustCA(t)
	file := filepath.Join(root, "target-ca.pem")
	if err := os.WriteFile(file, ca, 0600); err != nil {
		t.Fatal(err)
	}
	address := config.Target("https://127.0.0.1:8443")
	hostname := "target.internal"
	source := "target-ca.pem"
	project := Project{Root: root, Config: config.TNL{Services: config.Services{"api": {Tunnel: &config.Tunnel{}, Target: &config.ServiceTarget{Type: "address", Address: &address, TLS: &config.TargetTLS{ServerName: &hostname, CAFile: &source}}}}}}
	snapshot, err := project.CaptureTargetTrust(t.Context(), privatetrust.NewCache(nil), "api", "")
	if err != nil || snapshot.Hostname != hostname || len(snapshot.CAPEM) == 0 || snapshot.Validate() != nil {
		t.Fatalf("captured target trust: %+v: %v", snapshot, err)
	}
	if snapshot.Digest == "" || len(snapshot.Digest) != 64 {
		t.Fatalf("target trust digest=%q", snapshot.Digest)
	}
	if _, err := project.CaptureServiceTrust(t.Context(), privatetrust.NewCache(nil), "api", ""); err == nil {
		t.Fatal("public target trust entered private visitor metadata")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("captured trust depends on the source file: %v", err)
	}
	snapshot.Hostname = "different.internal"
	if err := snapshot.Validate(); err == nil {
		t.Fatal("changed target identity retained approval")
	}
}
