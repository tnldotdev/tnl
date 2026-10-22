package httpstream_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func providerCertificate(t *testing.T) ([]byte, tls.Certificate) {
	return testutil.TLSCertificate(t, []string{"db.example"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}
func providerSnapshot(t *testing.T, root []byte, names ...string) targettrust.Snapshot {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "root.pem"), root, 0600); err != nil {
		t.Fatal(err)
	}
	name := "db.example"
	if len(names) != 0 {
		name = names[0]
	}
	snapshot, err := targettrust.NewCache(nil).Capture(t.Context(), directory, "127.0.0.1:5432", config.TrustSource{CA: "root.pem", Hostname: &name})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
