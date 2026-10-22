package tcpconnect

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
)

func providerCertificate(t *testing.T) ([]byte, tls.Certificate) {
	return testutil.TLSCertificate(t, []string{"db.example"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}
func testCertificateForUses(t *testing.T, names []string, usages []x509.ExtKeyUsage) ([]byte, tls.Certificate) {
	return testutil.TLSCertificate(t, names, usages)
}
