package visitorlease

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPolicyClientTrustCannotOutliveItsObservationOrShareMutableRoots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, key := fixture(t)
		update.View.Scope = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_aaaaaaaaaaaaaaaaaaaaaa"}
		lease.scope = update.View.Scope
		update.View.MetadataRevision = 1
		now := time.Now()
		certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "prepared client trust"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public().(ed25519.PublicKey), key)
		if err != nil {
			t.Fatal(err)
		}
		material := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		wire := controlv1.VisitorPolicyUpdate{SnapshotRequired: true, Policy: controlv1.VisitorPolicySnapshot{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: update.View.Scope.ID}, Hostname: update.View.Hostname, Port: int(update.View.Port), Issuer: update.View.Issuer, VisitorPolicyRevision: 1, MetadataRevision: 1, KeyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Enabled: true, Public: true, ClientIssuerPem: &material}}
		decoded, err := Decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		request := lease.Begin()
		time.Sleep(3 * time.Second)
		if err := lease.Apply(request, decoded); err != nil {
			t.Fatal(err)
		}
		roots := lease.ClientAuthorities()
		if roots == nil || !roots.Equal(decoded.ClientAuthorities) {
			t.Fatal("authenticated client trust was not installed")
		}
		// mutate the returned copy with a distinct root. callers cannot change the
		// policy owner's shared verifier through a certificate-pool pointer.
		certificate.SerialNumber = big.NewInt(2)
		der, err = x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public().(ed25519.PublicKey), key)
		if err != nil {
			t.Fatal(err)
		}
		extra, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		roots.AddCert(extra)
		if lease.ClientAuthorities().Equal(roots) {
			t.Fatal("caller mutation replaced shared client trust")
		}
		time.Sleep(7 * time.Second)
		if lease.ClientAuthorities() != nil {
			t.Fatal("slow policy reply extended client trust beyond fetch-start expiry")
		}
		for _, raw := range []string{"not a certificate", material + material} {
			wire.Policy.ClientIssuerPem = &raw
			if _, err := Decode(wire); err == nil {
				t.Fatal("malformed or ambiguous client trust was installed")
			}
		}
		wire.Policy.Resource.Kind = "public_url"
		wire.Policy.Resource.Id = "url_aaaaaaaaaaaaaaaaaaaaaa"
		wire.Policy.MetadataRevision = 0
		wire.Policy.ClientIssuerPem = &material
		if _, err := Decode(wire); err == nil {
			t.Fatal("service client trust crossed the public URL boundary")
		}
	})
}
