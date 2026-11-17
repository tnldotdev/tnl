package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// certificateFixtureIssuance signs the real cache CSR; callers can vary the
// certificate contents without replacing the cache, acknowledgment, or run owner.
func certificateFixtureIssuance(control *lifecycleControl, der []byte, change func(*x509.Certificate)) (controlv1.ServiceCertificateIssuance, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: csr.DNSNames,
		NotBefore: now, NotAfter: now.Add(90 * time.Second), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if change != nil {
		change(leaf)
	}
	issued, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	chain := string(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root})...))
	return controlv1.ServiceCertificateIssuance{Id: "certificate-fixture-order",
		PublisherIdentityId: control.prep.PublisherIdentityId,
		ServiceId:           control.prep.ServiceId, ServiceRunId: control.prep.ServiceRunId, RunNumber: control.prep.RunNumber,
		CertificatePlan: *control.prep.CertificatePlan, State: controlv1.CertificateIssuanceStateWaitingForInstall,
		CertificatePem: &chain, NotBefore: &leaf.NotBefore, NotAfter: &leaf.NotAfter}, nil
}
