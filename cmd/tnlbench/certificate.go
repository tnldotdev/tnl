package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"time"
)

func loadCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("control CA file contains no certificates")
	}
	return pool, nil
}

func benchmarkCertificates(hostnames []string) ([]tls.Certificate, *x509.CertPool, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tnl benchmark CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, err
	}
	certificates := make([]tls.Certificate, len(hostnames))
	for index := range certificates {
		hostname := hostnames[index]
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(int64(index + 2)), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafKey.Public(), caKey)
		if err != nil {
			return nil, nil, err
		}
		leaf, err := x509.ParseCertificate(leafDER)
		if err != nil {
			return nil, nil, err
		}
		certificates[index] = tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey, Leaf: leaf}
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return certificates, roots, nil
}
